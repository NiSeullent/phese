"""Optional native PHP-FPM checks using a private temporary Unix socket."""
import grp
import json
import os
import pathlib
import pwd
import signal
import shutil
import socket
import struct
import subprocess
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def process_security(pid):
    fields = {}
    for line in pathlib.Path(f"/proc/{pid}/status").read_text().splitlines():
        name, separator, value = line.partition(":")
        if separator and name in {"NoNewPrivs", "Seccomp", "Seccomp_filters"}:
            fields[name] = int(value.strip())
    return fields


def fcgi_length(length):
    return bytes((length,)) if length < 128 else struct.pack("!I", length | 0x80000000)


def fcgi_record(kind, data=b""):
    return struct.pack("!BBHHBB", 1, kind, 1, len(data), 0, 0) + data


def read_exact(connection, length):
    parts = bytearray()
    while len(parts) < length:
        data = connection.recv(length - len(parts))
        if not data:
            raise OSError("FPM closed an incomplete FastCGI record")
        parts.extend(data)
    return bytes(parts)


def fastcgi_request(socket_path, filename, decode_json=True):
    params = {
        "REQUEST_METHOD": "GET", "SCRIPT_FILENAME": str(filename),
        "SCRIPT_NAME": "/probe.php", "REQUEST_URI": "/probe.php",
        "SERVER_PROTOCOL": "HTTP/1.1", "GATEWAY_INTERFACE": "CGI/1.1",
        "SERVER_NAME": "localhost", "SERVER_PORT": "0",
        "REMOTE_ADDR": "127.0.0.1", "CONTENT_LENGTH": "0",
    }
    encoded = bytearray()
    for name, value in params.items():
        key, data = name.encode(), value.encode()
        encoded.extend(fcgi_length(len(key)) + fcgi_length(len(data)) + key + data)
    request = (fcgi_record(1, struct.pack("!HB5x", 1, 0)) +
               fcgi_record(4, bytes(encoded)) + fcgi_record(4) + fcgi_record(5))
    output, error = bytearray(), bytearray()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(5)
        connection.connect(str(socket_path))
        connection.sendall(request)
        while True:
            version, kind, request_id, length, padding, _ = struct.unpack(
                "!BBHHBB", read_exact(connection, 8))
            if version != 1 or request_id != 1:
                raise OSError("Unexpected FastCGI record")
            content = read_exact(connection, length)
            if padding:
                read_exact(connection, padding)
            if kind == 6:
                output.extend(content)
            elif kind == 7:
                error.extend(content)
            elif kind == 3:
                if len(content) < 8 or struct.unpack("!I", content[:4])[0] != 0 or content[4] != 0:
                    raise OSError("FPM request failed: " + error.decode(errors="replace"))
                break
    headers, separator, body = bytes(output).partition(b"\r\n\r\n")
    if not separator:
        raise OSError("Missing FastCGI response headers: " + bytes(output).decode(errors="replace"))
    if b"Status: 500" in headers:
        raise OSError("FPM returned 500: " + error.decode(errors="replace"))
    return json.loads(body) if decode_json else (headers, body)


class FPMNativeExtensionTests(unittest.TestCase):
    scope = "startup"
    @classmethod
    def setUpClass(cls):
        cls.fpm = os.environ.get("PHESE_TEST_FPM")
        cls.php = os.environ.get("PHESE_TEST_PHP")
        if not cls.fpm or not cls.php:
            raise unittest.SkipTest("set matching PHESE_TEST_FPM/PHP")
        cls.extension = pathlib.Path(os.environ.get(
            "PHESE_TEST_EXTENSION", ROOT / "extension/modules/phese.so"))
        cls.tmp = tempfile.TemporaryDirectory(prefix="phese-fpm-test-")
        cls.base = pathlib.Path(cls.tmp.name)
        cls.base.chmod(0o755)
        cls.socket_path = cls.base / "fpm.sock"
        cls.probe = cls.base / "probe.php"
        cls.probe.write_text('''<?php
header('Content-Type: application/json');
$status = phese_status();
$status['pid'] = getmypid();
$status['sapi'] = PHP_SAPI;
$status['php_version'] = PHP_VERSION;
$status['roundtrip'] = json_decode(json_encode(['value' => '폐쇄!', 'list' => [1, 2]]), true);
$status['kernel'] = [];
preg_match_all('/^(NoNewPrivs|Seccomp|Seccomp_filters):\\s*(\\d+)$/m', file_get_contents('/proc/self/status'), $fields, PREG_SET_ORDER);
foreach ($fields as $field) $status['kernel'][$field[1]] = (int)$field[2];
echo json_encode($status);
''')
        cls.probe.chmod(0o644)
        cls.denial = cls.base / "deny.php"
        cls.denial.write_text('<?php exec("/usr/bin/true"); echo "SHOULD_NOT_EXECUTE";')
        cls.denial.chmod(0o644)
        cls.spoof_pages = []
        setups = ["header('HTTP/1.1 200 OK');", "header('Status: 200 OK');",
                  "header_register_callback(function(){header_remove(); http_response_code(200); echo 'CALLBACK_RAN'; exit;});"]
        for index, setup in enumerate(setups):
            page = cls.base / ("spoof" + str(index) + ".php")
            page.write_text("<?php " + setup + " exec('/usr/bin/true'); echo 'SHOULD_NOT_EXECUTE';")
            page.chmod(0o644)
            cls.spoof_pages.append(page)
        if os.geteuid() == 0:
            account = pwd.getpwnam("nobody")
            pool_identity = f"user = {account.pw_name}\ngroup = {grp.getgrgid(account.pw_gid).gr_name}"
        else:
            account = pwd.getpwuid(os.geteuid())
            pool_identity = f"user = {account.pw_name}\ngroup = {grp.getgrgid(account.pw_gid).gr_name}"
        cls.expected_uid = account.pw_uid
        cls.config = cls.base / "fpm.conf"
        cls.config.write_text(f'''[global]
error_log = {cls.base}/error.log
pid = {cls.base}/fpm.pid
daemonize = no
rlimit_core = 0
[phese-test]
{pool_identity}
listen = {cls.socket_path}
listen.mode = 0600
pm = static
pm.max_children = 1
pm.max_requests = 3
clear_env = yes
catch_workers_output = yes
security.limit_extensions = .php
''')
        cls.output = open(cls.base / "stdout.log", "w+")
        cls.process = subprocess.Popen([
            cls.fpm, "-n", "-d", "extension=" + str(cls.extension),
            "-d", "phese.scope=" + cls.scope,
            "-y", str(cls.config), "-F"], stdout=cls.output,
            stderr=subprocess.STDOUT, start_new_session=True)
        try:
            cls.master_baseline = None
            for _ in range(100):
                if cls.process.poll() is not None:
                    cls.output.flush()
                    raise RuntimeError((cls.base / "stdout.log").read_text() +
                                       ((cls.base / "error.log").read_text()
                                        if (cls.base / "error.log").exists() else ""))
                try:
                    cls.master_baseline = process_security(cls.process.pid)
                    cls.initial = fastcgi_request(cls.socket_path, cls.probe)
                    return
                except OSError:
                    time.sleep(0.05)
            raise RuntimeError("isolated FPM did not become ready")
        except Exception:
            cls.stop_server()
            raise

    @classmethod
    def stop_server(cls):
        if hasattr(cls, "process") and cls.process.poll() is None:
            os.killpg(cls.process.pid, signal.SIGTERM)
            try:
                cls.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(cls.process.pid, signal.SIGKILL)
                cls.process.wait(timeout=5)
        if hasattr(cls, "output"):
            cls.output.close()
        if hasattr(cls, "tmp"):
            cls.tmp.cleanup()

    @classmethod
    def tearDownClass(cls):
        cls.stop_server()

    def test_web_process_attempt_returns_403_page(self):
        headers, body = fastcgi_request(self.socket_path, self.denial, decode_json=False)
        self.assertIn(b"Status: 403", headers)
        self.assertIn(b"Content-Security-Policy:", headers)
        self.assertIn("입원", body.decode("utf-8"))
        self.assertNotIn(b"SHOULD_NOT_EXECUTE", body)
        self.assertNotIn(b"{{EVENT_ID}}", body)

    def test_header_callbacks_and_existing_status_cannot_override_403(self):
        for page in self.spoof_pages:
            with self.subTest(page=page.name):
                headers, body = fastcgi_request(self.socket_path, page, decode_json=False)
                self.assertIn(b"Status: 403", headers)
                self.assertIn(b"Content-Security-Policy:", headers)
                self.assertIn("입원", body.decode("utf-8"))
                self.assertNotIn(b"CALLBACK_RAN", body)
                self.assertNotIn(b"SHOULD_NOT_EXECUTE", body)

    def test_requests_and_worker_recycling_preserve_filter(self):
        statuses = [self.initial]
        statuses.extend(fastcgi_request(self.socket_path, self.probe) for _ in range(9))
        self.assertGreaterEqual(len({status["pid"] for status in statuses}), 2)
        for status in statuses:
            self.assertEqual(status["sapi"], "fpm-fcgi")
            self.assertEqual(status["scope"], self.scope)
            self.assertEqual(status["effective_uid"], self.expected_uid)
            self.assertEqual(status["roundtrip"], {"value": "폐쇄!", "list": [1, 2]})
            for flag in ("seccomp_active", "no_new_privileges", "version_gate"):
                self.assertTrue(status[flag], status)
            self.assertEqual(status["kernel"]["NoNewPrivs"], 1)
            self.assertEqual(status["kernel"]["Seccomp"], 2)
            self.assertEqual(status["kernel"]["Seccomp_filters"],
                             self.master_baseline["Seccomp_filters"] + int(self.scope == "worker"))
        self.assertEqual(process_security(self.process.pid), self.master_baseline)


class FPMWorkerNativeExtensionTests(FPMNativeExtensionTests):
    scope = "worker"

    def run_failure_case(self, deny_seccomp=False, root_pool=False):
        with tempfile.TemporaryDirectory(prefix="phese-worker-failure-") as directory:
            base = pathlib.Path(directory)
            base.chmod(0o755)
            markers = base / "markers"
            markers.mkdir()
            markers.chmod(0o755)
            if os.geteuid() == 0:
                os.chown(markers, self.expected_uid, -1)
            marker = markers / "application-ran"
            page = base / "probe.php"
            page.write_text("<?php file_put_contents(" + json.dumps(str(marker)) +
                            ", 'ran'); echo json_encode(phese_status());")
            page.chmod(0o644)
            account = pwd.getpwnam("root") if root_pool else pwd.getpwuid(self.expected_uid)
            php_errors = base / "php-errors.log"
            php_errors.touch()
            if os.geteuid() == 0:
                os.chown(php_errors, account.pw_uid, -1)
            php_errors.chmod(0o600)
            socket_path = base / "fpm.sock"
            config = base / "fpm.conf"
            config.write_text(f"""[global]
error_log = {base}/error.log
daemonize = no
[phese-failure-test]
user = {account.pw_name}
group = {grp.getgrgid(account.pw_gid).gr_name}
listen = {socket_path}
pm = static
pm.max_children = 1
clear_env = yes
catch_workers_output = yes
""")
            command = [self.fpm, "-n", "-d", "extension=" + str(self.extension),
                       "-d", "phese.scope=worker", "-d", "display_errors=0",
                       "-d", "log_errors=1", "-d", "error_log=" + str(php_errors),
                       "-y", str(config), "-F"]
            if root_pool:
                command.append("-R")
            if deny_seccomp:
                wrapper = base / "deny-seccomp"
                subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                                str(ROOT / "extension/worker_failure_test.c"),
                                "-o", str(wrapper)], check=True, capture_output=True, text=True)
                command.insert(0, str(wrapper))
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       text=True, start_new_session=True)
            try:
                for _ in range(100):
                    if socket_path.exists() or process.poll() is not None:
                        break
                    time.sleep(0.02)
                self.assertIsNone(process.poll(), "failure fixture FPM did not start")
                try:
                    fastcgi_request(socket_path, page)
                except (OSError, ValueError):
                    pass
                expected = "requires a non-root pool UID" if root_pool else "cannot install mandatory seccomp"
                for _ in range(100):
                    log = ((base / "error.log").read_text() if (base / "error.log").exists() else "") + php_errors.read_text()
                    if expected in log:
                        break
                    time.sleep(0.01)
                self.assertIn(expected, log)
                self.assertFalse(marker.exists(), "application ran without mandatory worker enforcement")
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                process.communicate(timeout=5)

    @unittest.skipUnless(shutil.which("cc"), "cc required for filter-failure injection")
    def test_seccomp_installation_failure_refuses_application(self):
        self.run_failure_case(deny_seccomp=True)

    @unittest.skipUnless(os.geteuid() == 0, "root FPM pool fixture requires root")
    def test_root_pool_refused_before_application(self):
        self.run_failure_case(root_pool=True)

    def test_master_version_command_remains_available(self):
        result = subprocess.run([self.fpm, "-n", "-d", "extension=" + str(self.extension),
                                 "-d", "phese.scope=worker", "-v"],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PHP 8.5.12", result.stdout)

    def test_usr2_reload_preserves_master_exec_and_worker_enforcement(self):
        before = fastcgi_request(self.socket_path, self.probe)
        master_before = pathlib.Path(f"/proc/{self.process.pid}/status").read_text()
        baseline = pathlib.Path("/proc/self/status").read_text()
        for field in ("NoNewPrivs", "Seccomp", "Seccomp_filters"):
            expected = next(line for line in baseline.splitlines() if line.startswith(field + ":"))
            self.assertIn(expected, master_before)
        os.kill(self.process.pid, signal.SIGUSR2)
        after = None
        for _ in range(100):
            if self.process.poll() is not None:
                self.fail("worker-scope FPM master exited during USR2 reload: " +
                          (self.base / "error.log").read_text())
            try:
                candidate = fastcgi_request(self.socket_path, self.probe)
                if candidate["pid"] != before["pid"]:
                    after = candidate
                    break
            except (OSError, ValueError):
                pass
            time.sleep(0.05)
        self.assertIsNotNone(after, "no new FPM worker after USR2 reload")
        self.assertEqual(after["scope"], "worker")
        self.assertEqual(after["effective_uid"], self.expected_uid)
        for flag in ("enforcing", "seccomp_active", "no_new_privileges", "version_gate"):
            self.assertTrue(after[flag], after)
        log = (self.base / "error.log").read_text()
        self.assertIn("reloading: execvp(", log)
        self.assertGreaterEqual(log.count("ready to handle connections"), 2)
        headers, body = fastcgi_request(self.socket_path, self.denial, decode_json=False)
        self.assertIn(b"Status: 403", headers)
        self.assertNotIn(b"SHOULD_NOT_EXECUTE", body)
        master_after = pathlib.Path(f"/proc/{self.process.pid}/status").read_text()
        for field in ("NoNewPrivs", "Seccomp", "Seccomp_filters"):
            expected = next(line for line in baseline.splitlines() if line.startswith(field + ":"))
            self.assertIn(expected, master_after)


if __name__ == "__main__":
    unittest.main()
