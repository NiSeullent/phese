"""Optional real event-MPM/mod_php checks using an isolated loopback listener.

Set PHESE_TEST_APACHE, PHESE_TEST_LIBPHP and PHESE_TEST_PHP to matching
patched builds; no installed service or configuration is modified.
"""
import concurrent.futures
import http.client
import json
import os
import pathlib
import pwd
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.request
import urllib.error

ROOT = pathlib.Path(__file__).resolve().parents[1]


def process_security(pid):
    fields = {}
    for line in pathlib.Path(f"/proc/{pid}/status").read_text().splitlines():
        name, separator, value = line.partition(":")
        if separator and name in {"NoNewPrivs", "Seccomp", "Seccomp_filters"}:
            fields[name] = int(value.strip())
    return fields


class ApacheNativeExtensionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.apache = os.environ.get("PHESE_TEST_APACHE")
        cls.libphp = os.environ.get("PHESE_TEST_LIBPHP")
        cls.php = os.environ.get("PHESE_TEST_PHP")
        if not all((cls.apache, cls.libphp, cls.php)):
            raise unittest.SkipTest("set matching PHESE_TEST_APACHE/LIBPHP/PHP")
        cls.extension = pathlib.Path(os.environ.get(
            "PHESE_TEST_EXTENSION", ROOT / "extension/modules/phese.so"))
        cls.server_root = pathlib.Path(os.environ.get(
            "PHESE_TEST_APACHE_ROOT", pathlib.Path(cls.apache).resolve().parents[1]))
        cls.modules = cls.server_root / "libexec"
        if not (cls.modules / "mod_mpm_event.so").is_file():
            cls.modules = cls.server_root / "modules"
        cls.tmp = tempfile.TemporaryDirectory(prefix="phese-apache-test-")
        cls.base = pathlib.Path(cls.tmp.name)
        cls.base.chmod(0o755)
        cls.document_root = cls.base / "public"
        cls.document_root.mkdir(mode=0o755)
        cls.document_root.chmod(0o755)
        (cls.document_root / "probe.php").write_text('''<?php
header('Content-Type: application/json');
$status = phese_status();
$status['pid'] = getmypid();
$status['sapi'] = PHP_SAPI;
$status['php_version'] = PHP_VERSION;
$status['uid'] = function_exists('posix_geteuid') ? posix_geteuid() : null;
echo json_encode($status);
''')
        (cls.document_root / "probe.php").chmod(0o644)
        (cls.document_root / "deny.php").write_text('<?php exec("/usr/bin/true"); echo "SHOULD_NOT_EXECUTE";')
        (cls.document_root / "deny.php").chmod(0o644)
        spoof_sources = {
            "statusline": "header('HTTP/1.1 200 OK');",
            "statusheader": "header('Status: 200 OK');",
            "callback": "header_register_callback(function(){header_remove(); http_response_code(200); echo 'CALLBACK_RAN'; exit;});",
        }
        for name, setup in spoof_sources.items():
            page = cls.document_root / (name + ".php")
            page.write_text("<?php " + setup + " exec('/usr/bin/true'); echo 'SHOULD_NOT_EXECUTE';")
            page.chmod(0o644)
        (cls.base / "php.ini").write_text("extension=" + str(cls.extension) + "\nphese.scope=worker\n")
        (cls.base / "scan").mkdir()
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            cls.port = reservation.getsockname()[1]
        if os.geteuid() == 0:
            account = pwd.getpwnam("nobody")
            user_group = f"User #{account.pw_uid}\nGroup #{account.pw_gid}"
        else:
            user_group = ""
        unixd = f'LoadModule unixd_module "{cls.modules}/mod_unixd.so"'
        if not (cls.modules / "mod_unixd.so").is_file():
            builtins = subprocess.run([cls.apache, "-l"], check=True, capture_output=True, text=True).stdout
            if "unixd.c" not in builtins:
                raise RuntimeError("Apache unixd is neither built in nor available as a module")
            unixd = "# unixd is built into this Apache binary"
        conf = f'''ServerRoot "{cls.server_root}"
ServerName localhost
DefaultRuntimeDir "{cls.base}"
CoreDumpDirectory "{cls.base}"
Listen 127.0.0.1:{cls.port}
PidFile "{cls.base}/httpd.pid"
ErrorLog "{cls.base}/error.log"
LoadModule mpm_event_module "{cls.modules}/mod_mpm_event.so"
{unixd}
LoadModule authz_core_module "{cls.modules}/mod_authz_core.so"
LoadModule php_module "{cls.libphp}"
{user_group}
PHPIniDir "{cls.base}"
DocumentRoot "{cls.document_root}"
<Directory "{cls.document_root}">
Require all granted
AllowOverride None
</Directory>
<FilesMatch \\.php$>
SetHandler application/x-httpd-php
</FilesMatch>
StartServers 1
ServerLimit 1
ThreadLimit 16
ThreadsPerChild 8
MinSpareThreads 1
MaxSpareThreads 8
MaxRequestWorkers 8
'''
        cls.config = cls.base / "httpd.conf"
        cls.config.write_text(conf)
        env = os.environ.copy()
        env["PHP_INI_SCAN_DIR"] = str(cls.base / "scan")
        cls.output = open(cls.base / "stdout.log", "w+")
        cls.process = subprocess.Popen([cls.apache, "-f", str(cls.config), "-DFOREGROUND"],
                                       env=env, stdout=cls.output,
                                       stderr=subprocess.STDOUT, start_new_session=True)
        cls.url = f"http://127.0.0.1:{cls.port}/probe.php"
        try:
            # TCP readiness performs no PHP request. The first PHP admission is
            # deliberately a concurrent wave, rather than a serial warm-up.
            for _ in range(100):
                if cls.process.poll() is not None:
                    cls.output.flush()
                    raise RuntimeError((cls.base / "stdout.log").read_text() +
                                       ((cls.base / "error.log").read_text()
                                        if (cls.base / "error.log").exists() else ""))
                try:
                    with socket.create_connection(("127.0.0.1", cls.port), timeout=0.3):
                        break
                except OSError:
                    time.sleep(0.05)
            else:
                raise RuntimeError("isolated Apache did not become TCP-ready")
            cls.master_baseline = process_security(cls.process.pid)

            def first_fetch(_):
                with urllib.request.urlopen(cls.url, timeout=5) as response:
                    return json.load(response)
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as workers:
                cls.initial_wave = list(workers.map(first_fetch, range(24)))
            cls.initial = cls.initial_wave[0]
            cls.initial_worker_security = {status["pid"]: process_security(status["pid"])
                                           for status in cls.initial_wave}
            cls.initial_thread_security = {
                str(task): process_security(int(task.name))
                for pid in cls.initial_worker_security
                for task in pathlib.Path(f"/proc/{pid}/task").iterdir()}
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

    def test_event_mpm_php_threads_inherit_protection(self):
        def fetch(_):
            with urllib.request.urlopen(self.url, timeout=5) as response:
                return json.load(response)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as workers:
            statuses = list(workers.map(fetch, range(24)))
        for status in statuses:
            self.assertEqual(status["sapi"], "apache2handler")
            self.assertEqual(status["scope"], "worker")
            for flag in ("seccomp_active", "no_new_privileges", "version_gate"):
                self.assertTrue(status[flag], status)
            status_file = pathlib.Path(f'/proc/{status["pid"]}/status').read_text()
            self.assertIn("NoNewPrivs:\t1", status_file)
            self.assertIn("Seccomp:\t2", status_file)

    def test_concurrent_first_wave_installs_one_filter_per_worker(self):
        self.assertEqual(len(self.initial_wave), 24)
        self.assertGreater(len(self.initial_thread_security), 1)
        self.assertEqual(self.master_baseline, process_security(os.getpid()))
        for status in self.initial_wave:
            self.assertEqual(status["scope"], "worker")
            self.assertNotEqual(status["effective_uid"], 0)
            for flag in ("enforcing", "seccomp_active", "no_new_privileges", "version_gate"):
                self.assertTrue(status[flag], status)
        for fields in [*self.initial_worker_security.values(), *self.initial_thread_security.values()]:
            self.assertEqual(fields["NoNewPrivs"], 1)
            self.assertEqual(fields["Seccomp"], 2)
            self.assertEqual(fields["Seccomp_filters"], self.master_baseline["Seccomp_filters"] + 1)

    @unittest.skipUnless(shutil.which("cc"), "cc required for filter-failure injection")
    def test_failed_worker_filter_blocks_concurrent_and_later_requests(self):
        alternate = self.base / "failure"
        alternate.mkdir()
        alternate.chmod(0o755)
        markers = alternate / "markers"
        markers.mkdir()
        markers.chmod(0o755)
        if os.geteuid() == 0:
            os.chown(markers, pwd.getpwnam("nobody").pw_uid, -1)
        marker = markers / "application-ran"
        page = self.document_root / "failed-admission.php"
        page.write_text("<?php file_put_contents(" + json.dumps(str(marker)) + ", 'ran'); echo 'APPLICATION_RAN';")
        page.chmod(0o644)
        wrapper = alternate / "deny-seccomp"
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        str(ROOT / "extension/worker_failure_test.c"), "-o", str(wrapper)],
                       check=True, capture_output=True, text=True)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        config = alternate / "httpd.conf"
        php_errors = alternate / "php-errors.log"
        php_errors.touch(mode=0o600)
        if os.geteuid() == 0:
            os.chown(php_errors, pwd.getpwnam("nobody").pw_uid, -1)
        (alternate / "php.ini").write_text(
            "extension=" + str(self.extension) + "\nphese.scope=worker\n"
            "display_errors=0\nlog_errors=1\nerror_log=" + str(php_errors) + "\n")
        config.write_text(self.config.read_text().replace(
            f"Listen 127.0.0.1:{self.port}", f"Listen 127.0.0.1:{port}").replace(
            f'{self.base}/httpd.pid', f'{alternate}/httpd.pid').replace(
            f'{self.base}/error.log', f'{alternate}/error.log').replace(
            f'PHPIniDir "{self.base}"', f'PHPIniDir "{alternate}"'))
        env = os.environ.copy()
        env["PHP_INI_SCAN_DIR"] = str(self.base / "scan")
        output = open(alternate / "stdout.log", "w+")
        process = subprocess.Popen([str(wrapper), self.apache, "-f", str(config), "-DFOREGROUND"],
                                   env=env, stdout=output, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        try:
            for _ in range(100):
                self.assertIsNone(process.poll(), "failure-fixture Apache did not start")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                        break
                except OSError:
                    time.sleep(0.02)
            else:
                self.fail("failure-fixture Apache did not become ready")
            def denied_fetch(_):
                try:
                    response = urllib.request.urlopen(f"http://127.0.0.1:{port}/{page.name}", timeout=5)
                except urllib.error.HTTPError as error:
                    response = error
                except (http.client.RemoteDisconnected, ConnectionResetError):
                    # Apache may abort the connection when PHP RINIT refuses
                    # startup. The durable marker still detects any app entry.
                    return b""
                with response:
                    return response.read()
            for _ in range(3):
                with concurrent.futures.ThreadPoolExecutor(max_workers=8) as workers:
                    bodies = list(workers.map(denied_fetch, range(24)))
                for body in bodies:
                    self.assertNotIn(b"APPLICATION_RAN", body)
                self.assertFalse(marker.exists(), "PHP application ran after worker enforcement failed")
            self.assertIsNone(process.poll())
            output.flush()
            log = ((alternate / "error.log").read_text() +
                   (alternate / "stdout.log").read_text() + php_errors.read_text())
            self.assertIn("cannot install mandatory seccomp", log)
            # Apache may replace a worker after request-startup refusal. A new
            # process reports its first EPERM again, so the sticky-state wording
            # depends on scheduling. Every concurrent and later wave above must
            # still refuse application entry, regardless of worker replacement.
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            finally:
                output.close()

    def test_web_process_attempt_returns_403_page(self):
        with self.assertRaises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(self.url.replace("probe.php", "deny.php"), timeout=5)
        self.assertEqual(error.exception.code, 403)
        body = error.exception.read().decode("utf-8")
        self.assertNotIn("SHOULD_NOT_EXECUTE", body)
        self.assertIn("입원", body)
        self.assertNotIn("{{EVENT_ID}}", body)
        self.assertIn("default-src", error.exception.headers["Content-Security-Policy"])
        self.assertEqual(error.exception.headers["Referrer-Policy"], "no-referrer")

    def test_header_callbacks_and_existing_status_cannot_override_403(self):
        for name in ("statusline", "statusheader", "callback"):
            with self.subTest(name=name):
                with self.assertRaises(urllib.error.HTTPError) as error:
                    urllib.request.urlopen(self.url.replace("probe.php", name + ".php"), timeout=5)
                self.assertEqual(error.exception.code, 403)
                body = error.exception.read().decode("utf-8")
                self.assertIn("입원", body)
                self.assertNotIn("CALLBACK_RAN", body)
                self.assertNotIn("SHOULD_NOT_EXECUTE", body)
                self.assertIn("default-src", error.exception.headers["Content-Security-Policy"])

    def test_startup_scope_rejected_by_apache(self):
        alternate = self.base / "startup-ini"
        alternate.mkdir()
        (alternate / "php.ini").write_text("extension=" + str(self.extension) + "\nphese.scope=startup\n")
        config = self.base / "startup-scope.conf"
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        config.write_text(self.config.read_text().replace(
            f'PHPIniDir "{self.base}"', f'PHPIniDir "{alternate}"').replace(
            f"Listen 127.0.0.1:{self.port}", f"Listen 127.0.0.1:{port}").replace(
            f'{self.base}/httpd.pid', f'{alternate}/httpd.pid').replace(
            f'{self.base}/error.log', f'{alternate}/error.log'))
        env = os.environ.copy()
        env["PHP_INI_SCAN_DIR"] = str(self.base / "scan")
        process = subprocess.Popen([self.apache, "-f", str(config), "-DFOREGROUND"],
                                   env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True, start_new_session=True)
        try:
            output, _ = process.communicate(timeout=5)
            self.assertNotEqual(process.returncode, 0)
            log = (alternate / "error.log").read_text() if (alternate / "error.log").exists() else ""
            self.assertIn("startup is not supported for Apache", output + log)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                process.communicate(timeout=5)

    def test_apache_graceful_reload_retains_protection(self):
        self.lifecycle_samples = []
        for cycle in range(10):
            with urllib.request.urlopen(self.url, timeout=5) as response:
                previous = json.load(response)
            os.kill(self.process.pid, signal.SIGUSR1)
            status = None
            for _ in range(100):
                self.assertIsNone(self.process.poll(), "isolated Apache master exited")
                try:
                    with urllib.request.urlopen(self.url, timeout=0.3) as response:
                        candidate = json.load(response)
                    if candidate["pid"] != previous["pid"]:
                        status = candidate
                        break
                except (OSError, ValueError):
                    pass
                time.sleep(0.05)
            self.assertIsNotNone(status, f"no new Apache worker after graceful cycle {cycle + 1}")
            self.assertEqual(status["scope"], "worker")
            for flag in ("enforcing", "seccomp_active", "no_new_privileges", "version_gate"):
                self.assertTrue(status[flag], status)
            master, worker = process_security(self.process.pid), process_security(status["pid"])
            self.assertEqual(master, self.master_baseline)
            self.assertEqual(worker["Seccomp_filters"], self.master_baseline["Seccomp_filters"] + 1)
            self.lifecycle_samples.append({"cycle": cycle + 1, "master": master, "worker": worker})


if __name__ == "__main__":
    unittest.main()
