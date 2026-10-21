"""Optional actual CLI sandbox checks, using only disposable fixture files."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ActualSandboxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.php = os.environ.get("PHESE_TEST_PHP")
        cls.extension = os.environ.get("PHESE_TEST_EXTENSION", str(ROOT / "extension/modules/phese.so"))
        if not cls.php or not Path(cls.extension).is_file() or not shutil.which("bwrap"):
            raise unittest.SkipTest("patched PHP, matching phese module and bubblewrap required")
        info = subprocess.run([cls.php, "-n", "-r", "echo PHP_VERSION_ID;"], check=True,
                              capture_output=True, text=True)
        if int(info.stdout) < 80512:
            raise unittest.SkipTest("this fixture uses a patched PHP 8.5 runtime")

    def test_files_network_process_policy_and_explicit_writable_data(self):
        with tempfile.TemporaryDirectory(prefix="phese-sandbox-") as directory:
            base = Path(directory)
            base.chmod(0o755)
            app = base / "app"
            app.mkdir(mode=0o755)
            app.chmod(0o755)
            data = app / "data"
            data.mkdir()
            data.chmod(0o777)
            secret = base / "host-secret"
            secret.write_text("private fixture")
            secret.chmod(0o644)
            source = '''<?php
$status = phese_status();
$status['host_secret_visible'] = file_exists(%s);
$status['app_write'] = @file_put_contents(__DIR__.'/unexpected', 'x') !== false;
$status['data_write'] = @file_put_contents(__DIR__.'/data/allowed', 'x') !== false;
$status['net_namespace'] = readlink('/proc/self/ns/net');
$status['host_env_visible'] = getenv('PHESE_PRIVATE_FIXTURE') !== false;
$code = 0; $out = []; exec('/usr/bin/true', $out, $code);
$status['exec_denied'] = $code !== 0;
echo json_encode($status);
''' % json.dumps(str(secret))
            script = app / "probe.php"
            script.write_text(source)
            script.chmod(0o644)
            command = [sys.executable, "-m", "phese", "run", "--php", self.php,
                       "--extension", self.extension, "--app", str(app),
                       "--write", str(data), "probe.php"]
            result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=30,
                                    env={**os.environ, "PHESE_PRIVATE_FIXTURE": "not inherited"})
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            status = json.loads(result.stdout)
            for key in ("seccomp_active", "no_new_privileges", "version_gate", "exec_denied", "data_write"):
                self.assertIs(status[key], True, key)
            for key in ("host_secret_visible", "app_write", "host_env_visible"):
                self.assertIs(status[key], False, key)
            self.assertNotEqual(status["net_namespace"], os.readlink("/proc/self/ns/net"))
            self.assertFalse((app / "unexpected").exists())
            self.assertEqual((data / "allowed").read_text(), "x")
            if os.getuid() == 0:
                self.assertEqual(status["effective_uid"], 65534)

    def test_missing_module_guard_stops_application(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "should-not-run"
            script = Path(directory) / "app.php"
            script.write_text("<?php file_put_contents(" + json.dumps(str(marker)) + ", 'bad');")
            result = subprocess.run([self.php, "-n", "-d", "extension=/nonexistent/phese.so",
                                     "-d", "auto_prepend_file=" + str(ROOT / "phese/guard.php"),
                                     str(script)], capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
