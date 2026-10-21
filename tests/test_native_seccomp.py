"""Exercise the actual Linux filter in disposable processes, never the test runner."""
import os
import pathlib
import platform
import shutil
import signal
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


@unittest.skipUnless(platform.system() == "Linux" and shutil.which("cc"), "Linux and cc required")
class SeccompFilterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="phese-native-test-")
        cls.binary = pathlib.Path(cls.build.name) / "seccomp-test"
        subprocess.run([
            "cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", "-pthread",
            str(ROOT / "extension/seccomp_test.c"), "-o", str(cls.binary),
        ], check=True, capture_output=True, text=True)

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def run_case(self, case):
        result = subprocess.run([str(self.binary), case], capture_output=True, text=True, timeout=10)
        if result.returncode == 77:
            self.skipTest("syscall or architecture not available")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_direct_execve_denied(self): self.run_case("exec")
    def test_direct_execveat_denied(self): self.run_case("execveat")
    def test_ptrace_denied(self): self.run_case("ptrace")
    def test_namespace_changes_denied(self): self.run_case("namespace")
    def test_clone_namespace_changes_denied(self): self.run_case("clone_namespace")
    def test_clone3_returns_enosys_for_glibc_fallback(self): self.run_case("clone3")
    def test_fork_retains_filter(self): self.run_case("fork")
    def test_existing_threads_synchronized(self): self.run_case("tsync")
    def test_new_threads_inherit_filter(self): self.run_case("thread_after")
    def test_x32_syscall_bypass_denied(self): self.run_case("x32")
    def test_ordinary_filesystem_io_remains_available(self): self.run_case("ordinary_io")

    @unittest.skipUnless(platform.machine() == "x86_64", "x86_64 compat syscall required")
    def test_incompatible_syscall_arch_killed(self):
        result = subprocess.run([str(self.binary), "compat_arch"], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, -signal.SIGSYS)


class PHPNativeExtensionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.php = os.environ.get("PHESE_TEST_PHP")
        cls.extension = pathlib.Path(os.environ.get(
            "PHESE_TEST_EXTENSION", ROOT / "extension/modules/phese.so"))
        if not cls.php or not cls.extension.is_file():
            raise unittest.SkipTest("build matching native extension and set PHESE_TEST_PHP")
        probe = subprocess.run([cls.php, "-n", "-r", "echo PHP_VERSION_ID;"],
                               check=True, capture_output=True, text=True)
        cls.version = int(probe.stdout)
        cls.supported = any(lo <= cls.version < hi for lo, hi in [
            (80235, 80300), (80336, 80400), (80427, 80500), (80512, 80600)])

    def php_run(self, source, extra=()):
        return subprocess.run([self.php, "-n", "-d", "extension=" + str(self.extension),
                               *extra, "-r", source], capture_output=True, text=True, timeout=10)

    def test_version_gate_or_runtime_filter(self):
        result = self.php_run('echo "APPLICATION_EXECUTED\\n";')
        if not self.supported:
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("APPLICATION_EXECUTED", result.stdout)
            self.assertIn("phese refuses this runtime", result.stderr + result.stdout)
        else:
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("APPLICATION_EXECUTED", result.stdout)

    @unittest.skipUnless(os.geteuid() == 0, "root-owned page validation requires root fixture")
    def test_block_page_rejects_symlink_and_writable_files(self):
        if not self.supported:
            self.skipTest("requires patched runtime")
        with tempfile.TemporaryDirectory(prefix="phese-page-test-") as directory:
            page = pathlib.Path(directory) / "page.html"
            page.write_text("<p>blocked</p>")
            page.chmod(0o666)
            result = self.php_run('echo "APPLICATION_EXECUTED";',
                                  ["-d", "phese.block_page=" + str(page)])
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("APPLICATION_EXECUTED", result.stdout)
            page.chmod(0o644)
            link = pathlib.Path(directory) / "link.html"
            link.symlink_to(page)
            result = self.php_run('echo "APPLICATION_EXECUTED";',
                                  ["-d", "phese.block_page=" + str(link)])
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("APPLICATION_EXECUTED", result.stdout)
            result = self.php_run('echo "APPLICATION_EXECUTED";',
                                  ["-d", "phese.block_page=" + str(page)])
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_worker_scope_rejected_by_cli(self):
        if not self.supported:
            self.skipTest("requires patched runtime")
        result = self.php_run('echo "APPLICATION_EXECUTED";', ["-d", "phese.scope=worker"])
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("APPLICATION_EXECUTED", result.stdout)
        self.assertIn("worker is allowed only for PHP-FPM", result.stdout + result.stderr)

    def test_php_status_and_exec_denial(self):
        if not self.supported:
            self.skipTest("requires patched runtime")
        result = self.php_run('''
$status = phese_status();
if (!$status["enforcing"] || !$status["no_new_privileges"] || !$status["seccomp_active"]) exit(10);
$code = 0; $out = []; exec('/usr/bin/true', $out, $code);
if ($code == 0) exit(11);
echo "DENIED";
''')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("DENIED", result.stdout)


if __name__ == "__main__":
    unittest.main()
