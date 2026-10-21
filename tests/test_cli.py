import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from phese import cli


class VersionTests(unittest.TestCase):
    def test_each_supported_branch_boundary_and_prerelease(self):
        for text, number, accepted in [
            ("8.2.34", 80234, False), ("8.2.35", 80235, True),
            ("8.3.35", 80335, False), ("8.3.36", 80336, True),
            ("8.4.26", 80426, False), ("8.4.27", 80427, True),
            ("8.5.11", 80511, False), ("8.5.12", 80512, True),
            ("8.5.13", 80513, True), ("8.5.12RC1", 80512, False),
            ("8.6.0-dev", 80600, False), ("7.4.33", 70433, False),
        ]:
            with self.subTest(version=text):
                result = argparse.Namespace(stdout=json.dumps([text, number, 0]))
                with patch.object(cli, "execute", return_value=result):
                    self.assertEqual(cli.php_info("php")["cve_2026_109618_109619_version_gate"], accepted)

    def test_status_requires_all_guards_not_just_truthiness(self):
        for value in [None, True, {"active": True}, {"seccomp_active": 1},
                      {"seccomp_active": True, "no_new_privileges": True, "version_gate": False}]:
            self.assertFalse(cli.protected_status(value))
        self.assertTrue(cli.protected_status(dict(seccomp_active=True, no_new_privileges=True, version_gate=True)))


class RequestTests(unittest.TestCase):
    def test_report_cannot_overwrite_application_file(self):
        with tempfile.TemporaryDirectory() as directory:
            app = Path(directory) / "app"
            app.mkdir()
            source = app / "index.php"
            source.write_text("<?php echo 'unchanged';")
            before = source.read_bytes()
            self.assertEqual(cli.main(["scan", str(app), "--output", str(source)]), 2)
            self.assertEqual(source.read_bytes(), before)

    def test_scan_is_read_only_and_does_not_follow_symlinks_or_copy_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "app"
            root.mkdir()
            original = b"<?php\n$secret='must-not-appear';\nsystem($arg);\neval($x);\n"
            source = root / "index.php"
            source.write_bytes(original)
            outside = Path(directory) / "outside.php"
            outside.write_text("<?php exec('outside');")
            (root / "link.php").symlink_to(outside)
            report = cli.scan(root)
            self.assertEqual(source.read_bytes(), original)
            self.assertFalse(report["source_modified"])
            self.assertEqual([x["line"] for x in report["requests"]], [3, 4])
            self.assertNotIn("must-not-appear", json.dumps(report))
            self.assertIn("link.php", report["skipped"])

    def test_mail_transport_requires_a_modification_request(self):
        with tempfile.TemporaryDirectory() as directory:
            app = Path(directory)
            (app / "send.php").write_text("<?php mail($to, $subject, $body);")
            report = cli.scan(app)
            self.assertEqual(report["requests"][0]["rule"], "process-execution")
            self.assertIn("격리 작업 서비스", report["requests"][0]["request"])

    def test_atomic_reports_private_and_symlinks_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "request.json"
            cli.private_json(destination, {"source_modified": False})
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
            destination.unlink()
            target = Path(directory) / "unrelated"
            target.write_text("unchanged")
            destination.symlink_to(target)
            with self.assertRaises(cli.PolicyError):
                cli.private_json(destination, {})
            self.assertEqual(target.read_text(), "unchanged")

    def test_shared_report_directory_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o777)
            with self.assertRaises(cli.PolicyError):
                cli.private_json(Path(directory) / "report.json", {})


class SandboxTests(unittest.TestCase):
    def arguments(self, root, **changes):
        values = dict(app=str(root), script="main.php", arguments=["-d", "x=1"],
                      write=[], network="none", timeout=20)
        values.update(changes)
        return argparse.Namespace(**values)

    def fixture(self, directory):
        root = Path(directory)
        app = root / "app"
        app.mkdir()
        app.chmod(0o755)
        (app / "main.php").write_text("<?php echo 'ok';")
        (app / "main.php").chmod(0o644)
        php = root / "php"
        extension = root / "phese.so"
        php.write_bytes(b"trusted interpreter fixture")
        extension.write_bytes(b"trusted module fixture")
        php.chmod(0o644)
        extension.chmod(0o644)
        return app, php, extension

    def assert_closed(self, descriptors):
        for descriptor in descriptors:
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    @patch.object(cli.shutil, "which", return_value="/usr/bin/bwrap")
    def test_minimal_default_and_no_host_root_bind(self, which):
        with tempfile.TemporaryDirectory() as directory:
            app, php, extension = self.fixture(directory)
            script = app / "main.php"
            with cli.sandbox_command(self.arguments(app), php, extension) as command:
                self.assertIn("--unshare-all", command.argv)
                self.assertNotIn("--share-net", command.argv)
                self.assertIn("--clearenv", command.argv)
                self.assertIn("auto_prepend_file=/phese/guard.php", command.argv)
                self.assertIn("extension=/phese/phese.so", command.argv)
                self.assertIn("/phese/php", command.argv)
                self.assertEqual(command.argv.count("--ro-bind-fd"), 4)
                for index, value in enumerate(command.argv):
                    if value in {"--ro-bind", "--bind"}:
                        self.assertNotEqual(command.argv[index + 1], "/")
                self.assertEqual(command.argv[-3:], [str(script), "-d", "x=1"])
                descriptors = tuple(command.pass_fds)
                for descriptor in descriptors:
                    self.assertFalse(os.get_inheritable(descriptor))
            self.assert_closed(descriptors)

    @patch.object(cli.shutil, "which", return_value="/usr/bin/bwrap")
    def test_script_escape_and_broad_write_are_rejected(self, which):
        with tempfile.TemporaryDirectory() as directory:
            app, php, extension = self.fixture(directory)
            outside = Path(directory) / "out.php"
            outside.write_text("<?php")
            (app / "escape.php").symlink_to(outside)
            for args in [self.arguments(app, script="escape.php"),
                         self.arguments(app, write=[str(app)]),
                         self.arguments(app, write=[directory])]:
                with self.assertRaises((cli.PolicyError, OSError)):
                    cli.sandbox_command(args, php, extension)

    @patch.object(cli.shutil, "which", return_value="/usr/bin/bwrap")
    def test_mounts_keep_original_inodes_after_host_path_swap(self, which):
        with tempfile.TemporaryDirectory() as directory:
            app, php, extension = self.fixture(directory)
            storage = app / "storage"
            storage.mkdir()
            outside = Path(directory) / "outside"
            outside.mkdir()
            app_inode, storage_inode = app.stat().st_ino, storage.stat().st_ino
            args = self.arguments(app, write=[str(storage)])
            with cli.sandbox_command(args, php, extension) as command:
                app.rename(Path(directory) / "original-app")
                app.symlink_to(outside, target_is_directory=True)
                php.rename(Path(directory) / "original-php")
                php.write_text("replacement")
                index = command.argv.index("--ro-bind-fd")
                app_fd = int(command.argv[index + 1])
                index = command.argv.index("--bind-fd")
                write_fd = int(command.argv[index + 1])
                self.assertEqual(os.fstat(app_fd).st_ino, app_inode)
                self.assertEqual(os.fstat(write_fd).st_ino, storage_inode)
                with open(f"/proc/self/fd/{command.php_fd}", "rb") as source:
                    self.assertEqual(source.read(), b"trusted interpreter fixture")

    @patch.object(cli.shutil, "which", return_value="/usr/bin/bwrap")
    def test_symlink_swap_before_write_pin_is_rejected_and_fds_closed(self, which):
        with tempfile.TemporaryDirectory() as directory:
            app, php, extension = self.fixture(directory)
            storage = app / "storage"
            storage.mkdir()
            outside = Path(directory) / "outside"
            outside.mkdir()
            original_pin = cli.pin_path
            opened = []

            def swap_before_pin(path, **kwargs):
                if kwargs.get("dir_fd") is not None and kwargs.get("directory"):
                    storage.rename(app / "original-storage")
                    storage.symlink_to(outside, target_is_directory=True)
                descriptor = original_pin(path, **kwargs)
                opened.append(descriptor)
                return descriptor

            with patch.object(cli, "pin_path", side_effect=swap_before_pin):
                with self.assertRaises(OSError):
                    cli.sandbox_command(self.arguments(app, write=[str(storage)]), php, extension)
            self.assert_closed(opened)

    def test_every_symlink_ancestor_and_final_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / "real"
            real.mkdir()
            (real / "file").write_text("fixture")
            (root / "link").symlink_to(real, target_is_directory=True)
            (real / "file-link").symlink_to(real / "file")
            for path, is_directory in [(root / "link", True),
                                       (root / "link/file", False),
                                       (real / "file-link", False)]:
                with self.subTest(path=path):
                    with self.assertRaises((cli.PolicyError, OSError)):
                        cli.pin_path(path, directory=is_directory)

    @patch.object(cli.shutil, "which", return_value="/usr/bin/bwrap")
    def test_child_gets_pins_but_parent_closes_them_on_execution_failure(self, which):
        with tempfile.TemporaryDirectory() as directory:
            app, php, extension = self.fixture(directory)
            with self.assertRaises(OSError):
                with cli.sandbox_command(self.arguments(app), php, extension) as command:
                    descriptors = tuple(command.pass_fds)
                    with patch.object(cli.subprocess, "Popen", side_effect=OSError("fixture failure")) as launch:
                        cli.run_sandbox(command, 1)
                    self.fail("Popen should have failed")
            self.assert_closed(descriptors)
            self.assertEqual(launch.call_args.kwargs["pass_fds"], descriptors)
            self.assertIs(launch.call_args.kwargs["close_fds"], True)
            if os.getuid() == 0:
                self.assertEqual(launch.call_args.kwargs["user"], 65534)
                self.assertEqual(launch.call_args.kwargs["group"], 65534)
                self.assertEqual(launch.call_args.kwargs["extra_groups"], ())

    @unittest.skipUnless(shutil.which("bwrap"), "bubblewrap required")
    def test_bubblewrap_consumes_mount_fds_without_leaking_them_to_application(self):
        # A trusted Python snippet tests setup descriptors independently of PHP
        # build availability. This is not a native phese extension test.
        with tempfile.TemporaryDirectory() as directory:
            Path(directory).chmod(0o755)
            app, php, extension = self.fixture(directory)
            guard = Path(directory) / "guard.php"
            guard.write_text("<?php /* trusted, unexecuted mount fixture */")
            guard.chmod(0o644)
            storage = app / "storage"
            storage.mkdir(mode=0o777)
            os.chmod(storage, 0o777)
            (storage / "original").write_text("pinned content")
            (storage / "original").chmod(0o644)
            root_private = app / "root-private"
            root_private.write_text("root-only fixture")
            root_private.chmod(0o600)
            outside = Path(directory) / "outside"
            outside.mkdir()
            (outside / "external-secret").write_text("must not be visible")
            args = self.arguments(app, write=[str(storage)])
            with patch.object(cli, "__file__", str(Path(directory) / "cli.py")), \
                    cli.sandbox_command(args, php, extension) as command:
                base_argv = command.argv[:command.argv.index("--") + 1]
                descriptors = tuple(command.pass_fds)
                check = subprocess.run(base_argv + ["/usr/bin/true"],
                                       pass_fds=descriptors, close_fds=True,
                                       capture_output=True, text=True, timeout=10,
                                       **cli.sandbox_credentials())
                if check.returncode != 0 and any(value in check.stderr for value in
                        ("Creating new namespace failed: Operation not permitted", "No permissions to create")):
                    self.skipTest("kernel/container policy forbids bubblewrap namespaces")
                self.assertEqual(check.returncode, 0, check.stderr)
                storage.rename(app / "old-storage")
                storage.symlink_to(outside, target_is_directory=True)
                rejected = subprocess.run(base_argv + ["/usr/bin/true"],
                                          pass_fds=descriptors, close_fds=True,
                                          capture_output=True, text=True, timeout=10,
                                          **cli.sandbox_credentials())
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn("symlink destination", rejected.stderr)
                self.assertFalse((outside / "written").exists())
                storage.unlink()
                (app / "old-storage").rename(storage)
                code = (
                    "import os,pathlib; "
                    f"p=pathlib.Path({str(storage)!r}); "
                    "assert (p/'original').read_text() == 'pinned content', 'pinned source changed'; "
                    "assert not (p/'external-secret').exists(), 'external source exposed'; "
                    "(p/'written').write_text('allowed'); "
                    f"fds={descriptors!r}; "
                    "assert all(not os.path.lexists('/proc/self/fd/'+str(fd)) for fd in fds), 'mount fd leaked'"
                )
                if os.getuid() == 0:
                    code += (
                        "; assert os.geteuid() == 65534, 'incorrect inner identity'; "
                        # bwrap can add an intermediate user namespace. The
                        # immediate uid_map is not an initial-host UID attestation.
                        f"assert not os.access({str(root_private)!r}, os.R_OK), 'host root identity retained'"
                    )
                argv = base_argv + ["/usr/bin/python3", "-I", "-c", code]
                result = subprocess.run(argv, pass_fds=descriptors, close_fds=True,
                                        capture_output=True, text=True, timeout=10,
                                        **cli.sandbox_credentials())
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((storage / "written").read_text(), "allowed")
                self.assertFalse((outside / "written").exists())

    @patch.object(cli.shutil, "which", return_value=None)
    def test_missing_sandbox_never_falls_back(self, which):
        with self.assertRaises(cli.PolicyError):
            cli.sandbox_command(self.arguments("/tmp"), Path("/usr/bin/php"), Path("/module/phese.so"))


if __name__ == "__main__":
    unittest.main()
