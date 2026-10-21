"""Setup fixtures never run assistant models or change a real PHP service."""
import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from phese import cli, setup


class RuntimeSelectionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.base = Path(self.directory.name)
        self.php = self.base / "php"
        self.module = self.base / "phese.so"
        self.php.write_bytes(b"trusted PHP fixture")
        self.php.chmod(0o700)
        self.module.write_bytes(b"trusted native fixture")

    def tearDown(self):
        self.directory.cleanup()

    def test_old_php_is_refused_before_native_probe(self):
        info = {"version": "8.5.11", "version_id": 80511, "zts": True,
                "cve_2026_109618_109619_version_gate": False}
        with patch.object(cli, "php_info", return_value=info), patch.object(cli, "emit"), \
                patch.object(setup, "run") as probe:
            with self.assertRaises(cli.PolicyError):
                setup.detect_runtime(self.php, self.module)
        probe.assert_not_called()

    def test_missing_or_unloaded_module_is_refused(self):
        info = {"version": "8.5.12", "version_id": 80512, "zts": True,
                "cve_2026_109618_109619_version_gate": True}
        with patch.object(cli, "php_info", return_value=info), \
                patch.object(setup, "run", return_value=argparse.Namespace(stdout="null")):
            for module in (self.base / "missing.so", self.module):
                with self.subTest(module=module), self.assertRaises(cli.PolicyError):
                    setup.detect_runtime(self.php, module)

    def test_loaded_status_proves_matching_native_abi(self):
        info = {"version": "8.5.12", "version_id": 80512, "zts": True,
                "cve_2026_109618_109619_version_gate": True}
        status = dict(seccomp_active=True, no_new_privileges=True, version_gate=True)
        with patch.object(cli, "php_info", return_value=info), \
                patch.object(setup, "run", return_value=argparse.Namespace(stdout=json.dumps(status))) as probe:
            result = setup.detect_runtime(self.php, self.module)
        self.assertTrue(result["native_verified"])
        self.assertTrue(result["zts"])
        self.assertIn("extension=" + str(self.module), probe.call_args.args[0])
        self.assertIn("-n", probe.call_args.args[0])

    def test_old_bwrap_is_refused(self):
        with patch.object(setup.shutil, "which", return_value=str(self.php)), \
                patch.object(setup, "run", return_value=argparse.Namespace(stdout="bubblewrap 0.9.0")):
            with self.assertRaises(cli.PolicyError):
                setup.detect_bwrap()


class SetupTransactions(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.base = Path(self.directory.name)
        self.app = self.base / "app $(touch forbidden); spaces"
        self.app.mkdir(mode=0o700)
        self.php_source = self.app / "index.php"
        self.php_source.write_text("<?php system($input);\n")
        self.original_source = self.php_source.read_bytes()
        self.state = self.base / "private state"
        self.runtime = {"php": "/trusted/php", "extension": "/trusted/phese.so",
                        "version": "8.5.12", "version_id": 80512, "zts": True,
                        "native_verified": True}
        self.args = setup.parser().parse_args(["--app", str(self.app), "--state-dir", str(self.state)])
        self.runtime_patch = patch.object(setup, "detect_runtime", return_value=self.runtime)
        self.bwrap_patch = patch.object(setup, "detect_bwrap", return_value={"path": "/usr/bin/bwrap", "version": "0.10.0"})
        self.runtime_patch.start()
        self.bwrap_patch.start()

    def tearDown(self):
        self.bwrap_patch.stop()
        self.runtime_patch.stop()
        self.directory.cleanup()

    def test_plan_does_not_create_files_or_grant_discovered_writes(self):
        (self.app / "storage").mkdir()
        before = sorted(path.name for path in self.app.iterdir())
        plan = setup.build_plan(self.args)
        self.assertEqual(sorted(path.name for path in self.app.iterdir()), before)
        self.assertFalse(self.state.exists())
        self.assertEqual(plan["config"]["network"], "none")
        self.assertEqual(plan["config"]["write_dirs"], [])
        self.assertIn(str(self.app / "storage"), plan["summary"]["suggested_write_dirs"])
        self.assertFalse(plan["summary"]["assistant_model_invoked"])

    def test_apply_is_idempotent_preserves_user_rules_and_never_rewrites_php(self):
        user_rules = b"# Existing project\nKeep this exact instruction.\n"
        (self.app / "AGENTS.md").write_bytes(user_rules)
        first = setup.apply_plan(setup.build_plan(self.args))
        self.assertEqual(first["changed_files"], 3)
        self.assertEqual(first["request_count"], 1)
        agents = (self.app / "AGENTS.md").read_bytes()
        self.assertTrue(agents.startswith(user_rules))
        self.assertEqual(agents.count(setup.BEGIN.encode()), 1)
        second = setup.apply_plan(setup.build_plan(self.args))
        self.assertEqual(second["changed_files"], 0)
        self.assertEqual((self.app / "AGENTS.md").read_bytes(), agents)
        self.assertEqual(self.php_source.read_bytes(), self.original_source)
        self.assertEqual((self.app / ".phese/config.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.state / "requests.json").stat().st_mode & 0o777, 0o600)
        self.assertFalse((Path.cwd() / "forbidden").exists())

    def test_file_change_after_plan_is_refused(self):
        path = self.app / "AGENTS.md"
        path.write_text("original")
        plan = setup.build_plan(self.args)
        path.write_text("new independent rules")
        with self.assertRaises(cli.PolicyError):
            setup.apply_plan(plan)
        self.assertEqual(path.read_text(), "new independent rules")
        self.assertFalse((self.app / ".phese").exists())

    def test_partial_apply_rolls_back_earlier_files(self):
        existing = self.app / "AGENTS.md"
        existing.write_text("original rules")
        original_atomic = setup.atomic_write

        def write_or_fail(path, data, mode=0o600):
            if path.name == "CLAUDE.md":
                raise OSError("fixture failure")
            return original_atomic(path, data, mode)

        with patch.object(setup, "atomic_write", side_effect=write_or_fail):
            with self.assertRaises(OSError):
                setup.apply_plan(setup.build_plan(self.args))
        self.assertEqual(existing.read_text(), "original rules")
        self.assertFalse((self.app / ".phese/config.json").exists())
        self.assertEqual(self.php_source.read_bytes(), self.original_source)

    def test_symlink_targets_and_shared_writable_app_are_refused(self):
        unrelated = self.base / "unrelated"
        unrelated.write_text("untouched")
        target = self.app / "AGENTS.md"
        target.symlink_to(unrelated)
        with self.assertRaises(cli.PolicyError):
            setup.build_plan(self.args)
        self.assertEqual(unrelated.read_text(), "untouched")
        target.unlink()
        self.app.chmod(0o777)
        with self.assertRaises(cli.PolicyError):
            setup.build_plan(self.args)

    def test_unmanaged_or_invalid_config_is_never_adopted(self):
        folder = self.app / ".phese"
        folder.mkdir()
        for contents in ("", "[]", '{"managed_by":"other"}', "invalid"):
            with self.subTest(contents=contents):
                target = folder / "config.json"
                target.write_text(contents)
                with self.assertRaises(cli.PolicyError):
                    setup.build_plan(self.args)
                self.assertEqual(target.read_text(), contents)

    def test_write_escape_and_symlink_are_refused(self):
        (self.app / "storage").symlink_to(self.base, target_is_directory=True)
        for value in (str(self.app), str(self.base), str(self.app / "storage")):
            with self.subTest(value=value), self.assertRaises((cli.PolicyError, OSError)):
                args = argparse.Namespace(**{**vars(self.args), "write": [value]})
                setup.build_plan(args)

    def test_private_state_must_be_outside_app(self):
        self.args.state_dir = str(self.app / "reports")
        with self.assertRaises(cli.PolicyError):
            setup.build_plan(self.args)

    def test_broken_managed_markers_refuse_instead_of_erasing_user_rules(self):
        for original in (setup.BEGIN, setup.END, setup.BEGIN + setup.BEGIN + setup.END + setup.END):
            with self.assertRaises(cli.PolicyError):
                setup.merge_instructions(original.encode(), b"replacement")

    def test_configured_run_preserves_argv_and_reuses_fail_closed_runner(self):
        setup.apply_plan(setup.build_plan(self.args))
        config = self.app / ".phese/config.json"
        with patch.object(cli, "main", return_value=7) as protected_runner:
            code = setup.configured_main(["--config", str(config), "index.php", "$(unsafe); literal"])
        self.assertEqual(code, 7)
        argv = protected_runner.call_args.args[0]
        self.assertEqual(argv[-2:], ["index.php", "$(unsafe); literal"])
        self.assertIn("--extension", argv)
        self.assertIn("--timeout", argv)
        self.assertEqual(argv[0], "run")

    def test_configured_run_refuses_tampered_network_policy(self):
        setup.apply_plan(setup.build_plan(self.args))
        config = self.app / ".phese/config.json"
        data = json.loads(config.read_text())
        data["network"] = "host"
        config.write_text(json.dumps(data))
        with patch.object(cli, "main") as protected_runner, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(setup.configured_main(["--config", str(config), "index.php"]), 2)
        protected_runner.assert_not_called()


class BootstrapTests(unittest.TestCase):
    PHPIZE_VERSION = ("Configuring for:\nPHP Version:             8.5\n"
                     "PHP Api Version:         20250925\n"
                     "Zend Module Api No:      20250925\n"
                     "Zend Extension Api No:   420250925\n")

    def source_fixture(self, directory, name="trusted source with spaces"):
        repository = directory / name
        repository.mkdir()
        for relative in setup.SOURCE_FILES:
            path = repository / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("trusted source fixture")
            path.chmod(0o700 if path.name == "build.sh" else 0o600)
        return repository

    @contextlib.contextmanager
    def working_directory(self, directory):
        original = Path.cwd()
        os.chdir(directory)
        try:
            yield
        finally:
            os.chdir(original)

    def test_installed_module_uses_explicit_source_instead_of_release_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repository = self.source_fixture(base)
            installed = base / "releases/codehash/phese/setup.py"
            with patch.object(setup, "__file__", str(installed)):
                self.assertEqual(setup.source_directory(str(repository)), repository)

    def test_installed_module_falls_back_to_validated_source_cwd(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repository = self.source_fixture(base)
            installed = base / "site-packages/phese/setup.py"
            with patch.object(setup, "__file__", str(installed)), self.working_directory(repository):
                self.assertEqual(setup.source_directory(), repository)

    def test_installed_module_without_sdk_explains_source_before_runtime_probe(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            installed = base / "site-packages/phese/setup.py"
            error = io.StringIO()
            with patch.object(setup, "__file__", str(installed)), self.working_directory(base), \
                    patch.object(setup, "run") as runner, \
                    patch.object(cli, "php_info") as php_probe, \
                    contextlib.redirect_stderr(error):
                code = setup.bootstrap_main(["--php", "/missing/php", "--php-config", "/missing/php-config"])
            self.assertEqual(code, 2)
            self.assertIn("--source", error.getvalue())
            runner.assert_not_called()
            php_probe.assert_not_called()

    def test_incomplete_explicit_source_does_not_fall_back_silently(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repository = self.source_fixture(base)
            incomplete = base / "incomplete"
            incomplete.mkdir()
            with self.working_directory(repository), self.assertRaises(cli.PolicyError):
                setup.source_directory(str(incomplete))

    def test_shared_writable_or_symlinked_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repository = self.source_fixture(base)
            repository.chmod(0o777)
            with self.assertRaises(cli.PolicyError):
                setup.source_directory(repository)
            repository.chmod(0o700)
            alias = base / "source alias"
            alias.symlink_to(repository, target_is_directory=True)
            with self.assertRaises(cli.PolicyError):
                setup.source_directory(alias)

    def sdk_runner(self, extension_dir="/php/lib/php/extensions/no-debug-zts-20250925", phpize_output=None):
        # Real php-config --help exposes --version and --extension-dir, but
        # rejects unknown options. Do not mirror an invented --phpapi command.
        def runner(argv, **kwargs):
            if Path(argv[0]).name == "phpize" and argv[1:] == ["--version"]:
                return argparse.Namespace(stdout=self.PHPIZE_VERSION if phpize_output is None else phpize_output)
            if Path(argv[0]).name == "php-config" and argv[1:] == ["--version"]:
                return argparse.Namespace(stdout="8.5.12\n")
            if Path(argv[0]).name == "php-config" and argv[1:] == ["--extension-dir"]:
                return argparse.Namespace(stdout=extension_dir + "\n")
            raise subprocess.CalledProcessError(1, argv, output="Usage: php-config [OPTION]")
        return runner

    def test_supported_sdk_interfaces_cross_check_api_and_zts(self):
        with patch.object(setup, "run", side_effect=self.sdk_runner()) as runner:
            self.assertEqual(setup.development_abi(Path("/sdk/php-config"), Path("/sdk/phpize"),
                                                   {"version": "8.5.12", "zts": True}), "20250925")
        self.assertEqual([call.args[0][1:] for call in runner.call_args_list],
                         [["--version"], ["--extension-dir"]])

    def test_development_abi_rejects_mismatch_and_unidentified_layout(self):
        for folder in ("/php/no-debug-zts-20240924", "/php/no-debug-non-zts-20250925", "/usr/lib64/php/modules"):
            with self.subTest(folder=folder), patch.object(setup, "run", side_effect=self.sdk_runner(folder)):
                with self.assertRaises(cli.PolicyError):
                    setup.development_abi(Path("/sdk/php-config"), Path("/sdk/phpize"),
                                          {"version": "8.5.12", "zts": True})
        for output in ("PHP Api Version: 20250925\n", self.PHPIZE_VERSION.replace("PHP Version:             8.5", "PHP Version:             8.4"),
                       self.PHPIZE_VERSION.replace("PHP Api Version:         20250925", "PHP Api Version:         20240924")):
            with self.subTest(output=output), patch.object(setup, "run", side_effect=self.sdk_runner(phpize_output=output)):
                with self.assertRaises(cli.PolicyError):
                    setup.development_abi(Path("/sdk/php-config"), Path("/sdk/phpize"),
                                          {"version": "8.5.12", "zts": True})

    def test_bootstrap_plan_uses_actual_php_sdk_command_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            php, config, phpize = base / "php", base / "php-config", base / "phpize"
            for path in (php, config, phpize):
                path.write_text("trusted fixture")
                path.chmod(0o700)
            info = {"version": "8.5.12", "version_id": 80512, "zts": True,
                    "cve_2026_109618_109619_version_gate": True}
            output = io.StringIO()
            with patch.object(cli, "php_info", return_value=info), \
                    patch.object(setup, "run", side_effect=self.sdk_runner()) as runner, \
                    patch.object(setup, "detect_bwrap", return_value={}), \
                    patch.object(setup.shutil, "which", return_value=str(php)), \
                    contextlib.redirect_stdout(output):
                code = setup.bootstrap_main(["--php", str(php), "--php-config", str(config)])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output.getvalue())["php_api"], "20250925")
            self.assertEqual(runner.call_count, 3)

    def test_module_receipt_failure_restores_previous_owned_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "source.so"
            destination = base / "installed/phese.so"
            source.write_bytes(b"version one fixture")
            setup.install_module(source, destination, "20250925", True)
            old = destination.read_bytes()
            source.write_bytes(b"version two fixture")
            original_atomic = setup.atomic_write

            def fail_receipt(path, content, mode=0o600):
                if path.name.endswith(".json"):
                    raise OSError("fixture receipt write failure")
                return original_atomic(path, content, mode)

            with patch.object(setup, "atomic_write", side_effect=fail_receipt):
                with self.assertRaises((OSError, cli.PolicyError)):
                    setup.install_module(source, destination, "20250925", True)
            self.assertEqual(destination.read_bytes(), old)

    def test_unmanaged_native_binary_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source, destination = base / "source.so", base / "unrelated.so"
            source.write_bytes(b"module fixture")
            destination.write_bytes(b"unrelated existing binary")
            with self.assertRaises(cli.PolicyError):
                setup.install_module(source, destination, "20250925", True)
            self.assertEqual(destination.read_bytes(), b"unrelated existing binary")

    def test_bootstrap_plan_rejects_mismatched_development_tools_without_building(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            php, config, phpize = base / "php", base / "php-config", base / "phpize"
            for path in (php, config, phpize):
                path.write_text("trusted fixture")
                path.chmod(0o700)
            info = {"version": "8.5.12", "cve_2026_109618_109619_version_gate": True}
            with patch.object(cli, "php_info", return_value=info), \
                    patch.object(setup, "run", return_value=argparse.Namespace(stdout="8.5.6")) as runner, \
                    contextlib.redirect_stderr(io.StringIO()):
                code = setup.bootstrap_main(["--php", str(php), "--php-config", str(config)])
            self.assertEqual(code, 2)
            self.assertEqual(runner.call_count, 1)


if __name__ == "__main__":
    unittest.main()
