"""Transactional web deployment tests: all mutations and commands are fixtures."""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).absolute().parents[1] / "tools/web_guard.py"
SPEC = importlib.util.spec_from_file_location("phese_web_guard_test", SOURCE)
web = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(web)


class FakeCommands:
    def __init__(self):
        self.calls = []
        self.active = True
        self.fail_once = None
        self.on_call = None
        self.cli_loaded = lambda: False
        self.doctor = {"cve_2026_109618_109619_version_gate": True,
                       "phese": {"scope": "startup", "seccomp_active": True,
                                 "no_new_privileges": True, "version_gate": True}}
        self.secret = "PRIVATE-HEALTH-RESPONSE-MUST-NOT-BE-SAVED"

    def __call__(self, argv):
        argv = list(argv)
        self.calls.append(argv)
        if self.on_call:
            self.on_call(argv)
        failure = bool(self.fail_once and self.fail_once(argv))
        if failure:
            self.fail_once = None
        code, output = (1 if failure else 0), self.secret
        if "is-active" in argv and not self.active:
            code = 3
        if argv[-1] == web.CLI_PROBE:
            output = json.dumps(self.cli_loaded())
        if Path(argv[0]).name == "phese" and argv[1] == "doctor":
            output = json.dumps(self.doctor)
        return subprocess.CompletedProcess(argv, code, output, self.secret)


class WebGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="phese-web-fixture-")
        self.root = Path(self.tmp.name)
        self.php = self.make_file("usr/local/php/bin/php", b"fixture-php", 0o755)
        self.module = self.make_file("inputs/phese.so", b"fixture-native-module")
        self.scan = self.root / "etc/php.d"
        self.scan.mkdir(parents=True)
        self.global_ini = self.make_file("etc/php.ini", b"; existing normal CLI configuration\n")
        self.app = self.make_file("app/index.php", b"<?php echo 'normal application';")
        self.page = self.make_file("pages/blocked.html", b"<!doctype html><p>{{EVENT_ID}} {{TIMESTAMP}}</p>")
        self.page_ini = self.make_file("pages/phese-page.ini", (
            f'phese.block_page = "{self.page}"\n'
            'phese.block_csp = "default-src \'none\'; script-src \'none\'"\n').encode())
        self.make_file("usr/local/bin/phese", b"fixture-doctor", 0o755)
        self.health = [str(self.make_file("usr/local/bin/health", b"fixture-health", 0o755))]
        self.config_check = [str(self.make_file("usr/local/bin/config-check", b"fixture-config", 0o755)), "-t"]
        (self.root / "etc/systemd/system").mkdir(parents=True)
        (self.root / "var/lib").mkdir(parents=True)
        self.fake = FakeCommands()
        self.guard = web.WebGuard("fixture-php.service", self.php, self.module,
                                  self.scan, self.page_ini, "worker", root=self.root,
                                  runner=self.fake)

    def make_file(self, relative, data, mode=0o644):
        path = self.root / relative
        path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)
        return path

    def tearDown(self):
        self.tmp.cleanup()

    def restarts(self):
        return sum("restart" in command for command in self.fake.calls)

    def test_plan_has_no_filesystem_or_command_side_effects(self):
        plan = self.guard.plan()
        self.assertEqual(plan["scope"], "worker")
        self.assertEqual(plan["action"], "create-web-files")
        self.assertFalse(plan["default_php_ini_changed"])
        self.assertFalse(self.guard.extra_dir.exists())
        self.assertFalse(self.guard.state_dir.exists())
        self.assertFalse(self.guard.shared_guard.state_dir.exists())
        self.assertFalse(self.guard.native_dir.exists())
        self.assertEqual(self.fake.calls, [])

    def test_success_is_scoped_atomic_and_idempotent(self):
        sibling = self.make_file("etc/systemd/system/fixture-php.service.d/90-asylumenforce.conf",
                                 b"[Service]\nNoNewPrivileges=yes\n")
        originals = {path: path.read_bytes() for path in (self.global_ini, self.app, sibling)}
        result = self.guard.apply(self.health, self.config_check)
        self.assertEqual(result["result"], "applied")
        self.assertEqual(result["normal_cli_loads_phese"], False)
        dropin = self.guard.dropin.read_text()
        self.assertIn("PHP_INI_SCAN_DIR=" + str(self.scan) + ":" + str(self.guard.extra_dir), dropin)
        self.assertIn("ExecStartPre=", dropin)
        self.assertNotIn("ExecReload", dropin)
        self.assertNotIn("ExecStart=", dropin)
        self.assertIn('phese.scope = "worker"', self.guard.ini.read_text())
        cache = self.guard.native_dir / (web.digest(self.module.read_bytes()) + ".so")
        self.assertEqual(cache.read_bytes(), self.module.read_bytes())
        self.assertEqual(cache.stat().st_mode & 0o777, 0o444)
        self.assertEqual(self.guard.state_file.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.guard.read_state()["phase"], "applied")
        self.assertEqual(self.guard.apply(self.health)["result"], "unchanged")
        self.assertEqual(self.restarts(), 1)
        for path, data in originals.items():
            self.assertEqual(path.read_bytes(), data)
        self.assertTrue(any(command[0] == "/usr/bin/env" for command in self.fake.calls))
        for command in self.fake.calls:
            if command[-1] == web.CLI_PROBE:
                self.assertNotIn("-n", command)
        self.assertNotIn(self.fake.secret, self.guard.state_file.read_text())

    def test_rollback_removes_only_owned_files_and_keeps_shared_module(self):
        self.guard.apply(self.health)
        cache = next(self.guard.native_dir.glob("*.so"))
        self.assertEqual(self.guard.rollback()["result"], "rolled-back")
        self.assertFalse(self.guard.ini.exists())
        self.assertFalse(self.guard.dropin.exists())
        self.assertTrue(cache.exists())
        self.assertEqual(self.guard.rollback()["result"], "already-rolled-back")
        self.assertEqual(self.restarts(), 2)

    def test_rollback_recovers_an_inactive_managed_service(self):
        self.guard.apply(self.health)
        self.fake.active = False
        def restart_recovers(command):
            if "restart" in command:
                self.fake.active = True
        self.fake.on_call = restart_recovers
        self.assertEqual(self.guard.rollback()["result"], "rolled-back")
        self.assertTrue(self.fake.active)
        self.assertFalse(self.guard.ini.exists())
        self.assertFalse(self.guard.dropin.exists())
        self.assertEqual(self.restarts(), 2)

    def test_unmanaged_identical_or_different_files_are_never_adopted(self):
        prepared = self.guard.prepare()
        for key in ("ini", "dropin"):
            with self.subTest(key=key):
                target = self.guard.targets[key]
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(prepared["data"][key])
                before = target.read_bytes()
                with self.assertRaisesRegex(web.GuardError, "unmanaged"):
                    self.guard.apply(self.health)
                self.assertEqual(target.read_bytes(), before)
                target.unlink()
        self.assertEqual(self.restarts(), 0)

    def test_doctor_must_attest_matching_loaded_native_module(self):
        self.fake.doctor["phese"]["seccomp_active"] = False
        with self.assertRaisesRegex(web.GuardError, "attestation failed"):
            self.guard.apply(self.health)
        self.assertFalse(self.guard.ini.exists())
        self.assertFalse(self.guard.dropin.exists())
        self.assertEqual(self.restarts(), 0)

    def test_baseline_health_failure_causes_no_service_mutation(self):
        self.fake.fail_once = lambda command: command == self.health
        with self.assertRaises(web.GuardError):
            self.guard.apply(self.health)
        self.assertEqual(self.restarts(), 0)
        self.assertFalse(self.guard.ini.exists())
        self.assertFalse(self.guard.native_dir.exists())

    def test_existing_global_cli_load_is_refused_without_touching_it(self):
        self.fake.cli_loaded = lambda: True
        before = self.global_ini.read_bytes()
        with self.assertRaisesRegex(web.GuardError, "normal PHP CLI"):
            self.guard.apply(self.health)
        self.assertEqual(self.global_ini.read_bytes(), before)
        self.assertEqual(self.restarts(), 0)

    def test_post_restart_health_failure_restores_files_and_service(self):
        self.fake.fail_once = lambda command: command == self.health and self.restarts() > 0
        with self.assertRaisesRegex(web.GuardError, "original files and service health restored"):
            self.guard.apply(self.health)
        self.assertFalse(self.guard.ini.exists())
        self.assertFalse(self.guard.dropin.exists())
        self.assertEqual(self.guard.read_state()["phase"], "rolled_back")
        self.assertEqual(self.restarts(), 2)

    def test_post_restart_cli_contamination_is_rolled_back(self):
        self.fake.cli_loaded = lambda: self.guard.ini.exists() and self.restarts() > 0
        with self.assertRaisesRegex(web.GuardError, "restored"):
            self.guard.apply(self.health)
        self.assertFalse(self.guard.ini.exists())
        self.assertEqual(self.guard.read_state()["phase"], "rolled_back")
        self.assertEqual(self.restarts(), 2)

    def test_config_check_under_service_scan_failure_restores_baseline(self):
        self.fake.fail_once = lambda command: command[0] == "/usr/bin/env"
        with self.assertRaisesRegex(web.GuardError, "restored"):
            self.guard.apply(self.health, self.config_check)
        self.assertFalse(self.guard.ini.exists())
        self.assertFalse(self.guard.dropin.exists())
        self.assertEqual(self.guard.read_state()["phase"], "rolled_back")
        self.assertEqual(self.restarts(), 1)

    def test_publication_failure_never_leaves_partial_managed_config(self):
        publish = self.guard.publish
        def broken(path, *args, **kwargs):
            if path == self.guard.dropin:
                raise OSError("injected disk failure")
            return publish(path, *args, **kwargs)
        with patch.object(self.guard, "publish", side_effect=broken):
            with self.assertRaisesRegex(web.GuardError, "restored"):
                self.guard.apply(self.health)
        self.assertFalse(self.guard.ini.exists())
        self.assertFalse(self.guard.dropin.exists())
        self.assertEqual(self.guard.read_state()["phase"], "rolled_back")

    def test_restart_failure_rolls_back_and_restarts_original_configuration(self):
        self.fake.fail_once = lambda command: "restart" in command
        with self.assertRaisesRegex(web.GuardError, "restored"):
            self.guard.apply(self.health)
        self.assertFalse(self.guard.ini.exists())
        self.assertFalse(self.guard.dropin.exists())
        self.assertEqual(self.restarts(), 2)

    def test_failed_service_recovery_is_recorded_and_can_be_retried(self):
        def inactive_after_restart(command):
            if "restart" in command:
                self.fake.active = False
        self.fake.on_call = inactive_after_restart
        with self.assertRaisesRegex(web.GuardError, "requires attention"):
            self.guard.apply(self.health)
        self.assertEqual(self.guard.read_state()["phase"], "failed")
        self.assertFalse(self.guard.ini.exists())
        self.fake.on_call = None
        self.fake.active = True
        self.assertEqual(self.guard.rollback()["result"], "rolled-back")

    def test_publication_collision_preserves_foreign_file_and_reports_attention(self):
        real_link = os.link
        def collision(source, destination, **kwargs):
            if destination == self.guard.ini:
                destination.write_bytes(b"; new operator-owned file\n")
                destination.chmod(0o644)
            return real_link(source, destination, **kwargs)
        with patch.object(web.os, "link", side_effect=collision):
            with self.assertRaisesRegex(web.GuardError, "requires attention"):
                self.guard.apply(self.health)
        self.assertEqual(self.guard.ini.read_bytes(), b"; new operator-owned file\n")
        self.assertEqual(self.guard.read_state()["phase"], "failed")
        self.assertEqual(self.restarts(), 0)

    def test_fifo_managed_target_is_rejected_without_opening_it(self):
        self.guard.extra_dir.mkdir(parents=True)
        os.mkfifo(self.guard.ini, 0o600)
        with self.assertRaisesRegex(web.GuardError, "not a regular file"):
            self.guard.plan()
        self.assertEqual(self.fake.calls, [])

    def test_input_replacement_during_doctor_is_detected_before_web_files(self):
        def replace(command):
            if Path(command[0]).name == "phese":
                self.page.write_bytes(b"<!doctype html><p>changed {{EVENT_ID}} {{TIMESTAMP}}</p>")
        self.fake.on_call = replace
        with self.assertRaisesRegex(web.GuardError, "reviewed input changed"):
            self.guard.apply(self.health)
        self.assertFalse(self.guard.ini.exists())
        self.assertFalse(self.guard.dropin.exists())
        self.assertEqual(self.restarts(), 0)

    def test_shared_php_rollout_lock_serializes_web_transactions(self):
        with self.guard.shared_guard.lock():
            with self.assertRaisesRegex(web.GuardError, "another transaction"):
                self.guard.apply(self.health)
        self.assertEqual(self.fake.calls, [])
        self.assertFalse(self.guard.ini.exists())

    def test_changed_owned_content_or_inode_or_mode_blocks_rollback(self):
        self.guard.apply(self.health)
        target = self.guard.ini
        original, before = target.read_bytes(), self.restarts()
        target.write_bytes(original + b"; operator edit\n")
        with self.assertRaisesRegex(web.GuardError, "changed identity, mode or content"):
            self.guard.rollback()
        self.assertTrue(self.guard.dropin.exists())
        target.write_bytes(original)
        target.chmod(0o600)
        with self.assertRaises(web.GuardError):
            self.guard.rollback()
        target.chmod(0o644)
        replacement = target.with_name("replacement")
        replacement.write_bytes(original)
        replacement.chmod(0o644)
        os.replace(replacement, target)
        with self.assertRaises(web.GuardError):
            self.guard.rollback()
        self.assertEqual(self.restarts(), before)
        self.assertEqual(target.read_bytes(), original)

    def test_changed_owned_config_is_not_silently_upgraded(self):
        self.guard.apply(self.health)
        self.module.write_bytes(b"new-reviewed-native-candidate")
        before = self.guard.ini.read_bytes()
        with self.assertRaisesRegex(web.GuardError, "roll back before changing"):
            self.guard.apply(self.health)
        self.assertEqual(self.guard.ini.read_bytes(), before)
        self.assertEqual(self.restarts(), 1)

    def test_symlinks_and_writable_input_parents_are_not_trusted(self):
        original = self.module.with_name("original.so")
        self.module.rename(original)
        self.module.symlink_to(original)
        with self.assertRaisesRegex(web.GuardError, "symlink"):
            self.guard.plan()
        self.module.unlink()
        original.rename(self.module)
        self.module.parent.chmod(0o777)
        with self.assertRaisesRegex(web.GuardError, "writable"):
            self.guard.plan()
        self.assertEqual(self.fake.calls, [])

    def test_managed_target_symlink_is_preserved(self):
        destination = self.make_file("unrelated", b"preserve")
        self.guard.dropin_dir.mkdir(parents=True)
        self.guard.dropin.symlink_to(destination)
        with self.assertRaisesRegex(web.GuardError, "symlink"):
            self.guard.apply(self.health)
        self.assertEqual(destination.read_bytes(), b"preserve")
        self.assertEqual(self.restarts(), 0)

    def test_private_state_and_hash_cache_are_checked(self):
        self.guard.native_dir.mkdir(parents=True)
        cache = self.guard.native_dir / (web.digest(self.module.read_bytes()) + ".so")
        cache.write_bytes(b"wrong data")
        with self.assertRaisesRegex(web.GuardError, "immutable module cache"):
            self.guard.apply(self.health)
        self.assertFalse(self.guard.ini.exists())
        cache.unlink()
        self.guard.apply(self.health)
        self.guard.state_file.chmod(0o644)
        with self.assertRaisesRegex(web.GuardError, "protected regular file"):
            self.guard.rollback()
        self.assertTrue(self.guard.ini.exists())

    def test_startup_scope_is_rejected_for_all_web_handlers(self):
        for service in ("fixture-php.service", "fixture-apache.service"):
            guard = web.WebGuard(service, self.php, self.module, self.scan, self.page_ini,
                                 "startup", root=self.root, runner=self.fake)
            with self.subTest(service=service), self.assertRaisesRegex(web.GuardError, "requires scope=worker"):
                guard.plan()
        self.assertEqual(self.fake.calls, [])

    def test_other_ini_in_new_service_scan_directory_is_not_activated(self):
        self.guard.extra_dir.mkdir(parents=True)
        other = self.guard.extra_dir / "10-unmanaged.ini"
        other.write_text("extension=other.so\n")
        with self.assertRaisesRegex(web.GuardError, "unmanaged INI"):
            self.guard.plan()
        self.assertTrue(other.exists())

    def test_page_ini_has_a_strict_directive_allowlist_and_size_limits(self):
        valid = self.page_ini.read_bytes()
        invalid = [valid + b"extension=evil.so\n", valid + b'phese.block_csp="duplicate"\n',
                   b'phese.block_page="${HOME}/secret"\nphese.block_csp="x"\n',
                   f'phese.block_page="{self.page}"\nphese.block_csp="'.encode() + b"x" * 4097 + b'"\n']
        for data in invalid:
            with self.subTest(data=data[:40]):
                self.page_ini.write_bytes(data)
                with self.assertRaises(web.GuardError):
                    self.guard.plan()
        self.assertEqual(self.fake.calls, [])

    def test_page_must_be_public_html_not_arbitrary_root_file(self):
        self.page.write_bytes(b"private-account-data")
        with self.assertRaisesRegex(web.GuardError, "public block page"):
            self.guard.plan()
        self.page.write_bytes(b"<!doctype html>" + b"a" * 262144)
        with self.assertRaises(web.GuardError):
            self.guard.plan()

    def test_unsafe_service_and_health_commands_are_rejected(self):
        for name in ("../php.service", "php.service;id", "--bad.service", "php"):
            with self.subTest(name=name), self.assertRaises(web.GuardError):
                web.WebGuard(name, root=self.root, runner=self.fake)
        shell = self.make_file("usr/bin/sh", b"fixture-shell", 0o755)
        for argv in ([str(shell), "-c", "true"], [], ["relative-health"], [str(self.php), 1]):
            with self.subTest(argv=argv), self.assertRaises(web.GuardError):
                self.guard.apply(argv)
        self.assertEqual(self.fake.calls, [])

    def test_inactive_service_is_not_started(self):
        self.fake.active = False
        with self.assertRaisesRegex(web.GuardError, "already be active"):
            self.guard.apply(self.health)
        self.assertEqual(self.restarts(), 0)
        self.assertFalse(self.guard.ini.exists())

    def test_no_unmanaged_rollback_or_alternate_root_cli_apply(self):
        with self.assertRaisesRegex(web.GuardError, "no managed web state"):
            self.guard.rollback(self.health)
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            code = web.main(["apply", self.guard.service, "--system-root", str(self.root), "--apply"])
        self.assertEqual(code, 1)
        self.assertIn("read-only", output.getvalue())
        self.assertEqual(self.fake.calls, [])


if __name__ == "__main__":
    unittest.main()
