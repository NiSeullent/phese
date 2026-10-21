"""Transactional filesystem/systemd tests; no real service is mutated."""

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


SOURCE = Path(__file__).absolute().parents[1] / "tools/service_guard.py"
SPEC = importlib.util.spec_from_file_location("service_guard", SOURCE)
guard_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard_module)
ServiceGuard, GuardError = guard_module.ServiceGuard, guard_module.GuardError


class FakeCommands:
    def __init__(self):
        self.calls = []
        self.fail_once = None
        self.active = True
        self.secret = "SENSITIVE-COMMAND-OUTPUT"

    def __call__(self, argv):
        self.calls.append(list(argv))
        failure = self.fail_once and self.fail_once(argv)
        if failure:
            self.fail_once = None
        code = 1 if failure else 0
        if "is-active" in argv and not self.active:
            code = 3
        return subprocess.CompletedProcess(argv, code, self.secret, self.secret)


class ServiceGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "etc/systemd/system").mkdir(parents=True)
        (self.root / "var/lib").mkdir(parents=True)
        self.policy = self.root / "policy.conf"
        self.policy.write_text("[Service]\nNoNewPrivileges=yes\nProtectSystem=full\n")
        self.fake = FakeCommands()
        self.guard = ServiceGuard("fixture-php.service", root=self.root,
                                  policy=self.policy, runner=self.fake)
        self.health = ["/usr/bin/true"]

    def tearDown(self):
        self.tmp.cleanup()

    def test_successful_apply_is_additive_and_idempotent(self):
        other = self.guard.dropin_dir / "10-existing.conf"
        self.guard.dropin_dir.mkdir()
        other.write_text("[Service]\nMemoryMax=128M\n")
        before = other.read_bytes()
        self.assertEqual(self.guard.apply(self.health)["result"], "applied")
        self.assertEqual(other.read_bytes(), before)
        self.assertEqual(self.guard.dropin.read_bytes(), self.policy.read_bytes())
        self.assertEqual(self.guard.state_file.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.guard.read_state()["original"], None)
        self.assertEqual(self.guard.read_state()["phase"], "applied")
        restart_calls = len([x for x in self.fake.calls if "restart" in x])
        self.assertEqual(self.guard.apply(self.health)["result"], "unchanged")
        self.assertEqual(len([x for x in self.fake.calls if "restart" in x]), restart_calls)
        reload_index = next(i for i, x in enumerate(self.fake.calls) if "daemon-reload" in x)
        verify_index = next(i for i, x in enumerate(self.fake.calls) if "verify" in x)
        self.assertLess(reload_index, verify_index)

    def test_different_existing_dropin_is_not_overwritten(self):
        self.guard.dropin_dir.mkdir()
        self.guard.dropin.write_bytes(b"[Service]\nPrivateTmp=yes\n")
        before = self.guard.dropin.read_bytes()
        with self.assertRaisesRegex(GuardError, "refusing to overwrite"):
            self.guard.apply(self.health)
        self.assertEqual(self.guard.dropin.read_bytes(), before)
        self.assertFalse(any("restart" in x for x in self.fake.calls))

    def test_unmanaged_identical_dropin_is_never_adopted_or_removed(self):
        self.guard.dropin_dir.mkdir()
        self.guard.dropin.write_bytes(self.policy.read_bytes())
        result = self.guard.apply(self.health)
        self.assertFalse(result["owned"])
        with self.assertRaisesRegex(GuardError, "unmanaged"):
            self.guard.rollback()
        self.assertTrue(self.guard.dropin.exists())

    def test_failed_verify_removes_only_our_dropin_and_restores_service(self):
        self.fake.fail_once = lambda argv: "verify" in argv
        with self.assertRaisesRegex(GuardError, "original drop-in state and service health restored"):
            self.guard.apply(self.health)
        self.assertFalse(self.guard.dropin.exists())
        self.assertEqual(self.guard.read_state()["phase"], "rolled_back")
        self.assertTrue(any("restart" in x for x in self.fake.calls))
        self.assertNotIn(self.fake.secret, json.dumps(self.guard.read_state()))

    def test_failed_health_rolls_back_and_checks_original_health(self):
        self.fake.fail_once = lambda argv: argv == self.health
        with self.assertRaisesRegex(GuardError, "restored"):
            self.guard.apply(self.health)
        self.assertFalse(self.guard.dropin.exists())
        self.assertEqual(len([x for x in self.fake.calls if "restart" in x]), 2)
        self.assertEqual(len([x for x in self.fake.calls if x == self.health]), 2)

    def test_partial_write_failure_is_removed_before_restoring_service(self):
        real_fsync = os.fsync
        calls = 0

        def fsync(fd):
            nonlocal calls
            calls += 1
            if calls == 2:  # private backup succeeded; drop-in fsync fails
                raise OSError("simulated write failure")
            return real_fsync(fd)

        with patch.object(guard_module.os, "fsync", fsync):
            with self.assertRaisesRegex(GuardError, "restored"):
                self.guard.apply(self.health)
        self.assertFalse(self.guard.dropin.exists())
        self.assertEqual(self.guard.read_state()["phase"], "rolled_back")

    def test_recovery_preserves_a_concurrently_replaced_dropin(self):
        old_runner = self.guard.runner
        replaced = False

        def runner(argv):
            nonlocal replaced
            if argv == self.health and not replaced:
                replaced = True
                self.guard.dropin.unlink()
                self.guard.dropin.write_text("[Service]\nPrivateTmp=yes\n")
                return subprocess.CompletedProcess(argv, 1, "", "")
            return old_runner(argv)

        self.guard.runner = runner
        with self.assertRaisesRegex(GuardError, "restore-dropin"):
            self.guard.apply(self.health)
        self.assertEqual(self.guard.dropin.read_text(), "[Service]\nPrivateTmp=yes\n")
        self.assertEqual(self.guard.read_state()["phase"], "failed")

    def test_recovery_failure_is_reported_without_false_success(self):
        self.fake.fail_once = lambda argv: "verify" in argv
        old_runner = self.guard.runner

        def runner(argv):
            if "restart" in argv:
                self.fake.active = False
                self.fake.calls.append(argv)
                return subprocess.CompletedProcess(argv, 1, self.fake.secret, self.fake.secret)
            return old_runner(argv)

        self.guard.runner = runner
        with self.assertRaisesRegex(GuardError, "recovery requires attention") as error:
            self.guard.apply(self.health)
        self.assertNotIn(self.fake.secret, str(error.exception))
        self.assertEqual(self.guard.read_state()["phase"], "failed")

    def test_rollback_removes_managed_file_and_keeps_other_dropins(self):
        self.guard.apply(self.health)
        other = self.guard.dropin_dir / "10-existing.conf"
        other.write_text("[Service]\nMemoryMax=128M\n")
        self.assertEqual(self.guard.rollback()["result"], "rolled-back")
        self.assertFalse(self.guard.dropin.exists())
        self.assertTrue(other.exists())
        self.assertEqual(self.guard.rollback()["result"], "already-rolled-back")

    def test_rollback_refuses_a_changed_managed_file(self):
        self.guard.apply(self.health)
        self.guard.dropin.write_text("[Service]\nPrivateTmp=yes\n")
        with self.assertRaisesRegex(GuardError, "changed"):
            self.guard.rollback()
        self.assertTrue(self.guard.dropin.exists())

    def test_symlink_dropin_directory_and_file_are_rejected(self):
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir()
        self.guard.dropin_dir.symlink_to(elsewhere, target_is_directory=True)
        with self.assertRaisesRegex(GuardError, "symlink"):
            self.guard.apply(self.health)
        self.assertEqual(list(elsewhere.iterdir()), [])
        self.guard.dropin_dir.unlink()
        self.guard.dropin_dir.mkdir()
        destination = self.root / "unrelated.conf"
        destination.write_text("must remain unchanged")
        self.guard.dropin.symlink_to(destination)
        with self.assertRaisesRegex(GuardError, "symlink"):
            self.guard.apply(self.health)
        self.assertEqual(destination.read_text(), "must remain unchanged")

    def test_symlink_backup_and_writable_parent_are_rejected(self):
        self.guard.state_dir.mkdir(parents=True)
        elsewhere = self.root / "elsewhere.json"
        elsewhere.write_text("untouched")
        self.guard.state_file.symlink_to(elsewhere)
        with self.assertRaisesRegex(GuardError, "symlink"):
            self.guard.apply(self.health)
        self.assertEqual(elsewhere.read_text(), "untouched")
        self.guard.state_file.unlink()
        self.guard.dropin_dir.mkdir(mode=0o777)
        self.guard.dropin_dir.chmod(0o777)
        with self.assertRaisesRegex(GuardError, "writable"):
            self.guard.apply(self.health)

    def test_inactive_service_is_never_started(self):
        self.fake.active = False
        with self.assertRaisesRegex(GuardError, "already be active"):
            self.guard.apply(self.health)
        self.assertFalse(self.guard.dropin.exists())
        self.assertFalse(any("restart" in x for x in self.fake.calls))

    def test_policy_cannot_install_exec_directives(self):
        self.policy.write_text("[Service]\nExecStart=/usr/bin/true\n")
        with self.assertRaisesRegex(GuardError, "allowlist"):
            self.guard.apply(self.health)
        self.assertFalse(self.guard.dropin.exists())

    def test_plan_is_read_only(self):
        self.assertEqual(self.guard.plan()["action"], "create-dropin")
        self.assertFalse(self.guard.state_dir.exists())
        self.assertFalse(self.guard.dropin_dir.exists())
        self.assertEqual(self.fake.calls, [])


class InputValidationTests(unittest.TestCase):
    def test_service_name_rejects_injection_and_traversal(self):
        for name in ("../sshd.service", "--all.service", "php.service;id", "php service", "php", "a..service", "a@b@c.service"):
            with self.subTest(name=name), self.assertRaises(GuardError):
                ServiceGuard(name)

    def test_health_rejects_shell_and_nonargv(self):
        for health in ('"curl localhost"', '["curl","localhost"]', '["/bin/sh","-c","true"]', '[]', '["/usr/bin/true",1]'):
            with self.subTest(health=health), self.assertRaises(GuardError):
                guard_module.trusted_health(health)

    def test_alternate_system_root_cannot_mutate_real_systemd(self):
        with contextlib.redirect_stderr(io.StringIO()) as errors:
            code = guard_module.main(["apply", "fixture-php.service", "--system-root", "/tmp", "--apply"])
        self.assertEqual(code, 1)
        self.assertIn("read-only", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
