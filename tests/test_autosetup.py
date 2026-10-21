"""Source-only setup tests. No real model, PHP, installer, or service is run."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from phese import autosetup as setup



class FakeGuard:
    rows = {}
    calls = []
    fail = None

    def __init__(self, name, policy):
        self.name = name

    def plan(self):
        return dict(action=self.rows.get(self.name, "create-dropin"), policy_sha256="a" * 64,
                    restart_required=True)

    def active(self):
        return self.name != "inactive.service"

    def apply(self, health):
        self.calls.append((self.name, health))
        if self.name == self.fail:
            raise GuardError("SENSITIVE backend diagnostic")
        return {"service": self.name, "result": "applied"}


class GuardError(Exception):
    pass


def trusted_health(value):
    if not isinstance(value, list) or value != ["/usr/bin/true"]:
        raise GuardError("sensitive health argv")
    return value


BACKEND = (types.SimpleNamespace(ServiceGuard=FakeGuard, GuardError=GuardError,
                                  trusted_health=trusted_health), Path("unused-policy"))


def plan():
    return {"schema_version": 1, "platform_supported": True,
            "runtime": {"fixed_version": True, "native_cli_checked": False,
                        "path": "/SECRET/PRIVATE/PHP", "sha256": "f" * 64},
            "services": [{"service": "PRIVATE-CUSTOMER.service", "active": True, "action": "create-dropin",
                          "policy_sha256": "a" * 64, "restart_required": True}],
            "app_request_count": 2, "application_requests": {"private-path": "NEVER-SEND-THIS"}}


ADVICE = {"schema_version": 1, "profile": setup.PROFILE, "recommendations": ["measure-before-tuning"]}


class AdviceTests(unittest.TestCase):
    def test_public_summary_is_constructed_without_host_payload(self):
        result = setup.public_summary(plan())
        text = json.dumps(result)
        for secret in ["SECRET", "PRIVATE", "NEVER-SEND", "CUSTOMER", "sha256"]:
            self.assertNotIn(secret, text)
        self.assertEqual(result["service_count"], 1)

    def test_strict_schema_rejects_commands_new_policies_unknown_keys(self):
        bad = [dict(ADVICE, command="/bin/sh"), dict(ADVICE, profile="weaker"),
               dict(ADVICE, schema_version=True), dict(ADVICE, recommendations=["rm -rf /"]),
               dict(ADVICE, recommendations=["retain-policy", "retain-policy"]),
               dict(ADVICE, recommendations={}), [], {"schema_version": 1}]
        for value in bad:
            with self.subTest(value=value), self.assertRaises(setup.SetupError):
                setup.validate_advice(value)
        self.assertEqual(setup.validate_advice(ADVICE), ADVICE)

    def test_json_duplicate_nonfinite_oversized_and_deep_rejected(self):
        for value in ['{"x":1,"x":2}', '{"x":NaN}', '"' + 'x' * 32769 + '"', '[' * 2000 + ']' * 2000]:
            with self.subTest(value=value[:40]), self.assertRaises(setup.SetupError):
                setup.strict_json(value)

    def test_claude_adapter_uses_tools_empty_schema_and_only_public_stdin(self):
        calls = []
        def runner(argv, **kw):
            calls.append((argv, kw))
            self.assertEqual(Path(kw["cwd"]).stat().st_mode & 0o777, 0o700)
            self.assertEqual(list(Path(kw["cwd"]).iterdir()), [])
            return json.dumps({"structured_output": ADVICE, "is_error": False})
        result = setup.assistant_advice("claude", plan(), runner,
                                      {"available": True, "path": "/fake/claude"})
        argv, kw = calls[0]
        self.assertEqual(argv[argv.index("--tools") + 1], "")
        self.assertEqual(argv[argv.index("--mcp-config") + 1], '{"mcpServers":{}}')
        self.assertIn("--safe-mode", argv)
        self.assertIn("--no-session-persistence", argv)
        self.assertNotIn("--model", argv)
        self.assertNotIn("--effort", argv)
        for secret in ["PRIVATE", "SECRET", "NEVER-SEND"]:
            self.assertNotIn(secret, kw["payload"])
        self.assertFalse(result["tool_free_guarantee"])
        self.assertEqual(result["requested_tools"], "none")

    def test_codex_actual_argv_contract_schema_output_and_no_toolfree_claim(self):
        def runner(argv, **kw):
            self.assertIn("--ignore-user-config", argv)
            self.assertIn("--ignore-rules", argv)
            self.assertIn("--ephemeral", argv)
            self.assertEqual(argv[argv.index("--sandbox") + 1], "read-only")
            self.assertEqual(argv[-1], "-")
            self.assertNotIn("--model", argv)
            self.assertNotIn("danger-full-access", argv)
            target = Path(argv[argv.index("--output-last-message") + 1])
            self.assertEqual(set(p.name for p in target.parent.iterdir()), {"schema.json"})
            self.assertEqual(json.loads((target.parent / "schema.json").read_text()), setup.SCHEMA)
            target.write_text(json.dumps(ADVICE))
            return '{"type":"turn.completed"}\n'
        result = setup.assistant_advice("codex", plan(), runner,
                                      {"available": True, "path": "/fake/codex"})
        self.assertFalse(result["tool_free_guarantee"])
        self.assertFalse(result["model_override"])

    def test_assistant_error_no_retry_and_no_apply(self):
        calls = []
        def failed(argv, **kw):
            calls.append(argv)
            raise setup.SetupError("CLI failed")
        with self.assertRaises(setup.SetupError):
            setup.assistant_advice("claude", plan(), failed, {"available": True, "path": "/fake/claude"})
        self.assertEqual(len(calls), 1)
        self.assertEqual(FakeGuard.calls, [])

    def test_both_provider_outputs_fail_closed_on_untrusted_json(self):
        for output in [{"is_error": True, "result": "SENSITIVE"}, {"result": "not json"},
                       {"structured_output": dict(ADVICE, shell="touch /pwn")}]:
            with self.assertRaises(setup.SetupError):
                setup.assistant_advice("claude", plan(), lambda *a, **kw: json.dumps(output),
                                       {"available": True, "path": "/fake/claude"})


class TransactionsTests(unittest.TestCase):
    def setUp(self):
        FakeGuard.calls, FakeGuard.rows, FakeGuard.fail = [], {}, None

    @patch.object(setup.os, "geteuid", return_value=0)
    def test_only_existing_guard_applies_and_health_is_prevalidated(self, uid):
        result = setup.execute_plan(plan(), {"PRIVATE-CUSTOMER.service": ["/usr/bin/true"]}, BACKEND)
        self.assertEqual(result[0]["result"], "applied")
        self.assertEqual(FakeGuard.calls, [("PRIVATE-CUSTOMER.service", ["/usr/bin/true"])])

    @patch.object(setup.os, "geteuid", return_value=0)
    def test_missing_health_inactive_unknown_policy_platform_and_php_refuse(self, uid):
        variants = [plan() for _ in range(5)]
        variants[1]["services"][0]["active"] = False
        variants[2]["services"][0]["action"] = "refuse-existing-different-dropin"
        variants[3]["platform_supported"] = False
        variants[4]["runtime"]["fixed_version"] = False
        for i, value in enumerate(variants):
            with self.subTest(i=i), self.assertRaises(setup.SetupError):
                setup.execute_plan(value, {} if i == 0 else {"PRIVATE-CUSTOMER.service": ["/usr/bin/true"]}, BACKEND)
        self.assertEqual(FakeGuard.calls, [])

    @patch.object(setup.os, "geteuid", return_value=1000)
    def test_nonroot_apply_refused(self, uid):
        with self.assertRaises(setup.SetupError):
            setup.execute_plan(plan(), {"PRIVATE-CUSTOMER.service": ["/usr/bin/true"]}, BACKEND)

    @patch.object(setup.os, "geteuid", return_value=0)
    def test_multi_service_failure_stops_and_preserves_completed_result(self, uid):
        value = plan()
        for name in ["second.service", "third.service"]:
            value["services"].append(dict(value["services"][0], service=name))
        FakeGuard.fail = "second.service"
        with self.assertRaisesRegex(setup.SetupError, "transaction refused") as error:
            setup.execute_plan(value, {r["service"]: ["/usr/bin/true"] for r in value["services"]}, BACKEND)
        self.assertNotIn("SENSITIVE", str(error.exception))
        self.assertEqual([r[0] for r in FakeGuard.calls], ["PRIVATE-CUSTOMER.service", "second.service"])
        self.assertEqual(len(value["transactions"]), 1)


class RuntimeTests(unittest.TestCase):
    def test_forked_descendant_cleanup_when_output_decode_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            executable, marker = Path(directory) / "fake-invalid-output", Path(directory) / "child.pid"
            executable.write_text('#!/usr/bin/python3\nimport os,sys,time\nfrom pathlib import Path\n'
                                  'child=os.fork()\n'
                                  'if child==0:\n time.sleep(10)\n os._exit(0)\n'
                                  'Path(sys.argv[1]).write_text(str(child))\nos.write(1,b"\\xff")\n')
            executable.chmod(0o700)
            with self.assertRaises(UnicodeDecodeError):
                setup.bounded_run([str(executable), str(marker)], timeout=0.15)
            descendant = int(marker.read_text())
            alive = True
            for _ in range(40):
                try:
                    state = Path(f"/proc/{descendant}/stat").read_text().rpartition(")")[2].split()[0]
                    alive = state not in {"Z", "X"}
                except FileNotFoundError:
                    alive = False
                if not alive:
                    break
                time.sleep(0.01)
            self.assertFalse(alive, "same-group descendant survived decode failure")

    def test_forked_descendant_is_stopped_after_success_failure_and_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            executable, pid_file = Path(directory) / "fake-forking-cli", Path(directory) / "child.pid"
            executable.write_text('#!/usr/bin/python3\nimport os,sys,time\nfrom pathlib import Path\n'
                                  'child=os.fork()\n'
                                  'if child==0:\n time.sleep(10)\n os._exit(0)\n'
                                  'Path(sys.argv[1]).write_text(str(child))\n'
                                  'if sys.argv[2]=="timeout": time.sleep(10)\n'
                                  'print("{}",flush=True)\n'
                                  'sys.exit(9 if sys.argv[2]=="nonzero" else 0)\n')
            executable.chmod(0o700)
            for mode in ["success", "nonzero", "timeout"]:
                with self.subTest(mode=mode):
                    if pid_file.exists():
                        pid_file.unlink()
                    started = time.monotonic()
                    if mode == "success":
                        self.assertEqual(setup.bounded_run([str(executable), str(pid_file), mode], timeout=0.15).strip(), "{}")
                    else:
                        with self.assertRaises(setup.SetupError):
                            setup.bounded_run([str(executable), str(pid_file), mode], timeout=0.15)
                    self.assertLess(time.monotonic() - started, 2)
                    pid = int(pid_file.read_text())
                    # A grandchild is not waitpid-reapable by this caller. Its
                    # zombie, if not yet reaped by init, is no longer executing.
                    alive = True
                    for _ in range(40):
                        try:
                            state = Path(f"/proc/{pid}/stat").read_text().rpartition(")")[2].split()[0]
                            alive = state not in {"Z", "X"}
                        except FileNotFoundError:
                            alive = False
                        if not alive:
                            break
                        time.sleep(0.01)
                    self.assertFalse(alive, "fake same-group descendant survived cleanup")

    def test_service_discovery_retains_only_recognized_names_and_states(self):
        output = ('srv-php-fpm.service loaded active running CUSTOMER SECRET DESCRIPTION\n'
                  'srv-apache.service loaded active running ANOTHER SECRET\n'
                  'ssh.service loaded active running ignore\n'
                  'httpd.service loaded inactive dead ignore\n'
                  '../httpd.service loaded active running ignore\n')
        with patch.object(setup.shutil, "which", return_value="/usr/bin/systemctl"), \
                patch.object(setup, "trusted_file", return_value=Path("/usr/bin/systemctl")):
            rows = setup.discover_services(lambda *a, **kw: output)
        self.assertEqual(rows, ["srv-apache.service", "srv-php-fpm.service"])
        self.assertNotIn("SECRET", json.dumps(rows))

    def test_discovery_cannot_implicitly_apply_to_all_services(self):
        with contextlib.redirect_stderr(io.StringIO()), patch.object(setup, "discover_services") as discover:
            self.assertEqual(setup.main(["--php", "/fake/php", "--discover-services", "--apply"]), 2)
        discover.assert_not_called()

    def test_fixed_boundary_and_invalid_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            php = Path(directory) / "php"
            php.write_bytes(b"public ELF fixture")
            for version, expected in [(["8.5.11", 80511, 0], False), (["8.5.12", 80512, 1], True),
                                      (["8.2.35", 80235, 0], True)]:
                with patch.object(setup, "trusted_file", return_value=php):
                    value = setup.runtime_inventory("/fake/php", runner=lambda *a, **kw: json.dumps(version))
                self.assertEqual(value["fixed_version"], expected)
                self.assertFalse(value["running_workers_checked"])
            for bad in [["8.5.12RC1", 80512, 0], ["8.5.12", 80511, 0], ["8.5.12", True, 0], ["8.5.12", 80512, 3]]:
                with patch.object(setup, "trusted_file", return_value=php), self.assertRaises(setup.SetupError):
                    setup.runtime_inventory("/fake/php", runner=lambda *a, **kw: json.dumps(bad))

    def test_no_services_still_yields_diagnosis_not_successful_install(self):
        runtime = dict(fixed_version=True, native_cli_checked=False)
        with patch.object(setup, "runtime_inventory", return_value=runtime):
            value = setup.make_plan("/fake/php", [], backend=BACKEND)
        self.assertFalse(value["service_protection_applied"])
        self.assertFalse(value["optimizations"]["worker_or_cache_settings_changed"])
        self.assertEqual(value["services"], [])

    def test_duplicate_or_nonexact_services_rejected_before_probes(self):
        for services in [["php.service", "php.service"], ["*.service"], ["../php.service"], ["php"]]:
            with self.assertRaises(setup.SetupError):
                setup.make_plan("/fake/php", services, backend=BACKEND)

    def test_both_fake_cli_capabilities_support_expected_flags(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "fake-cli"
            binary.write_bytes(b"inert public CLI fixture")
            for name, version in [("codex", "codex-cli 0.163.0"), ("claude", "2.1.304 (Claude Code)")]:
                def runner(argv, **kwargs):
                    if "--version" in argv:
                        return version
                    if "--help" in argv:
                        return " ".join(setup.CLAUDE_FLAGS) if name == "claude" else (
                            "--sandbox --ephemeral --ignore-user-config --ignore-rules "
                            "--output-schema --skip-git-repo-check --json")
                    if argv[1:] == ["features", "list"]:
                        return "\n".join(feature + " stable true" for feature in setup.CODEX_DISABLED)
                    raise AssertionError("unexpected executable request")
                with patch.object(setup, "trusted_file", return_value=binary):
                    result = setup.cli_capability(name, runner=runner, which=lambda value: str(binary))
                self.assertTrue(result["available"])
                self.assertEqual(result["version"], version)
                self.assertFalse(result["model_call_tested"])

    def test_fake_executable_process_no_model_and_bounded_error(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "fake-ai"
            executable.write_text('#!/usr/bin/python3\nimport sys,json\np=sys.stdin.read()\nprint(json.dumps({"bytes":len(p)}))\n')
            executable.chmod(0o700)
            self.assertEqual(json.loads(setup.bounded_run([str(executable)], payload="public"))["bytes"], 6)
            executable.write_text('#!/usr/bin/python3\nimport sys\nprint("SECRET-KEY",file=sys.stderr)\nsys.exit(9)\n')
            with self.assertRaises(setup.SetupError) as error:
                setup.bounded_run([str(executable)])
            self.assertNotIn("SECRET", str(error.exception))

    def test_fake_executable_timeout_and_output_limit_fail_without_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "fake-ai"
            executable.write_text('#!/usr/bin/python3\nimport time\ntime.sleep(5)\n')
            executable.chmod(0o700)
            with self.assertRaisesRegex(setup.SetupError, "timed out"):
                setup.bounded_run([str(executable)], timeout=0.05)
            executable.write_text('#!/usr/bin/python3\nprint("x"*2000000)\n')
            with self.assertRaisesRegex(setup.SetupError, "output limit"):
                setup.bounded_run([str(executable)], timeout=2)

    def test_fake_claude_executable_end_to_end_structured_response(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "fake-claude"
            executable.write_text('#!/usr/bin/python3\nimport json,sys\np=sys.stdin.read()\n'
                                  'assert "PRIVATE" not in p and "NEVER-SEND" not in p\n'
                                  'assert "--tools" in sys.argv and sys.argv[sys.argv.index("--tools")+1]==""\n'
                                  'print(json.dumps({"structured_output":'+repr(ADVICE)+'}))\n')
            executable.chmod(0o700)
            result = setup.assistant_advice("claude", plan(), capability={"available": True, "path": str(executable)})
            self.assertEqual(result["advice"], ADVICE)

    def test_main_no_apply_default_and_import_response_does_not_call_ai(self):
        value = plan()
        with patch.object(setup, "make_plan", return_value=value), patch.object(setup, "execute_plan") as apply, \
                patch.object(setup, "assistant_advice") as ai, patch.object(sys, "stdin", io.StringIO(json.dumps(ADVICE))), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(setup.main(["--php", "/fake/php", "--assistant-response-stdin"]), 0)
        apply.assert_not_called()
        ai.assert_not_called()


class BackendIntegrationTests(unittest.TestCase):
    def test_setup_installer_creates_complete_immutable_bundle_and_preserves_previous(self):
        spec = importlib.util.spec_from_file_location("setup_install_bundle_fixture", ROOT / "tools/install_autosetup.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository, lib, binary = root / "repo", root / "lib", root / "bin/phese-setup"
            binary.parent.mkdir()
            for folder in ["phese", "tools", "policies"]:
                (repository / folder).mkdir(parents=True)
            (repository / "phese/__init__.py").write_text('__version__="fixture"\n')
            (repository / "phese/autosetup.py").write_text('def main(argv=None): return 0\n')
            for folder, name in [("tools", "service_guard.py"), ("tools", "install_cli.py"), ("policies", "php-service.conf")]:
                shutil.copyfile(ROOT / folder / name, repository / folder / name)
            fake_install = types.SimpleNamespace(main=lambda: None)
            fake_spec = types.SimpleNamespace(loader=types.SimpleNamespace(exec_module=lambda m: None))
            with patch.object(module, "ROOT", repository), patch.object(module, "LIB", lib), patch.object(module, "BIN", binary), \
                    patch.object(module, "safe"), patch.object(module.os, "geteuid", return_value=0), \
                    patch.object(module.importlib.util, "spec_from_file_location", return_value=fake_spec), \
                    patch.object(module.importlib.util, "module_from_spec", return_value=fake_install):
                first = module.install()
                original = binary.read_bytes()
                manifest = json.loads((first / "manifest.json").read_text())
                self.assertEqual(set(manifest), {"phese/__init__.py", "phese/autosetup.py", "phese/_service_guard.py", "phese/_service_policy.conf"})
                self.assertEqual((lib / "setup-releases").stat().st_mode & 0o777, 0o755)
                self.assertEqual((first / "phese/_service_guard.py").read_bytes(), (ROOT / "tools/service_guard.py").read_bytes())
                self.assertEqual((first / "phese/_service_policy.conf").read_bytes(), (ROOT / "policies/php-service.conf").read_bytes())
                self.assertEqual(module.install(), first)
                self.assertEqual(binary.read_bytes(), original)
                (repository / "phese/autosetup.py").write_text('def main(argv=None): return 1\n')
                second = module.install()
                self.assertNotEqual(first, second)
                self.assertTrue((first / "manifest.json").exists())
                self.assertEqual((first / "phese/autosetup.py").read_text(), 'def main(argv=None): return 0\n')
                (second / "phese/autosetup.py").write_text('tampered')
                with self.assertRaisesRegex(RuntimeError, "bytes differ"):
                    module.install()

    def test_existing_guard_transaction_replay_in_fake_filesystem(self):
        spec = importlib.util.spec_from_file_location("setup_guard_fixture", ROOT / "tools/service_guard.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "etc/systemd/system").mkdir(parents=True)
            (root / "var/lib").mkdir(parents=True)
            policy = root / "policy.conf"
            policy.write_bytes((ROOT / "policies/php-service.conf").read_bytes())
            calls = []
            def runner(argv):
                calls.append(list(argv))
                return subprocess.CompletedProcess(argv, 0, "", "")
            class FixtureGuard(module.ServiceGuard):
                def __init__(self, service, policy):
                    super().__init__(service, root=root, policy=policy, runner=runner)
            backend = (types.SimpleNamespace(ServiceGuard=FixtureGuard, GuardError=module.GuardError,
                                             trusted_health=module.trusted_health), policy)
            runtime = dict(fixed_version=True, native_cli_checked=False)
            with patch.object(setup, "runtime_inventory", return_value=runtime):
                value = setup.make_plan("/fake/php", ["fixture-php.service"], backend=backend)
            value["platform_supported"] = True
            with patch.object(setup.os, "geteuid", return_value=0):
                first = setup.execute_plan(value, {"fixture-php.service": ["/usr/bin/true"]}, backend)
            self.assertEqual(first[0]["result"], "applied")
            self.assertEqual((root / "etc/systemd/system/fixture-php.service.d/90-asylumenforce.conf").read_bytes(), policy.read_bytes())
            self.assertEqual((root / "var/lib/asylumenforce/service-guard/fixture-php.service/state.json").stat().st_mode & 0o777, 0o600)
            restarts = sum("restart" in row for row in calls)
            with patch.object(setup.os, "geteuid", return_value=0):
                second = setup.execute_plan(value, {"fixture-php.service": ["/usr/bin/true"]}, backend)
            self.assertEqual(second[0]["result"], "unchanged")
            self.assertEqual(sum("restart" in row for row in calls), restarts)
            FixtureGuard("fixture-php.service", policy=policy).rollback()
            self.assertFalse((root / "etc/systemd/system/fixture-php.service.d/90-asylumenforce.conf").exists())

    def test_installer_refuses_nonroot_before_import_or_changes(self):
        spec = importlib.util.spec_from_file_location("setup_install_fixture", ROOT / "tools/install_autosetup.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with patch.object(module.os, "geteuid", return_value=1000), self.assertRaisesRegex(RuntimeError, "requires root"):
            module.install()

    def test_capability_fails_closed_if_required_cli_flags_disappear(self):
        with patch.object(setup, "trusted_file", return_value=Path("/fake/claude")):
            result = setup.cli_capability("claude", runner=lambda *a, **kw: "2.1.304 (Claude Code)" if "--version" in a[0] else "--print", which=lambda name: "/fake/claude")
        self.assertEqual(result, {"available": False, "reason": "unsupported-flags"})

    def test_no_cli_installation_when_no_install_flag(self):
        spec = importlib.util.spec_from_file_location("setup_install_entry_fixture", ROOT / "tools/install_autosetup.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with patch.object(module, "install") as install, patch.object(setup, "main", return_value=0) as main:
            self.assertEqual(module.main(["--php", "/fake/php"]), 0)
        install.assert_not_called()
        main.assert_called_once_with(["--php", "/fake/php"])


class CLISelectionTests(unittest.TestCase):
    def test_symlink_loop_is_safe_optional_inventory_and_selected_apply_blocker(self):
        with tempfile.TemporaryDirectory() as directory:
            loop = Path(directory) / "private-loop-client"
            loop.symlink_to(loop.name)
            original_capability = setup.cli_capability
            probe = unittest.mock.Mock(side_effect=AssertionError("loop must fail before any client execution"))
            def capability(name, **kwargs):
                if name == "claude":
                    return {"available": True, "version": "2.1.304 (Claude Code)"}
                kwargs["runner"] = probe
                return original_capability(name, **kwargs)
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch.object(setup, "make_plan", return_value=plan()), \
                    patch.object(setup, "cli_capability", side_effect=capability), \
                    contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = setup.main(["--php", "/fake/php", "--assistant-inventory", "--codex-cli", str(loop)])
            self.assertEqual(result, 0)
            inventory = json.loads(stdout.getvalue())["assistant_inventory"]
            self.assertEqual(inventory["codex"], {"available": False, "reason": "metadata-unavailable"})
            self.assertTrue(inventory["claude"]["available"])
            self.assertEqual(stderr.getvalue(), "")
            self.assertNotIn(str(loop), json.dumps(inventory))
            stderr = io.StringIO()
            with patch.object(setup, "make_plan", return_value=plan()), \
                    patch.object(setup, "cli_capability", side_effect=capability), \
                    patch.object(setup, "execute_plan") as apply, contextlib.redirect_stderr(stderr):
                result = setup.main(["--php", "/fake/php", "--assistant", "codex", "--codex-cli", str(loop), "--apply"])
            self.assertEqual(result, 2)
            self.assertNotIn(str(loop), stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())
            probe.assert_not_called()
            apply.assert_not_called()

    @staticmethod
    def supported_runner(argv, **kwargs):
        if "--version" in argv:
            return "codex-cli 0.163.0" if "codex" in argv[0] else "2.1.304 (Claude Code)"
        if "--help" in argv:
            return ("--sandbox --ephemeral --ignore-user-config --ignore-rules "
                    "--output-schema --skip-git-repo-check --json") if "codex" in argv[0] else " ".join(setup.CLAUDE_FLAGS)
        if argv[1:] == ["features", "list"]:
            return "\n".join(feature + " stable true" for feature in setup.CODEX_DISABLED)
        raise AssertionError("unexpected fake CLI request")

    def test_explicit_absolute_cli_overrides_path_discovery(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "explicit-codex"
            binary.write_bytes(b"inert public binary fixture")
            with patch.object(setup, "trusted_file", return_value=binary) as trust:
                which = unittest.mock.Mock(side_effect=AssertionError("PATH fallback forbidden"))
                value = setup.cli_capability("codex", runner=self.supported_runner, which=which, executable=str(binary))
            self.assertTrue(value["available"])
            self.assertEqual(value["path"], str(binary))
            trust.assert_called_once_with(str(binary), executable=True)
            which.assert_not_called()

    def test_relative_explicit_cli_is_refused_before_probe_or_path_fallback(self):
        runner, which = unittest.mock.Mock(), unittest.mock.Mock()
        with patch.object(setup, "trusted_file") as trust:
            value = setup.cli_capability("codex", runner=runner, which=which, executable="relative-private-codex")
        self.assertEqual(value, {"available": False, "reason": "invalid-cli-path"})
        self.assertNotIn("relative-private", json.dumps(value))
        trust.assert_not_called()
        runner.assert_not_called()
        which.assert_not_called()

    def test_inventory_untrusted_client_keeps_other_client_and_succeeds(self):
        with tempfile.TemporaryDirectory() as directory:
            claude = Path(directory) / "claude"
            claude.write_bytes(b"inert Claude metadata fixture")
            original_capability = setup.cli_capability
            def trust(value, **kwargs):
                if value == "/untrusted/codex":
                    raise setup.SetupError("SECRET original path and raw policy error")
                return claude
            def capability(name, **kwargs):
                return original_capability(name, runner=self.supported_runner, **kwargs)
            stdout = io.StringIO()
            with patch.object(setup, "make_plan", return_value=plan()), patch.object(setup, "trusted_file", side_effect=trust), \
                    patch.object(setup, "cli_capability", side_effect=capability), contextlib.redirect_stdout(stdout):
                result = setup.main(["--php", "/fake/php", "--assistant-inventory", "--codex-cli", "/untrusted/codex", "--claude-cli", str(claude)])
            self.assertEqual(result, 0)
            inventory = json.loads(stdout.getvalue())["assistant_inventory"]
            self.assertEqual(inventory["codex"], {"available": False, "reason": "untrusted-cli-path"})
            self.assertTrue(inventory["claude"]["available"])
            self.assertNotIn("SECRET", json.dumps(inventory))
            self.assertNotIn("/untrusted", json.dumps(inventory))

    def test_selected_unavailable_cli_blocks_request_and_apply(self):
        for reason in ["not-installed", "untrusted-cli-path", "unsupported-flags", "metadata-unavailable"]:
            with self.subTest(reason=reason), patch.object(setup, "make_plan", return_value=plan()), \
                    patch.object(setup, "cli_capability", return_value={"available": False, "reason": reason}) as capability, \
                    patch.object(setup, "execute_plan") as apply, contextlib.redirect_stderr(io.StringIO()):
                result = setup.main(["--php", "/fake/php", "--assistant", "codex", "--codex-cli", "/explicit/codex", "--apply"])
            self.assertEqual(result, 2)
            self.assertEqual(capability.call_args.kwargs["executable"], "/explicit/codex")
            apply.assert_not_called()

    def test_explicit_selection_is_forwarded_to_assistant_request(self):
        calls = []
        def runner(argv, **kwargs):
            calls.append(argv)
            return json.dumps({"structured_output": ADVICE})
        with patch.object(setup, "cli_capability", return_value={"available": True, "path": "/trusted/selected-claude"}) as capability:
            result = setup.assistant_advice("claude", plan(), runner=runner, executable="/explicit/claude")
        capability.assert_called_once_with("claude", runner=runner, executable="/explicit/claude")
        self.assertEqual(calls[0][0], "/trusted/selected-claude")
        self.assertEqual(result["advice"], ADVICE)

    def test_main_forwards_per_client_inventory_and_selected_override(self):
        with patch.object(setup, "make_plan", return_value=plan()), \
                patch.object(setup, "cli_capability", return_value={"available": False, "reason": "not-installed"}) as inventory, \
                patch.object(setup, "assistant_advice", return_value={"advice": ADVICE}) as advice, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(setup.main(["--php", "/fake/php", "--assistant-inventory", "--assistant", "codex",
                                         "--codex-cli", "/selected/codex", "--claude-cli", "/selected/claude"]), 0)
        self.assertEqual(inventory.call_args_list, [unittest.mock.call("codex", executable="/selected/codex"),
                                                   unittest.mock.call("claude", executable="/selected/claude")])
        self.assertEqual(advice.call_args.kwargs["executable"], "/selected/codex")

    def test_metadata_failures_are_static_enum_records_without_raw_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "codex"
            binary.write_bytes(b"public binary fixture")
            cases = [(FileNotFoundError("SECRET missing path"), None, "not-installed"),
                     (setup.SetupError("SECRET owner"), None, "untrusted-cli-path"),
                     (OSError("SECRET metadata"), None, "metadata-unavailable"),
                     (None, lambda *a, **kw: "SECRET unsupported version", "unsupported-version"),
                     (None, lambda argv, **kw: "codex-cli 0.163.0" if "--version" in argv else "SECRET help", "unsupported-flags"),
                     (None, lambda argv, **kw: "SECRET features" if argv[1:] == ["features", "list"] else self.supported_runner(argv), "unsupported-features")]
            for trust_error, runner, expected in cases:
                with self.subTest(reason=expected), patch.object(setup, "trusted_file", side_effect=trust_error, return_value=binary):
                    value = setup.cli_capability("codex", runner=runner or self.supported_runner, executable=str(binary))
                self.assertEqual(value, {"available": False, "reason": expected})
                self.assertNotIn("SECRET", json.dumps(value))
            with patch.object(setup, "trusted_file", return_value=binary):
                value = setup.cli_capability("codex", runner=unittest.mock.Mock(side_effect=setup.SetupError("SECRET quota")), executable=str(binary))
            self.assertEqual(value, {"available": False, "reason": "probe-failed"})
        self.assertEqual(setup.cli_capability("claude", which=lambda name: None), {"available": False, "reason": "not-installed"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
