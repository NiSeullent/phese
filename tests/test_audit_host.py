"""Read-only audit tests with fake package/PHP command runners."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).absolute().parents[1] / "tools/audit_host.py"
SPEC = importlib.util.spec_from_file_location("audit_host", SOURCE)
audit_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit_module)
HELP = "--security --available --list --with-cve"


class FakeRunner:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, argv, timeout):
        self.calls.append((argv, timeout))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        code, stdout, stderr = response
        return subprocess.CompletedProcess(argv, code, stdout, stderr)


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.dnf = self.root / "dnf"
        self.dnf.write_text("fixture only")
        self.dnf.chmod(0o755)
        self.php = self.root / "php"
        self.php.write_text("fixture only")
        self.php.chmod(0o755)
        self.os_release = self.root / "os-release"
        self.os_release.write_text('ID=almalinux\nVERSION_ID="10.2"\nPRETTY_NAME="PRIVATE-IGNORED"\n')

    def tearDown(self):
        self.tmp.cleanup()

    def dnf_audit(self, runner):
        return audit_module.dnf_audit(runner, (self.dnf,))

    def test_dnf_checks_help_and_collects_only_structured_identifiers(self):
        runner = FakeRunner([(0, HELP, ""), (0, "CVE-2026-123456 Important/Sec. php-8.5.12-1.x86_64\n", "")])
        result = self.dnf_audit(runner)
        self.assertEqual(result["state"], "checked")
        self.assertEqual(result["cves"], ["CVE-2026-123456"])
        self.assertFalse(result["all_cves_protected"])
        self.assertEqual(runner.calls[0][0], [str(self.dnf), "updateinfo", "--help"])
        self.assertEqual(runner.calls[1][0], [str(self.dnf), "-q", "updateinfo", "list", "--security", "--available", "--with-cve"])
        self.assertEqual(runner.calls[1][1], 45)

    def test_dnf_missing_and_unsupported_are_unknown(self):
        self.assertEqual(audit_module.dnf_audit(candidates=())["reason"], "dnf_missing")
        runner = FakeRunner([(0, "--list", "")])
        self.assertEqual(self.dnf_audit(runner)["reason"], "dnf_updateinfo_unsupported")
        self.assertEqual(len(runner.calls), 1)

    def test_dnf_failure_timeout_warning_and_unparsed_output_are_unknown(self):
        cases = [(1, "", "repository failure"), (0, "", "warning"), (0, "unrecognized data", "")]
        for response in cases:
            with self.subTest(response=response):
                result = self.dnf_audit(FakeRunner([(0, HELP, ""), response]))
                self.assertEqual(result["state"], "unknown")
                self.assertNotIn("repository failure", json.dumps(result))
        runner = FakeRunner([(0, HELP, ""), subprocess.TimeoutExpired("dnf", 45)])
        self.assertEqual(self.dnf_audit(runner)["reason"], "dnf_timeout")

    def test_repository_authentication_details_are_not_retained(self):
        secret = "https://user:SECRET@repository.invalid/private"
        result = self.dnf_audit(FakeRunner([(0, HELP, ""), (1, secret, secret)]))
        self.assertEqual(result["state"], "unknown")
        self.assertNotIn("SECRET", json.dumps(result))
        self.assertNotIn("repository.invalid", json.dumps(result))

    def test_empty_success_is_scoped_and_never_all_cve_protection(self):
        result = self.dnf_audit(FakeRunner([(0, HELP, ""), (0, "", "")]))
        self.assertEqual(result["state"], "checked")
        self.assertEqual(result["advisories"], [])
        self.assertFalse(result["all_cves_protected"])
        self.assertTrue(result["absence_of_findings_is_not_proof"])

    def test_php_uses_constant_probe_and_upstream_branch_gate(self):
        for version, number, gate in [("8.5.11", 80511, "review_required"), ("8.5.12", 80512, "passed"),
                                      ("8.3.36", 80336, "passed"), ("8.3.33", 80333, "review_required")]:
            runner = FakeRunner([(0, json.dumps([version, number, 1]), "")])
            result = audit_module.php_audit(str(self.php), runner)
            self.assertEqual(result["upstream_version_gate"], gate)
            self.assertEqual(runner.calls[0][0], [str(self.php), "-n", "-r", audit_module.VERSION_CODE])
            self.assertEqual(result["running_workers"], "not_inspected")

    def test_php_future_branch_and_prerelease_are_unknown(self):
        for version, number in [("8.6.0", 80600), ("8.5.12RC1", 80512)]:
            result = audit_module.php_audit(str(self.php), FakeRunner([(0, json.dumps([version, number, 0]), "")]))
            self.assertEqual(result["state"], "unknown")
            self.assertEqual(result["upstream_version_gate"], "unknown")

    def test_php_invalid_output_failure_and_timeout_are_unknown(self):
        for response in [(0, "not json", ""), (0, '["8.5.12",80511,1]', ""),
                         (0, '["8.5.12",80512,1]', "SECRET WARNING"), (1, "", "SECRET FAILURE")]:
            result = audit_module.php_audit(str(self.php), FakeRunner([response]))
            self.assertEqual(result["state"], "unknown")
            self.assertNotIn("SECRET", json.dumps(result))
        result = audit_module.php_audit(str(self.php), FakeRunner([subprocess.TimeoutExpired("php", 10)]))
        self.assertEqual(result["reason"], "php_probe_timeout")
        self.assertEqual(audit_module.php_audit("php")["reason"], "php_path_must_be_absolute")

    def test_os_identity_does_not_collect_other_fields(self):
        result = audit_module.os_identity(self.os_release)
        self.assertEqual(result, {"state": "checked", "id": "almalinux", "version_id": "10.2"})
        self.assertNotIn("PRIVATE", json.dumps(result))
        self.assertEqual(audit_module.os_identity(self.root / "absent")["state"], "unknown")

    def test_report_marks_unselected_php_as_unknown(self):
        report = audit_module.audit([], FakeRunner([(0, HELP, ""), (0, "", "")]), self.os_release,
                                    lambda: types.SimpleNamespace(release="fixture", machine="x86_64"), (self.dnf,))
        self.assertEqual(report["counts"]["unknown"], 1)
        self.assertEqual(report["php_selection"], "unknown_no_binaries_selected")
        self.assertFalse(report["all_cves_protected"])

    def test_console_summary_excludes_findings_and_report_is_private(self):
        report = {"counts": {"checked": 3, "unknown": 0, "php_binaries": 1,
                              "php_version_review_required": 1, "package_security_rows": 1, "package_cves": 1},
                  "secret_details": ["CVE-2026-123456", "PRIVATE-VERSION", "PRIVATE-RECOMMENDATION"]}
        destination = self.root / "report.json"
        with patch.object(audit_module, "audit", return_value=report), contextlib.redirect_stdout(io.StringIO()) as console:
            code = audit_module.main(["--output", str(destination)])
        self.assertEqual(code, 1)
        summary = console.getvalue()
        self.assertNotIn("CVE-", summary)
        self.assertNotIn("PRIVATE", summary)
        self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(destination.read_text()), report)

    def test_private_report_refuses_symlink(self):
        target = self.root / "unrelated.json"
        target.write_text("unchanged")
        destination = self.root / "report.json"
        destination.symlink_to(target)
        with patch.object(audit_module, "audit", return_value={}), contextlib.redirect_stderr(io.StringIO()):
            code = audit_module.main(["--output", str(destination)])
        self.assertEqual(code, 2)
        self.assertEqual(target.read_text(), "unchanged")


if __name__ == "__main__":
    unittest.main()
