"""Validate private event shape without sending real syslog records."""

import contextlib
import io
import json
import re
import syslog
import unittest
import uuid
from unittest.mock import patch

from phese import events


class EventTests(unittest.TestCase):
    def setUp(self):
        self.openlog = patch.object(events.syslog, "openlog").start()
        self.syslog = patch.object(events.syslog, "syslog").start()
        self.addCleanup(patch.stopall)

    def record(self):
        return json.loads(self.syslog.call_args.args[1])

    def test_exact_message_terms_schema_and_private_facility(self):
        identifier = events.emit("sandbox_started", "isolation_verified", pid=123)
        self.assertEqual(str(uuid.UUID(identifier)), identifier)
        record = self.record()
        self.assertEqual(set(record), {"product", "component", "event", "event_id", "timestamp", "pid", "reason", "terminology", "message"})
        self.assertEqual(record["product"], "AsylumEnforce")
        self.assertEqual(record["component"], "phese")
        self.assertEqual(record["message"], "ㅋㅋㅋㅋㅋ어떻게병동이름이폐쇄얔ㅋㅋㅋㅋㅋㅋ")
        self.assertEqual(record["terminology"], {"isolation": "입원", "sandbox": "폐쇄적 환경", "deep_isolation": "안정실", "risk": "공격 위험성"})
        self.assertRegex(record["timestamp"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
        self.openlog.assert_called_once_with(ident="phese", logoption=syslog.LOG_PID, facility=syslog.LOG_AUTHPRIV)
        self.assertEqual(self.syslog.call_args.args[0], syslog.LOG_AUTHPRIV | syslog.LOG_NOTICE)

    def test_native_32hex_and_optional_exit_code(self):
        identifier = events.emit("sandbox_exited", "nonzero_exit", event_id="AB" * 16, exit_code=7)
        self.assertEqual(identifier, "ab" * 16)
        self.assertEqual(self.record()["exit_code"], 7)

    def test_canonical_uuid_is_accepted(self):
        identifier = str(uuid.uuid4())
        self.assertEqual(events.emit("version_refused", "php_version_gate_failed", event_id=identifier), identifier)
        self.assertEqual(self.syslog.call_args.args[0], syslog.LOG_AUTHPRIV | syslog.LOG_WARNING)

    def test_untrusted_newlines_paths_and_secret_reasons_are_never_logged(self):
        for reason in ("php_process_execution\nSECRET", "/private/SECRET.php", "token_SECRET", {"secret": "SECRET"}):
            with self.subTest(reason=reason):
                self.assertIsNone(events.emit("policy_denied", reason))
        self.assertIsNone(events.emit("policy_denied\nSECRET", "policy_check_failed"))
        self.assertIsNone(events.emit({"secret": "SECRET"}, "policy_check_failed"))
        self.syslog.assert_not_called()

    def test_extra_secret_keys_are_not_accepted(self):
        with self.assertRaises(TypeError):
            events.emit("sandbox_started", "isolation_verified", secret="SECRET", command="private-command")
        self.syslog.assert_not_called()

    def test_malformed_identifiers_pids_exit_codes_are_rejected(self):
        cases = [{"event_id": "id\nSECRET"}, {"event_id": "{" + str(uuid.uuid4()) + "}"},
                 {"pid": "SECRET"}, {"pid": True}, {"pid": 0}, {"exit_code": "SECRET"}, {"exit_code": 256}]
        for extra in cases:
            with self.subTest(extra=extra):
                self.assertIsNone(events.emit("sandbox_started", "isolation_verified", **extra))
        self.syslog.assert_not_called()

    def test_one_record_never_contains_a_newline(self):
        events.emit("policy_denied", "php_process_execution")
        self.assertNotIn("\n", self.syslog.call_args.args[1])
        self.assertNotIn("\r", self.syslog.call_args.args[1])

    def test_submission_failure_returns_none_without_printing(self):
        self.syslog.side_effect = OSError("SECRET ERROR")
        with contextlib.redirect_stdout(io.StringIO()) as stdout, contextlib.redirect_stderr(io.StringIO()) as stderr:
            result = events.emit("policy_denied", "mandatory_seccomp_unavailable")
        self.assertIsNone(result)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "")

    def test_reason_must_match_its_event(self):
        self.assertIsNone(events.emit("sandbox_started", "php_process_execution"))
        self.syslog.assert_not_called()


if __name__ == "__main__":
    unittest.main()
