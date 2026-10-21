"""Private, fixed-schema AsylumEnforce events. Never pass application data here."""

from datetime import datetime, timezone
import json
import os
import re
import syslog
import threading
import uuid


MESSAGE = "ㅋㅋㅋㅋㅋ어떻게병동이름이폐쇄얔ㅋㅋㅋㅋㅋㅋ"
TERMINOLOGY = {"isolation": "입원", "sandbox": "폐쇄적 환경",
               "deep_isolation": "안정실", "risk": "공격 위험성"}

# Static cause codes only. In particular, exception messages, request values,
# file paths, commands and function arguments must never become a reason.
REASONS = {
    "sandbox_started": frozenset({"sandbox_setup_started", "isolation_verified", "sandbox_ready", "seccomp_installed", "policy_enforced"}),
    "sandbox_exited": frozenset({"normal_exit", "nonzero_exit", "signal_terminated", "sandbox_timeout"}),
    "policy_denied": frozenset({"policy_check_failed", "sandbox_setup_failed", "untrusted_runtime",
                                "php_process_execution", "php_ffi_access", "mandatory_seccomp_unavailable",
                                "process_execution_attempt", "native_interface_attempt",
                                "seccomp_install_failed", "no_new_privileges_failed", "namespace_setup_failed",
                                "protected_status_unverified", "worker_privilege_drop_required"}),
    "version_refused": frozenset({"php_version_gate_failed", "unpatched_or_unsupported_php",
                                  "unsupported_php_branch", "unpatched_php_version", "prerelease_php_version"}),
}
_LOCK = threading.Lock()


def _identifier(value):
    if value is None:
        return str(uuid.uuid4())
    if not isinstance(value, str):
        return None
    if re.fullmatch(r"[0-9a-fA-F]{32}", value):
        return value.lower()
    try:
        canonical = str(uuid.UUID(value))
    except (ValueError, AttributeError):
        return None
    return canonical if canonical == value.lower() else None


def emit(event, reason, *, pid=None, exit_code=None, event_id=None):
    """Submit one event to AUTHPRIV; return its ID, or None on invalid/failing submission.

    An ID confirms that Python's syslog call returned, not durable disk storage.
    Callers must preserve enforcement when logging fails. No exception or user
    content is printed, and no application arguments or paths are accepted.
    """
    if (not isinstance(event, str) or event not in REASONS
            or not isinstance(reason, str) or reason not in REASONS[event]):
        return None
    pid = os.getpid() if pid is None else pid
    if type(pid) is not int or not 0 < pid < 2 ** 31:
        return None
    if exit_code is not None and (type(exit_code) is not int or not -255 <= exit_code <= 255):
        return None
    try:
        identifier = _identifier(event_id)
        if identifier is None:
            return None
        record = {"product": "AsylumEnforce", "component": "phese", "event": event,
                  "event_id": identifier,
                  "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                  "pid": pid, "reason": reason, "terminology": dict(TERMINOLOGY), "message": MESSAGE}
        if exit_code is not None:
            record["exit_code"] = exit_code
        payload = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
        priority = syslog.LOG_WARNING if event in {"policy_denied", "version_refused"} else syslog.LOG_NOTICE
        with _LOCK:
            syslog.openlog(ident="phese", logoption=syslog.LOG_PID, facility=syslog.LOG_AUTHPRIV)
            syslog.syslog(syslog.LOG_AUTHPRIV | priority, payload)
        return identifier
    except (OSError, RuntimeError, ValueError, OverflowError):
        return None
