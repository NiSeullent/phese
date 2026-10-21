#!/usr/bin/env python3
"""Transactional, additive systemd hardening for explicitly named PHP services."""

import argparse
import contextlib
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile


SERVICE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,180}\.service\Z")
DROPIN_NAME = "90-asylumenforce.conf"
POLICY = Path(__file__).absolute().parent.parent / "policies/php-service.conf"
SHELL_NAMES = {"sh", "bash", "dash", "ash", "zsh", "ksh", "csh", "tcsh", "fish"}


class GuardError(Exception):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run_command(argv, timeout=45):
    # Never stream application health responses or systemctl diagnostics: these
    # may contain secrets. Errors expose only the operation name and exit code.
    try:
        return subprocess.run(argv, check=False, capture_output=True, text=True,
                              timeout=timeout, shell=False, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GuardError(f"{Path(argv[0]).name}: command unavailable or timed out") from exc


def trusted_health(value):
    """Accept only explicit argv and a root-controlled executable, never a shell."""
    try:
        argv = json.loads(value) if isinstance(value, str) else value
    except (ValueError, TypeError) as exc:
        raise GuardError("health check must be a JSON array of strings") from exc
    if (not isinstance(argv, list) or not argv or len(argv) > 80
            or any(not isinstance(x, str) or "\0" in x for x in argv)
            or not Path(argv[0]).is_absolute()):
        raise GuardError("health check must use an absolute executable and string arguments")
    try:
        executable = Path(argv[0]).resolve(strict=True)
        if executable.name in SHELL_NAMES or Path(argv[0]).name in SHELL_NAMES:
            raise GuardError("shell health checks are not allowed")
        assert_safe(executable, Path("/"))
        info = executable.stat()
        if not stat.S_ISREG(info.st_mode) or not os.access(executable, os.X_OK):
            raise GuardError("health executable is not an executable regular file")
    except OSError as exc:
        raise GuardError("health executable is unavailable") from exc
    return [str(executable), *argv[1:]]


def assert_safe(path, boundary, missing=False):
    """Reject symlinks and untrusted owners/modes from boundary through path."""
    path, boundary = Path(path), Path(boundary)
    if not path.is_absolute() or ".." in path.parts:
        raise GuardError("an absolute path without parent traversal is required")
    try:
        relative = path.relative_to(boundary)
    except ValueError as exc:
        raise GuardError("path escapes the configured system root") from exc
    # Alternate roots are inspection/test fixtures and cannot be applied through
    # the CLI. Their owner substitutes for root so unprivileged CI can exercise
    # every transaction against a fake command runner.
    expected_uid = 0 if boundary == Path("/") else boundary.lstat().st_uid
    current = boundary
    for part in (None, *relative.parts):
        if part is not None:
            current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            if missing:
                return
            raise GuardError("required file or directory is absent")
        if stat.S_ISLNK(info.st_mode):
            raise GuardError("symlink in managed path is not allowed")
        if info.st_uid != expected_uid or info.st_mode & 0o022:
            raise GuardError("managed paths must be root-owned and not group/world writable")
        if current != path and not stat.S_ISDIR(info.st_mode):
            raise GuardError("managed parent is not a directory")


class ServiceGuard:
    def __init__(self, service, root=Path("/"), policy=POLICY, runner=run_command):
        if not SERVICE_RE.fullmatch(service) or ".." in service or service.count("@") > 1:
            raise GuardError("invalid service name; use an exact .service unit name")
        self.service = service
        self.root = Path(root).absolute()
        self.policy = Path(policy).absolute()
        self.runner = runner
        self.dropin_dir = self.root / "etc/systemd/system" / f"{service}.d"
        self.dropin = self.dropin_dir / DROPIN_NAME
        self.state_dir = self.root / "var/lib/asylumenforce/service-guard" / service
        self.state_file = self.state_dir / "state.json"

    def command(self, argv, check=True):
        result = self.runner(argv)
        if check and result.returncode:
            raise GuardError(f"{Path(argv[0]).name} {argv[1]} failed (exit {result.returncode})")
        return result

    def systemctl(self, action, *extra, check=True):
        return self.command(["/usr/bin/systemctl", action, *extra, self.service], check)

    def read_policy(self):
        # Policy may live in an operator checkout; file/parents must be trusted
        # for an actual deployment. Tests deliberately inject a private fixture.
        boundary = self.root if self.policy.is_relative_to(self.root) else Path("/")
        assert_safe(self.policy, boundary)
        with self.policy.open("rb") as source:
            data = source.read(64 * 1024 + 1)
        if len(data) > 64 * 1024 or not data or b"[Service]" not in data or b"\0" in data:
            raise GuardError("invalid or oversized service policy")
        # This tool only installs sandbox settings, never executable directives.
        allowed = {"NoNewPrivileges", "ProtectSystem", "ProtectKernelTunables",
                   "ProtectKernelModules", "ProtectKernelLogs", "ProtectControlGroups",
                   "PrivateDevices", "RestrictSUIDSGID", "RestrictRealtime",
                   "LockPersonality", "RestrictNamespaces", "SystemCallArchitectures",
                   "SystemCallFilter", "SystemCallErrorNumber", "ProtectHome",
                   "ProtectClock", "ProtectHostname", "PrivateTmp"}
        try:
            for line in data.decode("utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith(("#", ";")) or line == "[Service]":
                    continue
                if "=" not in line or line.split("=", 1)[0].strip() not in allowed:
                    raise GuardError("policy contains a directive outside the sandbox allowlist")
        except UnicodeDecodeError as exc:
            raise GuardError("policy must be UTF-8") from exc
        return data

    def read_dropin(self):
        assert_safe(self.dropin, self.root, missing=True)
        try:
            fd = os.open(self.dropin, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return None
        with os.fdopen(fd, "rb") as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                raise GuardError("drop-in is not a regular file")
            data = source.read(64 * 1024 + 1)
        if len(data) > 64 * 1024:
            raise GuardError("existing drop-in is oversized")
        return data

    def read_state(self):
        assert_safe(self.state_file, self.root, missing=True)
        try:
            fd = os.open(self.state_file, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return None
        with os.fdopen(fd, "r") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > 64 * 1024:
                raise GuardError("backup state must be a private regular file")
            try:
                state = json.load(source)
            except ValueError as exc:
                raise GuardError("backup state is invalid") from exc
        if (not isinstance(state, dict) or state.get("schema") != 1
                or state.get("service") != self.service or state.get("original") is not None
                or not re.fullmatch(r"[a-f0-9]{64}", str(state.get("installed_sha256", "")))
                or state.get("phase") not in {"applying", "applied", "rolled_back", "failed"}):
            raise GuardError("backup state does not match the managed service")
        return state

    def mkdir_private(self, target):
        assert_safe(target, self.root, missing=True)
        missing = []
        current = target
        while not current.exists():
            missing.append(current)
            current = current.parent
        for directory in reversed(missing):
            directory.mkdir(mode=0o700)
        assert_safe(target, self.root)

    @contextlib.contextmanager
    def lock(self):
        self.mkdir_private(self.state_dir)
        lockfile = self.state_dir / "transaction.lock"
        assert_safe(lockfile, self.root, missing=True)
        fd = os.open(lockfile, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            os.close(fd)
            raise GuardError("another transaction is running for this service") from exc
        try:
            yield
        finally:
            os.close(fd)

    def save_state(self, state):
        assert_safe(self.state_file, self.root, missing=True)
        fd, filename = tempfile.mkstemp(prefix=".state-", dir=self.state_dir)
        try:
            with os.fdopen(fd, "w") as output:
                json.dump(state, output, sort_keys=True, indent=2)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(filename, self.state_file)
        finally:
            if os.path.exists(filename):
                os.unlink(filename)

    def verify(self):
        self.command(["/usr/bin/systemd-analyze", "verify", self.service])

    def reload(self):
        # daemon-reload affects the manager, not the running process namespaces.
        self.command(["/usr/bin/systemctl", "daemon-reload"])

    def active(self):
        return self.systemctl("is-active", "--quiet", check=False).returncode == 0

    def health(self, argv):
        result = self.runner(trusted_health(argv))
        if result.returncode:
            raise GuardError(f"application health check failed (exit {result.returncode})")

    def plan(self, rollback=False):
        policy, existing, state = self.read_policy(), self.read_dropin(), self.read_state()
        if rollback:
            action = "remove-managed-dropin" if state and state["phase"] != "rolled_back" else "nothing-to-rollback"
        elif existing is None:
            action = "create-dropin"
        elif existing == policy:
            action = "unchanged" if state and state["phase"] == "applied" else "unmanaged-identical"
        else:
            action = "refuse-existing-different-dropin"
        return {"service": self.service, "action": action, "dropin": str(self.dropin),
                "policy_sha256": digest(policy), "restart_required": action in {"create-dropin", "remove-managed-dropin"},
                "health_check_required": True, "changes_application_source": False,
                "backup_state": str(self.state_file)}

    def status(self):
        result = self.plan()
        state = self.read_state()
        result["transaction"] = state["phase"] if state else "unmanaged"
        if self.root == Path("/"):
            result["active"] = self.active()
            # Exposes no environment, command line, or journal content.
            result["configured_properties"] = self.systemctl(
                "show", "--property=NoNewPrivileges,ProtectSystem,PrivateDevices,RestrictNamespaces",
                "--no-pager").stdout.strip().splitlines()
        return result

    def apply(self, health_argv):
        health_argv = trusted_health(health_argv)
        with self.lock():
            policy, existing, previous = self.read_policy(), self.read_dropin(), self.read_state()
            if existing is not None and existing != policy:
                raise GuardError("existing drop-in differs; refusing to overwrite it")
            if not self.active():
                raise GuardError("service must already be active before apply")
            if existing == policy:
                self.verify()
                self.health(health_argv)
                return {"service": self.service, "result": "unchanged",
                        "owned": bool(previous and previous["phase"] == "applied")}
            if previous and previous["phase"] in {"applying", "applied"}:
                raise GuardError("recorded installation is missing; inspect state before another apply")
            state = {"schema": 1, "service": self.service, "original": None,
                     "installed_sha256": digest(policy), "phase": "applying",
                     "health_argv": health_argv,
                     "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
            self.save_state(state)
            created = False
            created_identity = None
            written = False
            try:
                assert_safe(self.dropin_dir, self.root, missing=True)
                self.dropin_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
                assert_safe(self.dropin_dir, self.root)
                fd = os.open(self.dropin, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
                created = True
                info = os.fstat(fd)
                created_identity = (info.st_dev, info.st_ino)
                with os.fdopen(fd, "wb") as output:
                    output.write(policy)
                    output.flush()
                    os.fsync(output.fileno())
                written = True
                self.reload()
                self.verify()
                self.systemctl("restart")
                if not self.active():
                    raise GuardError("service is inactive after restart")
                self.health(health_argv)
                state["phase"] = "applied"
                self.save_state(state)
                return {"service": self.service, "result": "applied", "active": True, "health": "passed"}
            except Exception as exc:
                recovery_errors = []
                if created:
                    try:
                        # A failed/partial write is still ours. Never remove a
                        # replacement inode, or someone else's completed edit.
                        assert_safe(self.dropin, self.root)
                        info = self.dropin.lstat()
                        if ((info.st_dev, info.st_ino) != created_identity
                                or (written and self.read_dropin() != policy)):
                            raise GuardError("drop-in changed during transaction; preserving it")
                        self.dropin.unlink()
                    except Exception:
                        recovery_errors.append("restore-dropin")
                    for operation, name in [(self.reload, "daemon-reload"), (self.verify, "verify"),
                                            (lambda: self.systemctl("restart"), "restart")]:
                        try:
                            operation()
                        except Exception:
                            recovery_errors.append(name)
                    try:
                        if not self.active():
                            raise GuardError("inactive")
                        self.health(health_argv)
                    except Exception:
                        recovery_errors.append("restored-health")
                state["phase"] = "failed" if recovery_errors else "rolled_back"
                state["recovery_errors"] = recovery_errors
                try:
                    self.save_state(state)
                except Exception:
                    recovery_errors.append("save-state")
                if recovery_errors:
                    raise GuardError("apply failed; recovery requires attention: " + ", ".join(recovery_errors)) from exc
                if not created:
                    raise GuardError("apply failed before drop-in creation; service configuration unchanged") from exc
                raise GuardError("apply failed; original drop-in state and service health restored") from exc

    def rollback(self, health_argv=None):
        with self.lock():
            state = self.read_state()
            if state is None:
                raise GuardError("no managed backup state; refusing to remove an unmanaged drop-in")
            existing = self.read_dropin()
            if state["phase"] == "rolled_back":
                if existing is not None:
                    raise GuardError("a drop-in exists after rollback; refusing to remove it")
                return {"service": self.service, "result": "already-rolled-back"}
            if existing is not None and digest(existing) != state["installed_sha256"]:
                raise GuardError("managed drop-in changed; refusing to remove it")
            health_argv = trusted_health(health_argv or state.get("health_argv"))
            if existing is not None:
                self.dropin.unlink()
            errors = []
            for operation, name in [(self.reload, "daemon-reload"), (self.verify, "verify"),
                                    (lambda: self.systemctl("restart"), "restart")]:
                try:
                    operation()
                except Exception:
                    errors.append(name)
            try:
                if not self.active():
                    raise GuardError("service inactive")
                self.health(health_argv)
            except Exception:
                errors.append("restored-health")
            state["phase"] = "failed" if errors else "rolled_back"
            state["recovery_errors"] = errors
            self.save_state(state)
            if errors:
                raise GuardError("drop-in removed; original service recovery requires attention: " + ", ".join(errors))
            return {"service": self.service, "result": "rolled-back", "active": True, "health": "passed"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "apply", "rollback", "status"))
    parser.add_argument("service", help="exact existing .service unit name")
    parser.add_argument("--apply", action="store_true", help="explicitly perform apply/rollback")
    parser.add_argument("--health-check", help='JSON argv, e.g. ["/usr/bin/curl","--fail","http://127.0.0.1/health"]')
    parser.add_argument("--system-root", type=Path, default=Path("/"), help="alternate root for read-only plan/status only")
    args = parser.parse_args(argv)
    try:
        root = args.system_root.absolute()
        if args.apply and args.action not in {"apply", "rollback"}:
            raise GuardError("--apply is only valid with apply or rollback")
        if args.apply and root != Path("/"):
            raise GuardError("alternate --system-root supports read-only plan/status only")
        guard = ServiceGuard(args.service, root=root)
        if args.action == "status":
            print(json.dumps(guard.status(), ensure_ascii=False, indent=2))
            return 0
        print(json.dumps(guard.plan(rollback=args.action == "rollback"), ensure_ascii=False, indent=2), flush=True)
        if args.action == "plan" or not args.apply:
            return 0
        if os.geteuid() != 0:
            raise GuardError("apply/rollback requires root")
        if args.action == "apply" and not args.health_check:
            raise GuardError("apply requires an explicit trusted --health-check")
        health = trusted_health(args.health_check) if args.health_check else None
        result = guard.apply(health) if args.action == "apply" else guard.rollback(health)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (GuardError, OSError) as exc:
        # GuardError texts never include captured command output or health argv.
        message = str(exc) if isinstance(exc, GuardError) else "filesystem operation failed"
        print(f"service-guard: {message}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
