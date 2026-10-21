#!/usr/bin/env python3
"""Plan or transactionally load phese only in an explicitly named web service."""

import argparse
import contextlib
import datetime
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

# Import this checkout's helper, never an unrelated top-level tools package.
_SPEC = importlib.util.spec_from_file_location(
    "_phese_web_service_guard", Path(__file__).absolute().with_name("service_guard.py")
)
_HELPER = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_HELPER)
GuardError = _HELPER.GuardError
ServiceGuard = _HELPER.ServiceGuard
assert_safe = _HELPER.assert_safe
digest = _HELPER.digest

MARKER = "AsylumEnforce managed web guard v1"
DROPIN = "91-asylumenforce-phese.conf"
HASH = re.compile(r"[a-f0-9]{64}\Z")
CLI_PROBE = "echo json_encode(extension_loaded('phese'));"


def unit_quote(value):
    """Quote one literal systemd argument; paths never contain control characters."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$") + '"'


class WebGuard(ServiceGuard):
    """Reuse service trust checks and its shared lock, with separate ownership state."""

    def __init__(self, service, php=None, extension=None, scan_dir=None, page_ini=None,
                 scope=None, root=Path("/"), runner=_HELPER.run_command):
        super().__init__(service, root=root, runner=runner)
        self.shared_guard = ServiceGuard(service, root=self.root, runner=runner)
        self.dropin = self.dropin_dir / DROPIN
        self.extra_dir = self.root / "usr/local/etc/asylumenforce" / (service + ".d")
        self.ini = self.extra_dir / "99-phese.ini"
        self.state_dir = self.root / "var/lib/asylumenforce/web-guard" / service
        self.state_file = self.state_dir / "state.json"
        self.native_dir = self.root / "usr/local/lib/asylumenforce/native"
        self.doctor = self.root / "usr/local/bin/phese"
        self.php, self.extension = php, extension
        self.scan_dir, self.page_ini, self.scope = scan_dir, page_ini, scope
        self.targets = {"ini": self.ini, "dropin": self.dropin}

    def command(self, argv, check=True):
        result = self.runner(argv)
        if check and result.returncode:
            raise GuardError(f"{Path(argv[0]).name} failed (exit {result.returncode})")
        return result

    def path(self, value, directory=False, executable=False):
        if not isinstance(value, (str, os.PathLike)):
            raise GuardError("php, extension, scan-dir, page-ini and scope are required for installation")
        path = Path(value)
        if (not path.is_absolute() or ".." in path.parts
                or any(ord(c) < 32 or c in '\\"$%:' for c in str(path))):
            raise GuardError("paths must be absolute and contain no INI/unit interpolation characters")
        assert_safe(path, self.root)
        info = path.lstat()
        expected = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
        if not expected or (executable and not os.access(path, os.X_OK)):
            raise GuardError("input has the wrong file type or is not executable")
        return path

    def argv(self, value):
        if self.root == Path("/"):
            return _HELPER.trusted_health(value)
        # Alternate roots exist only for read-only CLI plans and injected-runner
        # tests. Validate every component inside that real fixture boundary.
        try:
            argv = json.loads(value) if isinstance(value, str) else value
        except (TypeError, ValueError) as exc:
            raise GuardError("check must be a JSON argv array") from exc
        if (not isinstance(argv, list) or not argv or len(argv) > 80
                or any(not isinstance(arg, str) or "\0" in arg for arg in argv)
                or Path(argv[0]).name in _HELPER.SHELL_NAMES):
            raise GuardError("check must use an explicit executable and string arguments")
        executable = self.path(argv[0], executable=True)
        return [str(executable), *argv[1:]]

    def read_file(self, path, limit=65536, missing=False, private=False):
        assert_safe(path, self.root, missing=missing)
        try:
            if not stat.S_ISREG(path.lstat().st_mode):
                raise GuardError("managed input is not a regular file")
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        except FileNotFoundError:
            if missing:
                return None
            raise GuardError("required input is absent")
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_size > limit
                    or (private and info.st_mode & 0o077)):
                raise GuardError("input is not a bounded, appropriately protected regular file")
            data = source.read(limit + 1)
        if len(data) > limit:
            raise GuardError("input exceeds its size limit")
        return data, info

    @staticmethod
    def record(data, info):
        return {"sha256": digest(data), "device": info.st_dev,
                "inode": info.st_ino, "mode": stat.S_IMODE(info.st_mode)}

    def own_file(self, key, record, missing=False):
        value = self.read_file(self.targets[key], missing=missing)
        if value is None:
            return None
        data, info = value
        if self.record(data, info) != record:
            raise GuardError("managed file changed identity, mode or content; preserving it")
        return data

    def read_state(self):
        value = self.read_file(self.state_file, missing=True, private=True)
        if value is None:
            return None
        try:
            state = json.loads(value[0])
        except (ValueError, UnicodeError) as exc:
            raise GuardError("web installation state is invalid") from exc
        if (not isinstance(state, dict) or state.get("schema") != 1
                or state.get("service") != self.service or state.get("original") is not None
                or state.get("phase") not in {"applying", "applied", "rolled_back", "failed"}
                or not isinstance(state.get("files"), dict)
                or set(state["files"]) - set(self.targets)):
            raise GuardError("web installation state does not match this service")
        for item in state["files"].values():
            if (not isinstance(item, dict) or set(item) != {"sha256", "device", "inode", "mode"}
                    or not HASH.fullmatch(str(item.get("sha256", "")))
                    or any(type(item.get(key)) is not int or item[key] < 0
                           for key in ("device", "inode", "mode"))
                    or item["mode"] != 0o644):
                raise GuardError("web installation file ownership record is invalid")
        if state["phase"] == "applied" and set(state["files"]) != set(self.targets):
            raise GuardError("applied web installation state is incomplete")
        return state

    @staticmethod
    def sync_directory(path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def save_state(self, state):
        super().save_state(state)
        self.sync_directory(self.state_dir)

    def public_directory(self, path):
        assert_safe(path, self.root, missing=True)
        missing, current = [], path
        while not current.exists():
            missing.append(current)
            current = current.parent
        for directory in reversed(missing):
            directory.mkdir(mode=0o755)
            directory.chmod(0o755)  # Explicit despite a restrictive operator umask.
        assert_safe(path, self.root)

    @contextlib.contextmanager
    def lock(self):
        # The first lock is exactly the PHP rollout/ServiceGuard lock already in
        # use by the other deployment task; web state has its own second lock.
        with self.shared_guard.lock():
            with super().lock():
                yield

    def page_settings(self):
        source = self.path(self.page_ini)
        data, info = self.read_file(source, limit=16384)
        try:
            settings = {}
            for raw in data.decode("utf-8").splitlines():
                line = raw.strip()
                if not line or line.startswith((";", "#")):
                    continue
                match = re.fullmatch(r'(phese\.block_(?:page|csp))\s*=\s*"([^"\\\r\n\0$]*)"\s*', line)
                if not match or match[1] in settings:
                    raise GuardError("page INI must contain only unique generated page/CSP directives")
                settings[match[1]] = match[2]
        except UnicodeDecodeError as exc:
            raise GuardError("page INI must be UTF-8") from exc
        if set(settings) != {"phese.block_page", "phese.block_csp"}:
            raise GuardError("page INI must provide both page and CSP")
        csp = settings["phese.block_csp"]
        if not csp or len(csp.encode("utf-8")) > 4096:
            raise GuardError("page CSP is empty or oversized")
        page = self.path(settings["phese.block_page"])
        html, page_info = self.read_file(page, limit=262144)
        try:
            public_html = html.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise GuardError("public block page must be UTF-8 HTML") from exc
        if (not html or b"\0" in html or not public_html.lstrip().lower().startswith("<!doctype html")
                or "{{EVENT_ID}}" not in public_html or "{{TIMESTAMP}}" not in public_html):
            raise GuardError("public block page must be bounded HTML with event/time placeholders")
        return settings, {str(source): self.record(data, info), str(page): self.record(html, page_info)}

    def prepare(self):
        if self.scope != "worker":
            raise GuardError("web installation requires scope=worker for both PHP-FPM and Apache")
        php = self.path(self.php, executable=True)
        extension = self.path(self.extension)
        scan_dir = self.path(self.scan_dir, directory=True)
        self.path(self.doctor, executable=True)
        module, module_info = self.read_file(extension, limit=16 * 1024 * 1024)
        if not module:
            raise GuardError("native module is empty")
        module_sha = digest(module)
        native = self.native_dir / (module_sha + ".so")
        settings, pins = self.page_settings()
        pins[str(extension)] = self.record(module, module_info)
        php_info = php.lstat()
        pins[str(php)] = {"device": php_info.st_dev, "inode": php_info.st_ino,
                          "mode": stat.S_IMODE(php_info.st_mode)}
        assert_safe(self.extra_dir, self.root, missing=True)
        if self.extra_dir.exists():
            if any(entry.name.lower().endswith(".ini") and entry != self.ini
                   for entry in self.extra_dir.iterdir()):
                raise GuardError("service-specific extra scan directory contains an unmanaged INI")
        scan_value = str(scan_dir) + ":" + str(self.extra_dir)
        ini = (f"; {MARKER}\n" + f'extension = "{native}"\n' +
               f'phese.scope = "{self.scope}"\n' +
               f'phese.block_page = "{settings["phese.block_page"]}"\n' +
               f'phese.block_csp = "{settings["phese.block_csp"]}"\n').encode("utf-8")
        doctor = [str(self.doctor), "doctor", "--php", str(php), "--extension", str(native)]
        dropin = (f"# {MARKER}\n[Service]\n" +
                  "Environment=" + unit_quote("PHP_INI_SCAN_DIR=" + scan_value) + "\n" +
                  "ExecStartPre=" + " ".join(map(unit_quote, doctor)) + "\n").encode("utf-8")
        return {"php": str(php), "native": str(native), "module": module,
                "module_sha256": module_sha, "scan_value": scan_value,
                "pins": pins, "doctor": doctor, "data": {"ini": ini, "dropin": dropin}}

    def verify_pins(self, prepared):
        for name, expected in prepared["pins"].items():
            path = self.path(name)
            info = path.lstat()
            actual = {"device": info.st_dev, "inode": info.st_ino,
                      "mode": stat.S_IMODE(info.st_mode)}
            if "sha256" in expected:
                actual = self.record(*self.read_file(path, limit=16 * 1024 * 1024))
            if actual != expected:
                raise GuardError("a reviewed input changed during the transaction")

    def validate_existing(self, prepared, state):
        existing = {key: self.read_file(path, missing=True) for key, path in self.targets.items()}
        if state and state["phase"] == "applied":
            for key in self.targets:
                self.own_file(key, state["files"][key])
            if (any(existing[key][0] != prepared["data"][key] for key in self.targets)
                    or state.get("pins") != prepared["pins"]):
                raise GuardError("managed inputs differ; roll back before changing the installation")
            return True
        if any(value is not None for value in existing.values()):
            raise GuardError("an unmanaged INI/drop-in already exists; refusing to overwrite or adopt it")
        if state and state["phase"] in {"applying", "failed"}:
            raise GuardError("incomplete installation requires rollback or operator recovery")
        return False

    def plan(self, rollback=False):
        state = self.read_state()
        if rollback:
            if state:
                for key, record in state["files"].items():
                    self.own_file(key, record, missing=True)
            return {"service": self.service, "action": "remove-managed-web-files" if state and state["phase"] != "rolled_back" else "nothing-to-rollback",
                    "dropin": str(self.dropin), "ini": str(self.ini), "backup_state": str(self.state_file),
                    "shared_lock": str(self.shared_guard.state_dir / "transaction.lock")}
        prepared = self.prepare()
        unchanged = self.validate_existing(prepared, state)
        return {"service": self.service, "action": "unchanged" if unchanged else "create-web-files",
                "scope": self.scope, "dropin": str(self.dropin), "ini": str(self.ini),
                "native_module": prepared["native"], "native_sha256": prepared["module_sha256"],
                "restart_required": not unchanged, "health_check_required": True,
                "default_php_ini_changed": False, "application_source_changed": False,
                "backup_state": str(self.state_file),
                "shared_lock": str(self.shared_guard.state_dir / "transaction.lock")}

    def publish(self, path, data, before_publish=None, after_publish=None, mode=0o644):
        self.public_directory(path.parent)
        assert_safe(path, self.root, missing=True)
        fd, name = tempfile.mkstemp(prefix=".phese-web-", dir=path.parent)
        temporary = Path(name)
        try:
            with os.fdopen(fd, "wb") as output:
                os.fchmod(output.fileno(), mode)
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
                record = self.record(data, os.fstat(output.fileno()))
            if before_publish:
                before_publish(record)
            os.link(temporary, path, follow_symlinks=False)  # Atomic, never replaces another inode.
            if after_publish:
                after_publish(record)
            self.sync_directory(path.parent)
            return record
        finally:
            temporary.unlink(missing_ok=True)

    def cache_module(self, prepared):
        destination = Path(prepared["native"])
        existing = self.read_file(destination, missing=True, limit=16 * 1024 * 1024)
        if existing is not None:
            if digest(existing[0]) != prepared["module_sha256"]:
                raise GuardError("immutable module cache content does not match its name")
            return
        try:
            self.publish(destination, prepared["module"], mode=0o444)
        except FileExistsError:
            value = self.read_file(destination, limit=16 * 1024 * 1024)
            if digest(value[0]) != prepared["module_sha256"]:
                raise GuardError("immutable module cache was replaced")

    def cli_unloaded(self, php):
        php = self.path(php, executable=True)
        result = self.command([str(php), "-r", CLI_PROBE])
        if result.stdout.strip() != "false":
            raise GuardError("normal PHP CLI already loads phese or could not be verified")

    def check_doctor(self, prepared):
        result = self.command(prepared["doctor"])
        try:
            report = json.loads(result.stdout)
            status = report["phese"]
        except (ValueError, TypeError, KeyError) as exc:
            raise GuardError("native doctor did not return a protection attestation") from exc
        if (report.get("cve_2026_109618_109619_version_gate") is not True
                or not isinstance(status, dict) or status.get("scope") != "startup"
                or any(status.get(key) is not True for key in
                       ("seccomp_active", "no_new_privileges", "version_gate"))):
            raise GuardError("native module/runtime protection attestation failed")

    def health(self, argv):
        self.command(self.argv(argv))

    def recover_service(self, health, php):
        errors = []
        for operation, name in [(self.reload, "daemon-reload"), (self.verify, "verify"),
                                (lambda: self.systemctl("restart"), "restart")]:
            try:
                operation()
            except (GuardError, OSError):
                errors.append(name)
        try:
            if not self.active():
                raise GuardError("service inactive")
            self.health(health)
            self.cli_unloaded(php)
        except (GuardError, OSError):
            errors.append("restored-health-or-cli")
        return errors

    def apply(self, health_argv, config_check=None):
        health = self.argv(health_argv)
        config_check = self.argv(config_check) if config_check else None
        with self.lock():
            prepared, previous = self.prepare(), self.read_state()
            unchanged = self.validate_existing(prepared, previous)
            if not self.active():
                raise GuardError("service must already be active before apply")
            self.health(health)
            self.cli_unloaded(prepared["php"])
            self.cache_module(prepared)
            self.check_doctor(prepared)
            self.verify_pins(prepared)
            if unchanged:
                self.verify()
                return {"service": self.service, "result": "unchanged", "owned": True}
            if config_check:
                self.command(config_check)  # Validate existing configuration before mutation.
            state = {"schema": 1, "service": self.service, "original": None,
                     "phase": "applying", "files": {}, "php": prepared["php"],
                     "scope": self.scope, "pins": prepared["pins"], "health_argv": health,
                     "module_sha256": prepared["module_sha256"],
                     "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
            self.save_state(state)
            created = {}
            try:
                for key in ("ini", "dropin"):
                    def before(record, key=key):
                        state["files"][key] = record
                        self.save_state(state)  # Durable inode ownership before atomic publication.
                    self.publish(self.targets[key], prepared["data"][key], before,
                                 lambda record, key=key: created.update({key: record}))
                self.verify_pins(prepared)
                if config_check:
                    self.command(["/usr/bin/env", "PHP_INI_SCAN_DIR=" + prepared["scan_value"], *config_check])
                self.reload()
                self.verify()
                self.systemctl("restart")
                if not self.active():
                    raise GuardError("service is inactive after restart")
                self.health(health)
                self.cli_unloaded(prepared["php"])
                state["phase"] = "applied"
                self.save_state(state)
                return {"service": self.service, "result": "applied", "active": True,
                        "health": "passed", "normal_cli_loads_phese": False,
                        "handler_enforcement": "requires-real-request-attestation"}
            except BaseException as exc:
                # A user interruption after publication must restore the prior service too.
                errors = []
                for key, record in created.items():
                    try:
                        self.own_file(key, record)
                        self.targets[key].unlink()
                        self.sync_directory(self.targets[key].parent)
                    except (GuardError, OSError):
                        errors.append("restore-" + key)
                for key, path in self.targets.items():
                    if key not in created and path.exists():
                        errors.append("unmanaged-" + key + "-appeared")
                if created and not errors:
                    errors.extend(self.recover_service(health, prepared["php"]))
                state["phase"] = "failed" if errors else "rolled_back"
                state["recovery_errors"] = errors
                try:
                    self.save_state(state)
                except (GuardError, OSError):
                    errors.append("save-state")
                if errors:
                    raise GuardError("web apply failed; recovery requires attention: " + ", ".join(errors)) from exc
                raise GuardError("web apply failed; original files and service health restored") from exc

    def rollback(self, health_argv=None):
        with self.lock():
            state = self.read_state()
            if not state:
                raise GuardError("no managed web state; refusing to remove unmanaged files")
            for key, path in self.targets.items():
                if key in state["files"]:
                    self.own_file(key, state["files"][key], missing=True)
                elif self.read_file(path, missing=True) is not None:
                    raise GuardError("an unmanaged web file exists; preserving it")
            if state["phase"] == "rolled_back":
                if any(path.exists() for path in self.targets.values()):
                    raise GuardError("a web file exists after rollback; preserving it")
                return {"service": self.service, "result": "already-rolled-back"}
            health = self.argv(health_argv or state.get("health_argv"))
            php = self.path(state.get("php"), executable=True)
            for key in state["files"]:
                self.targets[key].unlink(missing_ok=True)
                self.sync_directory(self.targets[key].parent)
            errors = self.recover_service(health, php)
            state["phase"] = "failed" if errors else "rolled_back"
            state["recovery_errors"] = errors
            self.save_state(state)
            if errors:
                raise GuardError("web files removed; service recovery requires attention: " + ", ".join(errors))
            return {"service": self.service, "result": "rolled-back", "health": "passed"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "apply", "rollback"))
    parser.add_argument("service", help="exact existing .service unit")
    parser.add_argument("--php")
    parser.add_argument("--extension")
    parser.add_argument("--scan-dir")
    parser.add_argument("--page-ini")
    parser.add_argument("--scope", choices=("worker",), default="worker")
    parser.add_argument("--health-check", help="trusted executable argv encoded as JSON")
    parser.add_argument("--config-check", help="optional trusted syntax-check argv encoded as JSON")
    parser.add_argument("--apply", action="store_true", help="perform the explicitly requested transaction")
    parser.add_argument("--system-root", type=Path, default=Path("/"), help="alternate roots are read-only")
    args = parser.parse_args(argv)
    try:
        root = args.system_root.absolute()
        if args.apply and args.action == "plan":
            raise GuardError("--apply is only valid with apply or rollback")
        if args.apply and root != Path("/"):
            raise GuardError("alternate system roots are read-only through the CLI")
        guard = WebGuard(args.service, args.php, args.extension, args.scan_dir,
                         args.page_ini, args.scope, root=root)
        print(json.dumps(guard.plan(rollback=args.action == "rollback"), indent=2), flush=True)
        if not args.apply or args.action == "plan":
            return 0
        if os.geteuid() != 0:
            raise GuardError("web apply/rollback requires root")
        if args.action == "apply" and not args.health_check:
            raise GuardError("apply requires an explicit trusted --health-check")
        result = (guard.apply(args.health_check, args.config_check) if args.action == "apply"
                  else guard.rollback(args.health_check))
        print(json.dumps(result, indent=2))
        return 0
    except (GuardError, OSError) as exc:
        message = str(exc) if isinstance(exc, GuardError) else "filesystem operation failed"
        print("web-guard: " + message, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
