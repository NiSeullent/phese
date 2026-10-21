"""Bounded setup planning, optional AI advice, and existing service transactions.

The AI result is data, never a shell command or a policy body. This module does
not rewrite applications, compile/load a global PHP extension, or tune workers.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

from . import __version__
from .cli import FIXED, VERSION_CODE, STATUS_CODE, PolicyError, private_json, protected_status, scan

PROFILE = "existing-php-service-floor-v1"
CODES = ("retain-policy", "measure-before-tuning", "review-app-requests", "use-cli-isolation")
SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["schema_version", "profile", "recommendations"],
    "properties": {
        "schema_version": {"type": "integer", "const": 1},
        "profile": {"type": "string", "const": PROFILE},
        "recommendations": {"type": "array", "maxItems": len(CODES),
                            "items": {"type": "string", "enum": list(CODES)}},
    },
}
PROMPT = ("Return only JSON matching the supplied schema. Review the PUBLIC_SUMMARY "
          "provided on stdin. Do not use tools, open files, inspect environment or "
          "credentials, or run commands. Choose existing recommendation codes only. "
          "Do not invent settings, shell commands, policy bodies, or performance claims.")
# These switches are individually present in the inspected Codex feature list.
# They reduce integration surface; they are NOT a claim that all model tools are absent.
CODEX_DISABLED = ("hooks", "plugins", "apps", "shell_tool", "unified_exec", "multi_agent",
                  "browser_use", "computer_use", "image_generation", "skill_search",
                  "workspace_dependencies", "view_image")
CLAUDE_FLAGS = ("--print", "--bare", "--safe-mode", "--restricted", "--tools",
                "--strict-mcp-config", "--mcp-config", "--setting-sources",
                "--no-session-persistence", "--no-chrome", "--permission-prompts",
                "--output-format", "--json-schema", "--system-prompt")
SERVICE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,180}\.service\Z")
MAX_OUTPUT = 1024 * 1024


class SetupError(Exception):
    pass


def trusted_file(value, executable=False):
    """Select only an owner-controlled executable; never evaluate PATH shell text."""
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise SetupError("an absolute executable/source path is required")
    path = path.resolve(strict=True)
    expected_uids = {0, os.geteuid()}
    for item in [path, *path.parents]:
        meta = item.lstat()
        if meta.st_uid not in expected_uids or meta.st_mode & 0o022 or stat.S_ISLNK(meta.st_mode):
            # /tmp itself is a shared ancestor, so production executables cannot
            # be loaded from an untrusted temporary tree even if its leaf is 0700.
            raise SetupError("executable/source ancestry must be owner-controlled and not shared-writable")
    if not path.is_file() or (executable and not os.access(path, os.X_OK)):
        raise SetupError("a regular executable/source file is required")
    return path


def digest(path):
    hasher = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(part)
    return hasher.hexdigest()


def bounded_run(argv, payload=None, cwd=None, timeout=20):
    """Bound process group lifetime and output on disk, with no inherited extra fds.

    HOME is retained for the CLI's own normal authentication. No auth file or
    environment value is copied into the model payload. Output is never logged.
    """
    if not all(hasattr(os, name) for name in ("waitid", "P_PID", "WEXITED", "WNOHANG", "WNOWAIT")):
        raise SetupError("Linux non-reaping child observation is required for bounded CLI cleanup")
    env = {"PATH": os.defpath, "LANG": "C.UTF-8", "HOME": str(Path.home())}
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        child = subprocess.Popen(list(argv), stdin=subprocess.PIPE if payload is not None else subprocess.DEVNULL,
                                 stdout=output, stderr=errors, cwd=cwd, env=env,
                                 start_new_session=True, close_fds=True)
        started = time.monotonic()
        try:
            if payload is not None:
                child.stdin.write(payload.encode("utf-8"))
                child.stdin.close()
            while True:
                # Do not reap the leader until group cleanup: its reserved PID
                # prevents the group number from being reused for another job.
                finished = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if finished is not None:
                    break
                if (time.monotonic() - started > timeout or output.tell() > MAX_OUTPUT
                        or errors.tell() > MAX_OUTPUT):
                    raise SetupError("CLI timed out or exceeded the output limit; no retry or paid fallback was attempted")
                time.sleep(0.025)
            if output.tell() > MAX_OUTPUT or errors.tell() > MAX_OUTPUT:
                raise SetupError("CLI output limit exceeded")
            output.seek(0)
            stdout = output.read(MAX_OUTPUT + 1).decode("utf-8", errors="strict")
            exit_code = finished.si_status if finished.si_code == os.CLD_EXITED else -finished.si_status
            if exit_code:
                # Never expose raw model/client errors, credentials or quota text.
                raise SetupError("CLI failed (exit %d); authentication, quota or availability may need operator attention; no retry" % exit_code)
            return stdout
        finally:
            # Successful leader exit does not imply its descendants exited.
            # Always signal our whole group before reaping the direct child.
            try:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            finally:
                child.wait(timeout=5)


def strict_json(raw):
    if len(raw.encode("utf-8")) > 32768:
        raise SetupError("JSON exceeds its size limit")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise SetupError("duplicate JSON field")
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda value: (_ for _ in ()).throw(ValueError()))
        pending, count = [(value, 0)], 0
        while pending:
            item, depth = pending.pop()
            count += 1
            if depth > 12 or count > 4096:
                raise SetupError("JSON depth or item limit exceeded")
            if isinstance(item, dict):
                pending.extend((child, depth + 1) for child in item.values())
            elif isinstance(item, list):
                pending.extend((child, depth + 1) for child in item)
        return value
    except (ValueError, TypeError, RecursionError) as exc:
        raise SetupError("invalid bounded JSON") from exc


def validate_advice(value):
    if not isinstance(value, dict) or set(value) != {"schema_version", "profile", "recommendations"}:
        raise SetupError("assistant output has unknown or missing fields")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1 or value["profile"] != PROFILE:
        raise SetupError("assistant cannot select a new or weaker policy")
    rows = value["recommendations"]
    if (not isinstance(rows, list) or len(rows) > len(CODES)
            or any(type(row) is not str or row not in CODES for row in rows) or len(set(rows)) != len(rows)):
        raise SetupError("assistant recommendation is not allowlisted")
    return value


def public_summary(plan):
    """Construct from scratch: no hostnames, paths, service names, env, logs or source."""
    return {"schema_version": 1, "platform_supported": plan["platform_supported"],
            "php_fixed_version": plan["runtime"]["fixed_version"],
            "native_cli_checked": plan["runtime"]["native_cli_checked"],
            "service_count": len(plan["services"]),
            "active_service_count": sum(row["active"] for row in plan["services"]),
            "existing_policy_count": sum(row["action"] == "unchanged" for row in plan["services"]),
            "app_request_count": plan["app_request_count"],
            "policy": PROFILE, "optimization": "measurement-required-no-worker-or-cache-changes"}


def cli_capability(name, runner=bounded_run, which=shutil.which):
    selected = which(name)
    if not selected:
        return {"available": False, "reason": "not-installed"}
    path = trusted_file(selected, executable=True)
    version = runner([str(path), "--version"], timeout=10).strip()
    patterns = {"codex": r"codex-cli [0-9]+\.[0-9]+\.[0-9]+", "claude": r"[0-9]+\.[0-9]+\.[0-9]+ \(Claude Code\)"}
    if not re.fullmatch(patterns[name], version):
        raise SetupError("unrecognized assistant CLI version response")
    help_text = runner([str(path), *( ["exec"] if name == "codex" else []), "--help"], timeout=10)
    flags = CLAUDE_FLAGS if name == "claude" else ("--sandbox", "--ephemeral", "--ignore-user-config", "--ignore-rules",
                                                  "--output-schema", "--skip-git-repo-check", "--json")
    if not all(flag in help_text for flag in flags):
        raise SetupError("installed assistant CLI lacks required planning switches")
    if name == "codex":
        features = runner([str(path), "features", "list"], timeout=10)
        names = {line.split()[0] for line in features.splitlines() if line.split()}
        if not set(CODEX_DISABLED).issubset(names):
            raise SetupError("Codex feature controls differ; update the reviewed adapter first")
    return {"available": True, "version": version, "path": str(path),
            "executable_sha256": digest(path), "model_call_tested": False}


def assistant_advice(name, plan, runner=bounded_run, capability=None):
    info = capability or cli_capability(name, runner=runner)
    if not info["available"]:
        raise SetupError("selected assistant CLI is not installed; use deterministic setup without it")
    payload = "PUBLIC_SUMMARY\n" + json.dumps(public_summary(plan), separators=(",", ":")) + "\n"
    with tempfile.TemporaryDirectory(prefix="phese-advice-") as temporary:
        workspace = Path(temporary)
        workspace.chmod(0o700)
        if name == "claude":
            argv = [info["path"], "--print", "--bare", "--safe-mode", "--restricted", "--tools", "",
                    "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}', "--setting-sources", "",
                    "--no-session-persistence", "--no-chrome", "--permission-prompts", "none",
                    "--output-format", "json", "--json-schema", json.dumps(SCHEMA), "--system-prompt", PROMPT]
            envelope = strict_json(runner(argv, payload=payload, cwd=workspace, timeout=120))
            if not isinstance(envelope, dict) or envelope.get("is_error") is True:
                raise SetupError("Claude returned an error; no automatic retry or paid fallback")
            value = envelope.get("structured_output")
            if value is None and isinstance(envelope.get("result"), str):
                value = strict_json(envelope["result"])
        elif name == "codex":
            schema = workspace / "schema.json"
            schema.write_text(json.dumps(SCHEMA), encoding="utf-8")
            answer = workspace / "answer.json"
            argv = [info["path"], "--no-daemon", "exec", "--sandbox", "read-only", "--ephemeral",
                    "--ignore-user-config", "--ignore-rules", "--skip-git-repo-check", "--color", "never",
                    "--output-schema", str(schema), "--output-last-message", str(answer), "--json"]
            for feature in CODEX_DISABLED:
                argv.extend(["--disable", feature])
            argv.append("-")
            # A read-only sandbox and disabled integrations reduce scope. Managed
            # policy/remaining built-in tools still apply; this is not tool-free.
            runner(argv, payload=PROMPT + "\n" + payload, cwd=workspace, timeout=120)
            descriptor = os.open(answer, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, "rb") as stream:
                meta = os.fstat(stream.fileno())
                if not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1 or meta.st_size > 32768:
                    raise SetupError("invalid Codex answer file")
                value = strict_json(stream.read(32769).decode("utf-8", errors="strict"))
        else:
            raise SetupError("unsupported assistant")
    return {"provider": name, "advice": validate_advice(value), "model_override": False,
            "arbitrary_execution": False, "tool_free_guarantee": False,
            "requested_tools": "none" if name == "claude" else "reduced-read-only",
            "auth_or_quota_verified": False}


def load_backend():
    package = Path(__file__).resolve().parent
    installed = package / "_service_guard.py"
    source = installed if installed.is_file() else package.parent / "tools/service_guard.py"
    source = trusted_file(source)
    spec = importlib.util.spec_from_file_location("phese_setup_service_guard", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    policy = package / "_service_policy.conf" if source == installed else package.parent / "policies/php-service.conf"
    policy = trusted_file(policy)
    return module, policy


def runtime_inventory(php, extension=None, runner=bounded_run):
    path = trusted_file(php, executable=True)
    version = strict_json(runner([str(path), "-n", "-r", VERSION_CODE], timeout=15))
    if not isinstance(version, list) or len(version) != 3:
        raise SetupError("invalid PHP version probe")
    text, number, zts = version
    if (not isinstance(text, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", text)
            or type(number) is not int or type(zts) not in {bool, int} or zts not in {0, 1}):
        raise SetupError("stable PHP version and valid ABI metadata are required")
    parts = tuple(map(int, text.split(".")))
    if number != parts[0] * 10000 + parts[1] * 100 + parts[2]:
        raise SetupError("inconsistent PHP version metadata")
    fixed = parts[:2] in FIXED and parts[2] >= FIXED[parts[:2]]
    native = False
    extension_sha = None
    if extension:
        if not fixed:
            raise SetupError("upgrade the selected PHP before probing a native extension")
        module = trusted_file(extension)
        status = strict_json(runner([str(path), "-n", "-d", "extension=" + str(module), "-r", STATUS_CODE], timeout=15))
        if not protected_status(status):
            raise SetupError("native CLI probe did not confirm all existing guards")
        native, extension_sha = True, digest(module)
    return {"path": str(path), "version": text, "version_id": number, "zts": bool(zts),
            "sha256": digest(path), "fixed_version": fixed, "provenance": "selected-file-sha256-not-vendor-attestation",
            "native_cli_checked": native, "extension_sha256": extension_sha,
            "running_workers_checked": False, "global_extension_enabled": False}


def discover_services(runner=bounded_run):
    """Read unit names/state only; never return descriptions, ExecStart or env."""
    path = shutil.which("systemctl")
    if not path:
        return []
    path = trusted_file(path, executable=True)
    raw = runner([str(path), "list-units", "--type=service", "--state=running",
                  "--plain", "--no-legend", "--no-pager"], timeout=10)
    names = []
    for line in raw.splitlines():
        words = line.split()
        if len(words) < 4:
            continue
        name = words[0]
        if (SERVICE.fullmatch(name) and words[1:4] == ["loaded", "active", "running"]
                and re.search(r"(?:^|[_.@-])(?:php(?:[0-9.]+)?-fpm|fpm|httpd|apache2?)(?:[_.@-]|$)", name)):
            names.append(name)
    return sorted(set(names))[:8]


def make_plan(php, services, extension=None, app=None, backend=None, runner=bounded_run):
    if len(services) > 8 or len(set(services)) != len(services) or any(not SERVICE.fullmatch(s) for s in services):
        raise SetupError("select at most eight unique exact .service names")
    module, policy = backend or load_backend()
    runtime = runtime_inventory(php, extension, runner)
    selected = []
    for name in services:
        guard = module.ServiceGuard(name, policy=policy)
        try:
            row = guard.plan()
            selected.append({"service": name, "action": row["action"], "active": bool(guard.active()),
                             "policy_sha256": row["policy_sha256"], "restart_required": row["restart_required"]})
        except module.GuardError as exc:
            raise SetupError("existing service guard refused inspection; inspect its local transaction status") from exc
    requests = scan(Path(app).resolve(strict=True)) if app else None
    return {"schema_version": 1, "phese_version": __version__, "platform_supported": sys.platform == "linux" and platform.machine() in {"x86_64", "aarch64"},
            "runtime": runtime, "profile": PROFILE, "services": selected,
            "app_request_count": len(requests["requests"]) if requests else 0,
            "application_requests": requests,
            "optimizations": {"mode": "measurement-required", "worker_or_cache_settings_changed": False,
                              "scope": "existing-policy-reuse-and-unnecessary-restart-avoidance-only",
                              "abi_autoselection": "separate-existing-phese.setup-contract",
                              "recommendations": ["retain-policy", "measure-before-tuning"]},
            "changes_application_source": False, "service_protection_applied": False,
            "activation_scope": "existing-systemd-policy-only-not-native-FPM-enforcement"}


def execute_plan(plan, health, backend=None):
    if os.geteuid() != 0:
        raise SetupError("service setup requires root")
    if not plan["platform_supported"] or not plan["runtime"]["fixed_version"]:
        raise SetupError("supported Linux and fixed stable PHP are required before apply")
    services = plan["services"]
    if not services or set(health) != {row["service"] for row in services}:
        raise SetupError("apply needs exact selected services and one explicit health check for each")
    module, policy = backend or load_backend()
    for row in services:
        if not row["active"] or row["action"] not in {"create-dropin", "unchanged", "unmanaged-identical"}:
            raise SetupError("all selected services must be active with an admissible existing drop-in")
        try:
            module.trusted_health(health[row["service"]])
        except module.GuardError as exc:
            raise SetupError("service health argv is not trusted") from exc
    # Each service has the existing locked transaction and rollback. This is not
    # an all-services atomic transaction: stop on first failure, preserve receipts.
    results = []
    plan["transactions"] = results
    for row in services:
        guard = module.ServiceGuard(row["service"], policy=policy)
        try:
            current = guard.plan()
            if current["policy_sha256"] != row["policy_sha256"]:
                raise SetupError("policy changed after planning; re-plan before apply")
            results.append(guard.apply(health[row["service"]]))
        except module.GuardError as exc:
            raise SetupError("existing service transaction refused or failed; stop and inspect its private receipt before resuming") from exc
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--php", default=shutil.which("php"), help="trusted fixed PHP executable; clean -n probe only")
    parser.add_argument("--extension", help="optional native CLI probe; never enables a global extension")
    parser.add_argument("--service", action="append", default=[], help="exact existing active .service; repeat at most eight")
    parser.add_argument("--discover-services", action="store_true", help="read-only diagnosis of recognized running PHP/web service names; --apply still requires explicit --service")
    parser.add_argument("--health-check", action="append", default=[], metavar="SERVICE=JSON_ARGV",
                        help="explicit trusted health argv; never include credentials in arguments")
    parser.add_argument("--app", help="optional read-only local change-request scan; source never sent to AI")
    parser.add_argument("--assistant", choices=("none", "codex", "claude"), default="none",
                        help="explicit optional account-backed planning call; may consume existing account quota")
    parser.add_argument("--assistant-inventory", action="store_true", help="local --version/--help checks only; no model call")
    parser.add_argument("--assistant-response-stdin", action="store_true", help="validate strict advice JSON without calling a model")
    parser.add_argument("--report", help="optional private local report; excludes raw CLI errors and health argv")
    parser.add_argument("--apply", action="store_true", help="apply existing policy with health check; may restart selected services")
    args = parser.parse_args(argv)
    plan = None
    try:
        if not args.php:
            raise SetupError("select a PHP executable using --php")
        if args.assistant_response_stdin and args.assistant != "none":
            raise SetupError("choose stdin advice or an assistant CLI, not both")
        if args.discover_services and (args.apply or args.service):
            raise SetupError("discovery is read-only; choose explicit --service names for apply")
        health = {}
        for value in args.health_check:
            name, separator, raw = value.partition("=")
            if not separator or name in health or not SERVICE.fullmatch(name):
                raise SetupError("health checks require unique SERVICE=JSON_ARGV values")
            health[name] = strict_json(raw)
        selected = discover_services() if args.discover_services else args.service
        plan = make_plan(args.php, selected, args.extension, args.app)
        if args.assistant_inventory:
            plan["assistant_inventory"] = {name: cli_capability(name) for name in ("codex", "claude")}
        if args.assistant_response_stdin:
            plan["assistant"] = {"provider": "response-import", "advice": validate_advice(strict_json(sys.stdin.read(32769)))}
        elif args.assistant != "none":
            plan["assistant"] = assistant_advice(args.assistant, plan)
        if args.apply:
            plan["transactions"] = execute_plan(plan, health)
            plan["service_protection_applied"] = True
        if args.report:
            private_json(args.report, plan)
        print(json.dumps(plan, ensure_ascii=False, indent=2))
        return 0
    except KeyboardInterrupt:
        print("phese-setup: interrupted; inspect per-service transaction receipts before continuing", file=sys.stderr)
        return 130
    except (SetupError, PolicyError, OSError, ValueError, subprocess.SubprocessError) as exc:
        if plan is not None and args.report:
            plan["result"] = "failed-or-partial-inspect-existing-transaction-receipts"
            try:
                private_json(args.report, plan)
            except (PolicyError, OSError):
                pass
        message = str(exc) if isinstance(exc, (SetupError, PolicyError)) else "local operation failed; inspect permissions and existing service transaction status"
        print("phese-setup: " + message, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
