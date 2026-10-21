"""Conservative local setup; application PHP and running services are untouched."""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile

from . import __version__
from . import cli

BEGIN = "<!-- AsylumEnforce managed instructions: begin -->"
END = "<!-- AsylumEnforce managed instructions: end -->"
MAX_FILE = 512 * 1024
ASSISTANTS = {"codex": "AGENTS.md", "claude": "CLAUDE.md"}


def safe_path(value):
    path = cli.absolute_without_symlinks(value)
    if any(ord(char) < 32 or ord(char) == 127 for char in str(path)):
        raise cli.PolicyError("설정 경로에 제어 문자를 사용할 수 없습니다.")
    return path


def check_path(path, *, missing=False, owner=None):
    """Trust immutable ancestors; allow the shared sticky /tmp ancestor only."""
    path = safe_path(path)
    uid = os.getuid() if owner is None else owner
    for current in (*reversed(path.parents), path):
        try:
            info = current.lstat()
        except FileNotFoundError:
            if missing:
                continue
            raise cli.PolicyError("필요한 설정 경로가 없습니다.")
        if stat.S_ISLNK(info.st_mode):
            raise cli.PolicyError("설정 경로의 심볼릭 링크는 허용하지 않습니다.")
        sticky_parent = (current != path and stat.S_ISDIR(info.st_mode)
                         and info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX))
        if info.st_uid not in {0, uid} or (info.st_mode & 0o022 and not sticky_parent):
            raise cli.PolicyError("설정 경로는 신뢰한 소유자만 변경할 수 있어야 합니다.")
    return path


def trusted_file(value, executable=False):
    # Operator-selected interpreter symlinks resolve to a separately checked
    # trusted file. Application and output paths themselves never follow links.
    path = Path(value).expanduser().resolve(strict=True)
    check_path(path)
    mode = path.stat().st_mode
    if not stat.S_ISREG(mode) or (executable and not os.access(path, os.X_OK)):
        raise cli.PolicyError("신뢰할 수 있는 일반 파일이 필요합니다.")
    return path


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, capture_output=True, text=True,
                          timeout=kwargs.pop("timeout", 20), stdin=subprocess.DEVNULL,
                          shell=False, **kwargs)


def detect_runtime(php=None, extension=None):
    php_candidates = [php] if php else [
        "/usr/local/lib/asylumenforce/runtime/php-8.5.12", shutil.which("php")]
    failures = []
    selected = None
    for value in php_candidates:
        if not value:
            continue
        try:
            candidate = trusted_file(value, executable=True)
            info = cli.php_info(candidate)
            cli.require_fixed(info)
            selected = candidate, info
            break
        except (cli.PolicyError, OSError, ValueError, subprocess.SubprocessError):
            failures.append("unverified_php")
    if not selected:
        raise cli.PolicyError("수정된 안정 PHP를 찾지 못했습니다. --php로 검증할 바이너리를 지정하세요.")
    binary, info = selected
    if extension:
        modules = [Path(extension)]
    else:
        folder = Path("/usr/local/lib/asylumenforce/native")
        modules = sorted(folder.glob("phese-*.so")) if folder.is_dir() else []
    for value in modules:
        try:
            module = trusted_file(value)
            result = run([str(binary), "-n", "-d", f"extension={module}", "-r", cli.STATUS_CODE])
            status = json.loads(result.stdout)
            if cli.protected_status(status):
                return {"php": str(binary), "extension": str(module),
                        "version": info["version"], "version_id": info["version_id"],
                        "zts": info["zts"], "native_verified": True}
        except (cli.PolicyError, OSError, ValueError, subprocess.SubprocessError):
            continue
    raise cli.PolicyError("PHP ABI/ZTS와 일치하는 보호 확장을 확인하지 못했습니다. --extension 또는 bootstrap을 사용하세요.")


def detect_bwrap():
    candidate = shutil.which("bwrap")
    if not candidate:
        raise cli.PolicyError("bubblewrap 0.10 이상이 필요합니다.")
    binary = trusted_file(candidate, executable=True)
    output = run([str(binary), "--version"]).stdout
    match = re.search(r"bubblewrap\s+(\d+)\.(\d+)(?:\.(\d+))?", output)
    if not match or tuple(int(part or 0) for part in match.groups()) < (0, 10, 0):
        raise cli.PolicyError("FD로 mount를 고정하려면 bubblewrap 0.10 이상이 필요합니다.")
    return {"path": str(binary), "version": match.group(0).split()[-1]}


def parse_assistants(value):
    names = [] if value in {"", "none"} else value.split(",")
    if len(names) != len(set(names)) or any(name not in ASSISTANTS for name in names):
        raise cli.PolicyError("--assistants는 codex,claude 또는 none으로 지정하세요.")
    return names


def state_directory(app, override=None):
    if override:
        path = safe_path(override)
    else:
        base = (Path("/var/lib/asylumenforce/apps") if os.getuid() == 0
                else Path.home() / ".local/state/phese/apps")
        path = base / hashlib.sha256(str(app).encode()).hexdigest()[:20]
    if path.is_relative_to(app) or app.is_relative_to(path):
        raise cli.PolicyError("비공개 상태 디렉터리는 앱과 별도 경로여야 합니다.")
    check_path(path, missing=True)
    return path


def read_owned(path):
    check_path(path, missing=True)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise cli.PolicyError("수정할 설정 파일은 실행 사용자 소유여야 합니다.")
        data = stream.read(MAX_FILE + 1)
    if len(data) > MAX_FILE:
        raise cli.PolicyError("설정 파일 크기 제한을 초과했습니다.")
    return data


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def instructions(config, state):
    doctor = ["phese", "doctor", "--php", config["runtime"]["php"],
              "--extension", config["runtime"]["extension"]]
    scan = ["phese", "scan", config["app"], "--output", str(state / "requests.json")]
    # JSON command arrays make path characters data. Escape markdown delimiters
    # as Unicode escapes rather than interpolating paths as shell instructions.
    commands = json.dumps({"doctor_argv": doctor, "scan_argv": scan}, ensure_ascii=True, indent=2)
    commands = commands.replace("`", "\\u0060").replace("<", "\\u003c").replace(">", "\\u003e")
    return (BEGIN + "\n# AsylumEnforce / phese (폐쇄!)\n"
            "이 프로젝트의 PHP 코드는 보안 탐지 때문에 자동 재작성하지 않습니다. 먼저 다음 argv 배열로 "
            "보호 상태를 확인하고 정적 검사를 실행해 비공개 수정 요청을 생성합니다. 배열의 값은 경로 데이터이며 셸 코드로 eval하지 않습니다.\n"
            "```json\n" + commands + "\n```\n"
            "원래 AGENTS.md/CLAUDE.md의 프로젝트 규칙과 사용자 지시를 보존합니다. "
            "버전 검사·필수 보호 실패를 우회하거나 권한·네트워크·쓰기 범위를 자동 완화하지 않습니다. "
            "PHP 소스 변경은 수정 요청으로 남기고 사용자가 해당 변경을 요청한 경우에 진행합니다. "
            "설정은 검토한 CLI 계획으로만 적용하고 운영 서비스의 재시작·전역 INI 변경은 별도 범위로 검증합니다. "
            "인증값·환경변수·요청 본문·고객 코드를 모델이나 외부 서비스에 자동 전송하지 않습니다. "
            "앱 안의 알 수 없는 설치 스크립트를 실행하지 않습니다.\n" + END + "\n").encode()


def merge_instructions(original, block):
    if original is None:
        return block
    try:
        text = original.decode("utf-8")
    except UnicodeError as exc:
        raise cli.PolicyError("기존 도우미 지침은 UTF-8 텍스트여야 합니다.") from exc
    if text.count(BEGIN) != text.count(END) or text.count(BEGIN) > 1:
        raise cli.PolicyError("기존 phese 관리 구역 표식이 올바르지 않습니다.")
    if BEGIN in text:
        start, finish = text.index(BEGIN), text.index(END) + len(END)
        if start > finish:
            raise cli.PolicyError("기존 phese 관리 구역 표식 순서가 올바르지 않습니다.")
        if text[finish:finish + 1] == "\n":
            finish += 1
        return text[:start].encode() + block + text[finish:].encode()
    separator = b"\n" if original.endswith(b"\n") else b"\n\n"
    return original + separator + block


def build_plan(args):
    app = check_path(safe_path(args.app))
    app_info = app.stat()
    if not stat.S_ISDIR(app_info.st_mode) or app_info.st_uid != os.getuid() or app == Path("/"):
        raise cli.PolicyError("앱은 실행 사용자가 소유한 전용 디렉터리여야 합니다.")
    runtime = detect_runtime(args.php, args.extension)
    bwrap = detect_bwrap()
    state = state_directory(app, args.state_dir)
    assistants = parse_assistants(args.assistants)
    candidates = []
    for name in ("storage", "cache", "tmp"):
        folder = app / name
        if folder.is_dir() and not folder.is_symlink():
            candidates.append(str(folder))
    writes = []
    for value in args.write:
        folder = safe_path(value)
        if folder == app or not folder.is_relative_to(app):
            raise cli.PolicyError("쓰기 허용은 앱 내부의 명시적인 하위 디렉터리여야 합니다.")
        # Pin the entire relative path and reject symlinks, including ancestors.
        fd = cli.pin_path(folder, directory=True)
        os.close(fd)
        writes.append(str(folder))
    config = {"schema": 1, "managed_by": "AsylumEnforce", "app": str(app),
              "runtime": runtime, "network": "none", "timeout_seconds": 60,
              "write_dirs": sorted(set(writes)), "assistant_integrations": assistants,
              "source_policy": "request-only", "service_changes": False}
    targets = {app / ".phese/config.json": json_bytes(config)}
    config_before = read_owned(app / ".phese/config.json")
    if config_before is not None:
        try:
            existing = json.loads(config_before)
        except ValueError as exc:
            raise cli.PolicyError("기존 .phese 설정을 확인할 수 없어 덮어쓰지 않습니다.") from exc
        if not isinstance(existing, dict) or existing.get("managed_by") != "AsylumEnforce" or existing.get("app") != str(app):
            raise cli.PolicyError("기존 .phese 설정은 이 도구의 관리 파일이 아닙니다.")
    block = instructions(config, state)
    for name in assistants:
        path = app / ASSISTANTS[name]
        targets[path] = merge_instructions(read_owned(path), block)
    before = {path: read_owned(path) for path in targets}
    return {"config": config, "state": state, "targets": targets, "before": before,
            "summary": {"mode": "apply" if args.apply else "plan", "app": str(app),
                        "runtime": runtime, "bubblewrap": bwrap, "network": "none",
                        "timeout_seconds": 60, "write_dirs": config["write_dirs"],
                        "suggested_write_dirs": candidates,
                        "write_permissions_changed": False,
                        "assistant_files": [ASSISTANTS[name] for name in assistants],
                        "state_directory": str(state), "changes_php_source": False,
                        "changes_running_services": False,
                        "assistant_model_invoked": False}}


def atomic_write(path, data, mode=0o600):
    check_path(path, missing=True)
    fd, temporary = tempfile.mkstemp(prefix=".phese-write-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def private_directory(path):
    check_path(path, missing=True)
    absent = []
    cursor = path
    while not cursor.exists():
        absent.append(cursor)
        cursor = cursor.parent
    for folder in reversed(absent):
        folder.mkdir(mode=0o700)
    check_path(path)
    if path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077:
        raise cli.PolicyError("상태 디렉터리는 실행 사용자 전용 권한 0700이어야 합니다.")


def apply_plan(plan):
    state = plan["state"]
    private_directory(state)
    lock_path = state / "setup.lock"
    check_path(lock_path, missing=True)
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise cli.PolicyError("동일 앱의 다른 설정 적용이 진행 중입니다.") from exc
        changed = []
        try:
            for path, original in plan["before"].items():
                if read_owned(path) != original:
                    raise cli.PolicyError("검토 이후 설정 파일이 변경되어 적용을 중단했습니다.")
            private_directory(Path(plan["config"]["app"]) / ".phese")
            report = cli.scan(Path(plan["config"]["app"]))
            cli.private_json(state / "requests.json", report)
            for path, content in plan["targets"].items():
                original = plan["before"][path]
                if content == original:
                    continue
                mode = path.stat().st_mode & 0o777 if original is not None else (0o600 if path.suffix == ".json" else 0o644)
                atomic_write(path, content, mode)
                changed.append((path, original, mode))
            cli.private_json(state / "config.json", plan["config"])
            cli.private_json(state / "manifest.json", {"schema": 1, "managed_by": "AsylumEnforce",
                "files": [{"path": str(path), "sha256": hashlib.sha256(data).hexdigest()}
                          for path, data in plan["targets"].items()]})
        except Exception as exc:
            failed = False
            for path, original, mode in reversed(changed):
                try:
                    # Preserve any concurrent external replacement rather than
                    # deleting or overwriting another actor's content.
                    if read_owned(path) != plan["targets"][path]:
                        failed = True
                        continue
                    if original is None:
                        path.unlink()
                    else:
                        atomic_write(path, original, mode)
                except Exception:
                    failed = True
            if failed:
                raise cli.PolicyError("설정 실패 후 일부 파일의 자동 복구를 확인할 수 없습니다.") from exc
            raise
        return {**plan["summary"], "result": "applied", "changed_files": len(changed),
                "request_count": len(report["requests"]),
                "config": str(state / "config.json"), "requests": str(state / "requests.json")}
    finally:
        os.close(fd)


def parser():
    result = argparse.ArgumentParser(description="PHP 보호 구성과 Codex/Claude 프로젝트 지침 자동 설정")
    result.add_argument("--version", action="version", version=__version__)
    result.add_argument("--app", required=True)
    result.add_argument("--php")
    result.add_argument("--extension")
    result.add_argument("--assistants", default="codex,claude")
    result.add_argument("--write", action="append", default=[])
    result.add_argument("--state-dir", help="앱 외부의 비공개 상태 디렉터리")
    result.add_argument("--apply", action="store_true", help="검사한 구성·지침만 기록; PHP·서비스는 변경하지 않음")
    return result


def main(argv=None):
    selected = sys.argv[1:] if argv is None else list(argv)
    if selected and selected[0] == "run":
        return configured_main(selected[1:])
    args = parser().parse_args(selected)
    try:
        plan = build_plan(args)
        result = apply_plan(plan) if args.apply else plan["summary"]
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (cli.PolicyError, OSError, ValueError, subprocess.SubprocessError) as exc:
        message = str(exc) if isinstance(exc, cli.PolicyError) else type(exc).__name__
        print("phese setup: " + message, file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("phese setup: 설정을 중단했습니다.", file=sys.stderr)
        return 130


def configured_main(argv=None):
    """Use managed settings while retaining every enforcement check in cli.run."""
    arguments = argparse.ArgumentParser(description="저장한 phese 구성으로 PHP 실행")
    arguments.add_argument("--config", default=str(Path.cwd() / ".phese/config.json"))
    arguments.add_argument("script")
    arguments.add_argument("arguments", nargs=argparse.REMAINDER)
    args = arguments.parse_args(argv)
    try:
        raw = read_owned(safe_path(args.config))
        config = json.loads(raw) if raw is not None else None
        if (not isinstance(config, dict) or config.get("schema") != 1
                or config.get("managed_by") != "AsylumEnforce"
                or config.get("network") != "none" or config.get("source_policy") != "request-only"
                or not isinstance(config.get("runtime"), dict)
                or not isinstance(config.get("write_dirs"), list)
                or any(not isinstance(value, str) for value in config["write_dirs"])
                or type(config.get("timeout_seconds")) is not int
                or not 1 <= config["timeout_seconds"] <= 86400):
            raise cli.PolicyError("지원하는 phese 관리 설정이 아닙니다.")
        runtime = config["runtime"]
        if any(not isinstance(value, str) for value in (config.get("app"), runtime.get("php"), runtime.get("extension"))):
            raise cli.PolicyError("실행 설정의 경로가 올바르지 않습니다.")
        command = ["run", "--php", runtime["php"], "--extension", runtime["extension"],
                   "--app", config["app"], "--timeout", str(config["timeout_seconds"])]
        for path in config["write_dirs"]:
            command.extend(("--write", path))
        return cli.main([*command, args.script, *args.arguments])
    except (cli.PolicyError, OSError, ValueError, TypeError) as exc:
        message = str(exc) if isinstance(exc, cli.PolicyError) else type(exc).__name__
        print("phese start: " + message, file=sys.stderr)
        return 2


def development_abi(config, phpize, info):
    """Use supported PHP SDK interfaces and cross-check independent ABI data."""
    output = run([str(phpize), "--version"]).stdout
    fields = {}
    for label in ("PHP Api Version", "Zend Module Api No", "Zend Extension Api No"):
        matches = re.findall(r"^\s*" + re.escape(label) + r":\s*(\d+)\s*$", output, re.MULTILINE)
        if len(matches) != 1:
            raise cli.PolicyError("phpize에서 PHP 확장 ABI 번호를 확인하지 못했습니다.")
        fields[label] = matches[0]
    api = fields["Zend Module Api No"]
    if not re.fullmatch(r"\d{8}", api) or fields["PHP Api Version"] != api:
        raise cli.PolicyError("PHP API와 Zend 모듈 ABI 정보가 일치하지 않습니다.")
    branch = re.findall(r"^\s*PHP Version:\s*(\d+\.\d+)\s*$", output, re.MULTILINE)
    expected_branch = ".".join(info["version"].split(".")[:2])
    if branch and (len(branch) != 1 or branch[0] != expected_branch):
        raise cli.PolicyError("phpize와 실행할 PHP 브랜치가 다릅니다.")
    extension_dir = run([str(config), "--extension-dir"]).stdout.strip()
    if not Path(extension_dir).is_absolute() or any(ord(char) < 32 for char in extension_dir):
        raise cli.PolicyError("php-config의 확장 경로를 확인하지 못했습니다.")
    encoded = re.fullmatch(r"(no-debug|debug)-(zts|non-zts|nts)-(\d{8})", Path(extension_dir).name)
    if not encoded:
        raise cli.PolicyError("ABI 정보가 포함된 PHP 확장 경로가 필요합니다. 이 SDK 배치를 별도로 검증하세요.")
    if encoded[3] != api or (encoded[2] == "zts") is not info["zts"]:
        raise cli.PolicyError("phpize·php-config 확장 ABI 또는 ZTS 정보가 일치하지 않습니다.")
    return api


SOURCE_FILES = ("extension/build.sh", "extension/config.m4", "extension/phese.c",
                "extension/phese_seccomp.h", "tools/install_cli.py", "phese/__init__.py",
                "phese/cli.py")


def source_directory(value=None, *, applying=False):
    """Find an intact source distribution, never treat site-packages as an SDK."""
    if value is not None:
        candidates = [safe_path(value)]
    else:
        candidates = [Path(__file__).resolve().parents[1], Path.cwd()]
    for candidate in dict.fromkeys(candidates):
        if not candidate.is_dir() or not all((candidate / name).is_file() for name in SOURCE_FILES):
            continue
        repository = check_path(candidate, owner=0 if applying else os.getuid())
        # Validation applies during plan as well. No file from an untrusted cwd
        # is ever executed, and a partial source bundle is not reported ready.
        for name in SOURCE_FILES:
            path = repository / name
            check_path(path, owner=0 if applying else os.getuid())
            if not stat.S_ISREG(path.stat().st_mode):
                raise cli.PolicyError("소스 배포본의 빌드 파일은 일반 파일이어야 합니다.")
        if not os.access(repository / "extension/build.sh", os.X_OK):
            raise cli.PolicyError("소스 배포본 extension/build.sh에 실행 권한이 필요합니다.")
        return repository
    raise cli.PolicyError("네이티브 SDK가 있는 소스 배포본을 찾지 못했습니다. --source /신뢰한/소스배포본 경로를 지정하세요.")


def bootstrap_main(argv=None):
    """Build from an already obtained trusted checkout; never fetch or change PHP."""
    arguments = argparse.ArgumentParser(description="CLI와 일치하는 PHP 보호 확장 설치")
    arguments.add_argument("--php", required=True)
    arguments.add_argument("--php-config", required=True)
    arguments.add_argument("--source", help="네이티브 SDK와 설치 도구를 포함한 신뢰한 소스 배포본")
    arguments.add_argument("--apply", action="store_true")
    arguments.add_argument("--version", action="version", version=__version__)
    args = arguments.parse_args(argv)
    try:
        repository = source_directory(args.source, applying=args.apply)
        php = trusted_file(args.php, executable=True)
        config = trusted_file(args.php_config, executable=True)
        phpize = trusted_file(config.with_name("phpize"), executable=True)
        info = cli.php_info(php)
        cli.require_fixed(info)
        if run([str(config), "--version"]).stdout.strip() != info["version"]:
            raise cli.PolicyError("php-config와 실행할 PHP 버전이 다릅니다. 같은 설치의 개발 도구를 사용하세요.")
        api = development_abi(config, phpize, info)
        detect_bwrap()
        for dependency in ("cc", "make", "autoconf"):
            path = shutil.which(dependency)
            if not path:
                raise cli.PolicyError(f"필수 빌드 도구가 없습니다: {dependency}")
            trusted_file(path, executable=True)
        module_name = "phese-" + api + ("-zts.so" if info["zts"] else "-nts.so")
        destination = Path("/usr/local/lib/asylumenforce/native") / module_name
        summary = {"mode": "apply" if args.apply else "plan", "php": str(php),
                   "source": str(repository),
                   "php_version": info["version"], "php_api": api, "zts": info["zts"],
                   "module": str(destination), "changes_php_binary": False,
                   "changes_running_services": False, "downloads_dependencies": False}
        if not args.apply:
            print(json.dumps(summary, ensure_ascii=False, indent=2))
            return 0
        if os.getuid() != 0:
            raise cli.PolicyError("시스템 설치는 root에서 실행하세요. 계획 검사는 일반 사용자도 가능합니다.")
        # Root executes only a root-controlled, non-shared checkout and tools.
        for path in (php, config, phpize, repository / "extension/build.sh",
                     repository / "tools/install_cli.py"):
            check_path(path, owner=0)
        run([str(repository / "extension/build.sh"), str(config)], timeout=180)
        source = trusted_file(repository / "extension/modules/phese.so")
        result = run([str(php), "-n", "-d", f"extension={source}", "-r", cli.STATUS_CODE])
        if not cli.protected_status(json.loads(result.stdout)):
            raise cli.PolicyError("새 네이티브 확장의 실제 보호 상태를 확인하지 못했습니다.")
        check_path(destination, missing=True, owner=0)
        run([sys.executable, str(repository / "tools/install_cli.py")], timeout=30)
        install_module(source, destination, api, info["zts"])
        print(json.dumps({**summary, "result": "installed"}, ensure_ascii=False, indent=2))
        return 0
    except (cli.PolicyError, OSError, ValueError, subprocess.SubprocessError) as exc:
        message = str(exc) if isinstance(exc, cli.PolicyError) else type(exc).__name__
        print("phese bootstrap: " + message, file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("phese bootstrap: 설치를 중단했습니다.", file=sys.stderr)
        return 130


def read_module(path):
    """Read only an owned bounded regular binary, without following links."""
    check_path(path, missing=True)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise cli.PolicyError("네이티브 설치 파일의 소유권이 올바르지 않습니다.")
        content = stream.read(16 * 1024 * 1024 + 1)
    if len(content) > 16 * 1024 * 1024:
        raise cli.PolicyError("네이티브 모듈의 설치 크기 제한을 초과했습니다.")
    return content


def install_module(source, destination, api, zts):
    """Commit module and receipt together, restoring owned files on failure."""
    check_path(destination, missing=True)
    manifest = destination.with_suffix(destination.suffix + ".json")
    previous, receipt = read_module(destination), read_owned(manifest)
    if previous is None and receipt is not None:
        raise cli.PolicyError("네이티브 설치 기록만 남아 있어 상태 확인이 필요합니다.")
    if previous is not None:
        try:
            owned = json.loads(receipt) if receipt else {}
        except ValueError:
            owned = {}
        if (not isinstance(owned, dict) or owned.get("managed_by") != "AsylumEnforce"
                or owned.get("sha256") != hashlib.sha256(previous).hexdigest()):
            raise cli.PolicyError("기존 네이티브 파일의 설치 기록이 일치하지 않아 덮어쓰지 않습니다.")
    binary = read_module(source)
    if binary is None or not binary:
        raise cli.PolicyError("빌드한 네이티브 모듈이 없습니다.")
    record = json_bytes({"schema": 1, "managed_by": "AsylumEnforce",
        "sha256": hashlib.sha256(binary).hexdigest(), "php_api": api,
        "zts": zts, "version": __version__})
    destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    destination.parent.chmod(0o755)
    module_written = False
    try:
        atomic_write(destination, binary, 0o644)
        module_written = True
        atomic_write(manifest, record, 0o600)
    except Exception as exc:
        if module_written:
            try:
                if read_module(destination) != binary:
                    raise cli.PolicyError("설치 도중 네이티브 파일이 외부에서 변경되었습니다.")
                if previous is None:
                    destination.unlink()
                else:
                    atomic_write(destination, previous, 0o644)
                current_receipt = read_owned(manifest)
                if current_receipt not in {None, receipt, record}:
                    raise cli.PolicyError("설치 도중 네이티브 기록이 외부에서 변경되었습니다.")
                if receipt is None:
                    if current_receipt is not None:
                        manifest.unlink()
                elif current_receipt != receipt:
                    atomic_write(manifest, receipt, 0o600)
            except Exception as recovery:
                raise cli.PolicyError("네이티브 설치 실패 후 원래 파일 복구를 확인하지 못했습니다.") from recovery
        raise exc


if __name__ == "__main__":
    raise SystemExit(main())
