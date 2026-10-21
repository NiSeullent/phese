"""Dependency-free administration CLI. Application source is never rewritten."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

from . import __version__
from .events import emit

FIXED = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
VERSION_CODE = "echo json_encode([PHP_VERSION, PHP_VERSION_ID, PHP_ZTS]);"
STATUS_CODE = "echo json_encode(extension_loaded('phese') && function_exists('phese_status') ? phese_status() : null);"
RULES = [
    ("process-execution", re.compile(r"\b(?:exec|system|shell_exec|passthru|proc_open|popen|pcntl_exec|mail)\s*\(", re.I),
     "메일·변환 도구 등 외부 프로세스 실행은 기본 정책에서 차단됩니다. 별도 격리 작업 서비스 사용을 요청합니다."),
    ("ffi", re.compile(r"\bFFI\s*::|\bdl\s*\(", re.I),
     "FFI/동적 라이브러리 로딩 필요성을 검토하고 격리된 대체 경로를 요청합니다."),
    ("dynamic-code", re.compile(r"\beval\s*\(", re.I),
     "동적 PHP 실행의 입력 검증 검토를 요청합니다. 이 탐지는 취약점 확정이 아닙니다."),
    ("unserialize-review", re.compile(r"\bunserialize\s*\(", re.I),
     "역직렬화의 신뢰 경계와 allowed_classes 설정 검토를 요청합니다."),
]


class PolicyError(Exception):
    pass


def execute(argv, **kwargs):
    return subprocess.run(argv, check=True, text=True, capture_output=True,
                          timeout=kwargs.pop("timeout", 20), **kwargs)


def resolve_file(value):
    path = Path(value).expanduser().resolve(strict=True)
    if not path.is_file():
        raise PolicyError(f"일반 파일이 필요합니다: {path}")
    return path


def php_info(php, **kwargs):
    # Constant trusted probe, no application code and no host INI/prepend.
    result = execute([str(php), "-n", "-r", VERSION_CODE], **kwargs)
    version, number, zts = json.loads(result.stdout)
    branch = (number // 10000, number // 100 % 100)
    fixed = branch in FIXED and number % 100 >= FIXED[branch] and not re.search(r"(?:dev|alpha|beta|rc)", version, re.I)
    return {"version": version, "version_id": number, "zts": bool(zts),
            "cve_2026_109618_109619_version_gate": fixed}


def require_fixed(info):
    if not info["cve_2026_109618_109619_version_gate"]:
        emit("version_refused", "php_version_gate_failed")
        raise PolicyError("수정된 안정 PHP 8.2.35/8.3.36/8.4.27/8.5.12 이상의 해당 브랜치가 필요합니다. "
                          "배포판 백포트는 버전 숫자만으로 증명하지 않으며, 이 도구는 미확인 버전을 거부합니다.")


def protected_status(value):
    return isinstance(value, dict) and all(value.get(key) is True for key in
        ("seccomp_active", "no_new_privileges", "version_gate"))


def private_json(destination, value):
    """Atomic private report, refusing symlink replacement and shared report dirs."""
    path = Path(destination).absolute()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = path.parent.stat()
    if parent.st_uid != os.getuid() or parent.st_mode & 0o022:
        raise PolicyError("보고서 디렉터리는 실행 사용자 소유이며 다른 사용자가 쓸 수 없어야 합니다.")
    if path.is_symlink():
        raise PolicyError("보고서 심볼릭 링크는 허용하지 않습니다.")
    descriptor, temporary = tempfile.mkstemp(prefix=".phese-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def scan(root, max_files=20000):
    findings, skipped, count = [], [], 0
    for directory, folders, names in os.walk(root, followlinks=False):
        folders[:] = sorted(name for name in folders if name not in {".git", ".codex", "node_modules"}
                            and not (Path(directory) / name).is_symlink())
        for name in sorted(names):
            path = Path(directory) / name
            if path.suffix.lower() not in {".php", ".phtml", ".inc", ".php5", ".php7", ".php8"}:
                continue
            relative = str(path.relative_to(root))
            if path.is_symlink() or not path.is_file():
                skipped.append(relative)
                continue
            count += 1
            if count > max_files:
                raise PolicyError("검색 파일 수 한도를 초과했습니다. 하위 경로별로 검사하세요.")
            try:
                with path.open("rb") as source:
                    raw = source.read(2 * 1024 * 1024 + 1)
                if len(raw) > 2 * 1024 * 1024:
                    skipped.append(relative)
                    continue
            except OSError:
                skipped.append(relative)
                continue
            content = raw.decode("utf-8", errors="replace")
            digest = hashlib.sha256(raw).hexdigest()
            for rule, pattern, request in RULES:
                for match in pattern.finditer(content):
                    findings.append({"rule": rule, "file": relative,
                                     "line": content.count("\n", 0, match.start()) + 1,
                                     "sha256": digest, "request": request})
                    if len(findings) >= 10000:
                        raise PolicyError("수정 요청 수 한도를 초과했습니다. 하위 경로별로 검사하세요.")
    return {"product": "AsylumEnforce / phese (폐쇄!)", "mode": "request-only",
            "source_modified": False, "files_scanned": count, "skipped": skipped,
            "limitations": "정적 휴리스틱으로 주석/문자열 오탐 및 동적 호출 누락이 있습니다. 비밀값/소스 본문은 기록하지 않습니다.",
            "requests": findings}


def absolute_without_symlinks(value):
    """Normalize a spelling without dereferencing any path component."""
    path = Path(value).expanduser()
    if ".." in path.parts:
        raise PolicyError("보호 경로에 '..'는 허용하지 않습니다.")
    return path if path.is_absolute() else Path.cwd() / path


def pin_path(path, *, directory=False, dir_fd=None):
    """Open each component relative to its pinned parent; never follow symlinks."""
    path = Path(path)
    if ".." in path.parts or (dir_fd is not None and path.is_absolute()):
        raise PolicyError("앱 기준의 안전한 하위 경로가 필요합니다.")
    if dir_fd is None:
        if not path.is_absolute():
            raise PolicyError("절대 보호 경로가 필요합니다.")
        descriptor = os.open("/", os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
        parts = path.parts[1:]
    else:
        descriptor = os.dup(dir_fd)
        parts = path.parts
    try:
        for index, component in enumerate(parts):
            flags = os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC
            if directory or index < len(parts) - 1:
                flags |= os.O_DIRECTORY
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        mode = os.fstat(descriptor).st_mode
        if not (stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode)):
            raise PolicyError("보호 경로의 파일 형식이 올바르지 않습니다.")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


class SandboxCommand:
    """Own all mount-source descriptors until bubblewrap has consumed them."""

    def __init__(self):
        self.argv = []
        self.pass_fds = []
        self.php_fd = None
        self.extension_fd = None

    def pin(self, path, **kwargs):
        descriptor = pin_path(path, **kwargs)
        self.pass_fds.append(descriptor)
        return descriptor

    def close(self):
        while self.pass_fds:
            os.close(self.pass_fds.pop())

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


def sandbox_command(args, php, extension):
    command = SandboxCommand()
    try:
        _sandbox_command(command, args, php, extension)
        return command
    except BaseException:
        command.close()
        raise


def _sandbox_command(command, args, php, extension):
    bwrap = shutil.which("bwrap")
    if not bwrap:
        raise PolicyError("bubblewrap(bwrap)가 필요합니다. 격리 없이 실행하지 않습니다.")
    app = absolute_without_symlinks(args.app)
    if app == Path("/"):
        raise PolicyError("애플리케이션 디렉터리를 지정하세요.")
    script = absolute_without_symlinks(app / args.script)
    if not script.is_relative_to(app) or script == app:
        raise PolicyError("스크립트는 앱 경로 안에 있어야 합니다.")
    if app in {Path("/usr"), Path("/etc"), Path("/proc"), Path("/dev"), Path("/tmp")}:
        raise PolicyError("시스템 루트를 앱 경로로 쓸 수 없습니다.")
    if app.is_relative_to(Path("/phese")):
        raise PolicyError("/phese는 보호 런타임의 예약 경로입니다.")
    app_fd = command.pin(app, directory=True)
    # Validate through the same app inode used by the mount, even if the host
    # replaces the application's pathname while setup is in progress.
    script_fd = pin_path(script.relative_to(app), dir_fd=app_fd)
    os.close(script_fd)
    command.php_fd = command.pin(absolute_without_symlinks(php))
    command.extension_fd = command.pin(absolute_without_symlinks(extension))
    guard_fd = command.pin(absolute_without_symlinks(Path(__file__).resolve().with_name("guard.php")))
    argv = [bwrap, "--die-with-parent", "--new-session", "--unshare-all",
            "--cap-drop", "ALL", "--clearenv", "--ro-bind", "/usr", "/usr"]
    if args.network == "host":
        argv.append("--share-net")
    for name in ("bin", "sbin", "lib", "lib64"):
        p = Path("/") / name
        if p.is_symlink():
            argv += ["--symlink", os.readlink(p), str(p)]
        elif p.is_dir():
            argv += ["--ro-bind", str(p), str(p)]
    argv += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/etc"]
    for name in ("ld.so.cache", "ssl", "pki", "localtime"):
        p = Path("/etc") / name
        if p.exists():
            argv += ["--ro-bind", str(p), str(p)]
    if args.network == "host":
        # Explicit opt-in; no promise to stop SSRF or exfiltration in this mode.
        for name in ("resolv.conf", "hosts", "nsswitch.conf"):
            p = Path("/etc") / name
            if p.exists():
                argv += ["--ro-bind", str(p), str(p)]
    argv += ["--ro-bind-fd", str(app_fd), str(app)]
    for value in args.write:
        path = absolute_without_symlinks(value)
        if not path.is_relative_to(app) or path == app:
            raise PolicyError("쓰기 경로는 앱 내부의 명시적인 하위 디렉터리여야 합니다.")
        write_fd = command.pin(path.relative_to(app), directory=True, dir_fd=app_fd)
        argv += ["--bind-fd", str(write_fd), str(path)]
    # Fixed destinations are mounted last: an app mount must never hide the
    # already-checked runtime or extension behind a mutable host pathname.
    argv += ["--dir", "/phese", "--ro-bind-fd", str(command.php_fd), "/phese/php",
             "--ro-bind-fd", str(command.extension_fd), "/phese/phese.so",
             "--ro-bind-fd", str(guard_fd), "/phese/guard.php"]
    if os.getuid() == 0:
        argv += ["--uid", "65534", "--gid", "65534"]
    argv += ["--setenv", "PATH", "/usr/bin:/bin", "--setenv", "HOME", "/tmp",
             "--setenv", "TMPDIR", "/tmp", "--setenv", "PHP_INI_SCAN_DIR", "/nonexistent",
             "--chdir", str(app), "--", "/phese/php", "-n",
             "-d", "extension=/phese/phese.so", "-d", "ffi.enable=false",
             "-d", "auto_prepend_file=/phese/guard.php",
             "-d", "enable_dl=0", "-d", "allow_url_include=0",
             "-d", "session.upload_progress.enabled=0", "-d", "fatal_error_backtraces=0",
             "-d", "display_errors=0", "-d", "log_errors=1", "-d", "error_log=/proc/self/fd/2",
             "-d", "session.save_path=/tmp", str(script)]
    argv += args.arguments
    command.argv = argv


def run_sandbox(command, timeout):
    # A separate session permits terminating descendants on timeout and interruption.
    # No address-space/data rlimits: they can trigger the targeted OOM bug.
    process = subprocess.Popen(command.argv, start_new_session=True, close_fds=True,
                               pass_fds=tuple(command.pass_fds), **sandbox_credentials())
    admission_id = emit("sandbox_started", "sandbox_setup_started", pid=process.pid)
    try:
        code = process.wait(timeout=timeout)
        reason = "normal_exit" if code == 0 else "signal_terminated" if code < 0 else "nonzero_exit"
        emit("sandbox_exited", reason, pid=process.pid, exit_code=code, event_id=admission_id)
        return code
    except (subprocess.TimeoutExpired, KeyboardInterrupt):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        emit("sandbox_exited", "sandbox_timeout", pid=process.pid, exit_code=-signal.SIGKILL,
             event_id=admission_id)
        raise PolicyError("격리 실행 시간 제한 또는 사용자 중단으로 종료했습니다.")


def sandbox_credentials():
    # --uid only chooses the identity *inside* bwrap's user namespace. When
    # launched as root it otherwise maps that identity back to host UID 0.
    return {"user": 65534, "group": 65534, "extra_groups": ()} if os.getuid() == 0 else {}


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "setup":
        from .setup import main as setup_main
        return setup_main(argv[1:])
    if argv and argv[0] == "start":
        from .setup import configured_main
        return configured_main(argv[1:])
    if argv and argv[0] in {"install", "bootstrap"}:
        from .setup import bootstrap_main
        return bootstrap_main(argv[1:])
    if argv and argv[0] == "page":
        from .pages import main as page_main
        return page_main(argv[1:])
    parser = argparse.ArgumentParser(description="AsylumEnforce / phese (폐쇄!) 방어 CLI")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("setup", help="앱 자동 탐지와 Codex/Claude 프로젝트 지침 설정")
    commands.add_parser("start", help="저장한 앱 설정으로 폐쇄적 환경 실행")
    commands.add_parser("install", help="일치하는 네이티브 확장과 CLI 빌드·설치")
    commands.add_parser("page", help="테마 JSON으로 차단 페이지와 CSP 생성")
    doctor = commands.add_parser("doctor", help="PHP 버전 및 보호 확장 확인")
    doctor.add_argument("--php", default=shutil.which("php") or "/usr/bin/php")
    doctor.add_argument("--extension")
    request = commands.add_parser("scan", help="PHP 소스를 변경하지 않고 로컬 수정 요청 생성")
    request.add_argument("app")
    request.add_argument("--output", required=True)
    run = commands.add_parser("run", help="고정 버전 + 네이티브 확장 + OS 격리로 CLI 실행")
    run.add_argument("--php", default=shutil.which("php") or "/usr/bin/php")
    run.add_argument("--extension", required=True)
    run.add_argument("--app", required=True)
    run.add_argument("--write", action="append", default=[])
    run.add_argument("--network", choices=["none", "host"], default="none")
    run.add_argument("--timeout", type=int, default=60)
    run.add_argument("script")
    run.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            root = Path(args.app).resolve(strict=True)
            if not root.is_dir():
                raise PolicyError("앱 디렉터리가 필요합니다.")
            destination = Path(args.output).absolute()
            # A report must never overwrite application source or data, including
            # a non-PHP file and a path reached through a symlinked parent.
            if destination.resolve().is_relative_to(root):
                raise PolicyError("수정 요청 출력 경로는 앱 디렉터리 밖이어야 합니다.")
            report = scan(root)
            private_json(args.output, report)
            print(json.dumps({"output": str(Path(args.output).absolute()),
                              "requests": len(report["requests"]), "source_modified": False}, ensure_ascii=False))
            return 0
        if args.command == "doctor":
            php = resolve_file(args.php)
            info = php_info(php)
            if args.extension:
                require_fixed(info)
                extension = resolve_file(args.extension)
                probe = execute([str(php), "-n", "-d", f"extension={extension}", "-r", STATUS_CODE])
                info["phese"] = json.loads(probe.stdout)
                if not protected_status(info["phese"]):
                    raise PolicyError("phese 확장 로드/상태 확인 실패")
            print(json.dumps(info, ensure_ascii=False, indent=2))
            return 0 if info["cve_2026_109618_109619_version_gate"] else 2
        if not 1 <= args.timeout <= 86400:
            raise PolicyError("실행 제한은 1~86400초로 지정하세요.")
        with sandbox_command(args, args.php, args.extension) as command:
            # Probe exactly the pinned inodes subsequently mounted by bubblewrap.
            # A pathname replacement cannot substitute another PHP or module.
            php = f"/proc/self/fd/{command.php_fd}"
            extension = f"/proc/self/fd/{command.extension_fd}"
            probe_fds = (command.php_fd, command.extension_fd)
            require_fixed(php_info(php, pass_fds=probe_fds))
            probe = execute([php, "-n", "-d", f"extension={extension}", "-r", STATUS_CODE],
                            pass_fds=probe_fds)
            if not protected_status(json.loads(probe.stdout)):
                raise PolicyError("phese 네이티브 보호가 확인되지 않아 실행을 거부합니다.")
            return run_sandbox(command, args.timeout)
    except (PolicyError, OSError, ValueError, subprocess.SubprocessError) as error:
        if args.command == "run":
            emit("policy_denied", "policy_check_failed")
        # Subprocess stderr can contain host config details; keep CLI errors narrow.
        message = str(error) if isinstance(error, PolicyError) else type(error).__name__
        print(f"phese: {message}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
