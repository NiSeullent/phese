#!/usr/bin/env python3
"""Install only the administration CLI; no service mutation or PHP replacement."""
import os
import hashlib
import json
from pathlib import Path
import shutil
import stat
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
LIB = Path("/usr/local/lib/asylumenforce")
BIN = Path("/usr/local/bin/phese")
MARKER = "# AsylumEnforce managed CLI launcher"
REQUIRED = {"__init__.py", "__main__.py", "cli.py", "events.py", "setup.py",
            "pages.py", "guard.php", "assets/__init__.py", "assets/theme.json",
            "assets/blocked.template.html"}


def trusted_path(path):
    for part in [*reversed(path.parents), path]:
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if (stat.S_ISLNK(info.st_mode) or info.st_uid != 0
                or info.st_mode & 0o022):
            raise SystemExit(f"설치 경로는 root 소유이며 다른 사용자가 쓸 수 없어야 합니다: {part}")


def main():
    if os.getuid() != 0:
        raise SystemExit("root 권한이 필요합니다. 설치 없이 python3 -m phese 를 사용할 수 있습니다.")
    trusted_path(ROOT)
    for path in (LIB, LIB / "phese", BIN):
        trusted_path(path)
    if BIN.exists() and MARKER not in BIN.read_text():
        raise SystemExit("기존 phese 명령이 이 설치 프로그램 소유가 아니므로 덮어쓰지 않습니다.")
    LIB.mkdir(mode=0o755, parents=True, exist_ok=True)
    LIB.chmod(0o755)
    # Install immutable, content-addressed code first, then atomically switch the
    # launcher. Running commands keep the previous complete package on upgrade.
    files = {}
    for source in sorted((ROOT / "phese").rglob("*")):
        if source.is_symlink():
            raise SystemExit("소스 배포본의 심볼릭 링크는 허용하지 않습니다.")
        if not source.is_file() or "__pycache__" in source.parts:
            continue
        if source.suffix not in {".py", ".php", ".html", ".json"}:
            continue
        trusted_path(source)
        files[str(source.relative_to(ROOT / "phese"))] = source.read_bytes()
    if not REQUIRED.issubset(files):
        raise SystemExit("필수 CLI 모듈 또는 페이지 자산이 없는 불완전한 소스 배포본입니다.")
    for name, data in files.items():
        if name.endswith(".py"):
            try:
                compile(data, name, "exec")
            except (SyntaxError, ValueError):
                raise SystemExit("소스 배포본의 Python 구문 검사가 실패했습니다.") from None
    digest = hashlib.sha256()
    for name, data in files.items():
        digest.update(name.encode() + b"\0" + data + b"\0")
    releases = LIB / "releases"
    trusted_path(releases)
    releases.mkdir(mode=0o755, exist_ok=True)
    releases.chmod(0o755)
    release = releases / digest.hexdigest()
    trusted_path(release)
    expected = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
    if release.exists():
        manifest = release / "manifest.json"
        trusted_path(manifest)
        if not manifest.is_file() or json.loads(manifest.read_text()) != expected:
            raise SystemExit("설치된 코드의 manifest가 일치하지 않습니다.")
        for name, wanted in expected.items():
            installed = release / "phese" / name
            trusted_path(installed)
            if hashlib.sha256(installed.read_bytes()).hexdigest() != wanted:
                raise SystemExit("설치된 코드의 무결성 검사가 실패했습니다.")
    else:
        temporary = Path(tempfile.mkdtemp(prefix=".stage-", dir=releases))
        try:
            temporary.chmod(0o755)
            (temporary / "phese").mkdir(mode=0o755)
            (temporary / "phese").chmod(0o755)
            for name, data in files.items():
                destination = temporary / "phese" / name
                destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                for parent in destination.parents:
                    if parent == temporary:
                        break
                    parent.chmod(0o755)
                destination.write_bytes(data)
                destination.chmod(0o644)
            manifest = temporary / "manifest.json"
            manifest.write_text(json.dumps(expected, sort_keys=True) + "\n")
            manifest.chmod(0o644)
            os.rename(temporary, release)
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)
    launcher = '#!/usr/bin/python3 -I\n' + MARKER + '\nimport sys\nsys.path.insert(0, ' + repr(str(release)) + ')\nfrom phese.cli import main\nraise SystemExit(main())\n'
    BIN.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    descriptor, staged = tempfile.mkstemp(prefix=".phese-", dir=BIN.parent)
    try:
        with os.fdopen(descriptor, "w") as handle:
            handle.write(launcher)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(staged, 0o755)
        os.replace(staged, BIN)
    finally:
        if os.path.exists(staged):
            os.unlink(staged)
    print("phese CLI 설치 완료: /usr/local/bin/phese (서버 서비스 적용은 별도)")


if __name__ == "__main__":
    main()
