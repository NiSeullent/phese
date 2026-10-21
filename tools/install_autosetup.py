#!/usr/bin/env python3
"""Install the separate phese-setup entry, then run its normal setup plan.

Example: python3 tools/install_autosetup.py --install --php /path/to/php
Service changes additionally require --service, --health-check and --apply.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
LIB = Path("/usr/local/lib/asylumenforce")
BIN = Path("/usr/local/bin/phese-setup")
MARKER = "# AsylumEnforce managed setup launcher"


def safe(path, missing=False):
    if not path.is_absolute():
        raise RuntimeError("absolute installation path required")
    for item in [*reversed(path.parents), path]:
        if missing and not item.exists() and not item.is_symlink():
            continue
        info = item.lstat()
        if item.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError("installation path must be root-owned, non-symlink and not shared-writable")


def atomic(path, content, mode):
    safe(path.parent)
    safe(path, missing=True)
    descriptor, name = tempfile.mkstemp(prefix=".phese-setup-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def install():
    if os.geteuid() != 0:
        raise RuntimeError("CLI installation requires root")
    sources = [(ROOT / "tools/service_guard.py", "phese/_service_guard.py"),
               (ROOT / "policies/php-service.conf", "phese/_service_policy.conf")]
    for source in [ROOT / "tools/install_cli.py", ROOT / "phese/autosetup.py", *(row[0] for row in sources)]:
        safe(source)
        if not source.is_file():
            raise RuntimeError("admit the autosetup sources into the repository before installation")
    safe(BIN, missing=True)
    if BIN.exists() and (not BIN.is_file() or MARKER not in BIN.read_text()):
        raise RuntimeError("refusing to replace an unmanaged setup entry")
    # The current main installer uses immutable releases. Keep this entry's
    # backend in its own immutable release too; never mutate an existing package.
    files = {}
    for source in sorted((ROOT / "phese").rglob("*")):
        if source.is_symlink():
            raise RuntimeError("package symlinks are not allowed")
        if source.is_file() and "__pycache__" not in source.parts and source.suffix in {".py", ".php", ".json", ".html"}:
            safe(source)
            files["phese/" + str(source.relative_to(ROOT / "phese"))] = source.read_bytes()
    for source, name in sources:
        files[name] = source.read_bytes()
    hasher = hashlib.sha256()
    for name, data in sorted(files.items()):
        hasher.update(name.encode() + b"\0" + data + b"\0")
    releases = LIB / "setup-releases"
    safe(releases, missing=True)
    release = releases / hasher.hexdigest()
    safe(release, missing=True)
    expected = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
    if release.exists():
        safe(release / "manifest.json")
        if json.loads((release / "manifest.json").read_text()) != expected:
            raise RuntimeError("existing setup release manifest differs")
        for name, wanted in expected.items():
            safe(release / name)
            if hashlib.sha256((release / name).read_bytes()).hexdigest() != wanted:
                raise RuntimeError("existing setup release bytes differ")
    spec = importlib.util.spec_from_file_location("phese_existing_install_cli", ROOT / "tools/install_cli.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.main()
    releases.mkdir(mode=0o755, parents=True, exist_ok=True)
    releases.chmod(0o755)
    safe(releases)
    if not release.exists():
        staged = Path(tempfile.mkdtemp(prefix=".setup-", dir=releases))
        try:
            staged.chmod(0o755)
            for name, data in files.items():
                destination = staged / name
                destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                for parent in destination.parents:
                    if parent == staged:
                        break
                    parent.chmod(0o755)
                destination.write_bytes(data)
                destination.chmod(0o644)
            (staged / "manifest.json").write_text(json.dumps(expected, sort_keys=True) + "\n")
            (staged / "manifest.json").chmod(0o644)
            os.rename(staged, release)
        finally:
            if staged.exists():
                shutil.rmtree(staged)
    launcher = ("#!/usr/bin/python3 -I\n" + MARKER + "\nimport sys\n"
                "sys.path.insert(0, " + repr(str(release)) + ")\n"
                "from phese.autosetup import main\nraise SystemExit(main())\n")
    atomic(BIN, launcher.encode(), 0o755)
    return release


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, add_help=False)
    parser.add_argument("--install", action="store_true", help="install CLI only; does not apply service changes")
    args, remaining = parser.parse_known_args(argv)
    try:
        selected = install() if args.install else ROOT
        sys.path.insert(0, str(selected))
        from phese.autosetup import main as setup_main
        return setup_main(remaining)
    except (OSError, RuntimeError) as exc:
        print("phese-setup-install: " + (str(exc) if isinstance(exc, RuntimeError) else "installation filesystem operation failed"), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
