"""Installer release transactions in a temporary prefix; never /usr/local.

The root admission check is simulated for unprivileged CI. Its fixture trust
boundary still rejects symlinks, foreign ownership and writable components, and
asserts that every path presented to the installer remains inside the prefix.
"""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).absolute().parents[1] / "tools/install_cli.py"
SPEC = importlib.util.spec_from_file_location("phese_install_cli_test", SOURCE)
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


class InstallCLITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="phese-installer-fixture-")
        self.base = Path(self.tmp.name)
        self.uid = self.base.lstat().st_uid
        self.source = self.base / "source"
        self.library = self.base / "install/lib/asylumenforce"
        self.launcher = self.base / "install/bin/phese"
        self.package = self.source / "phese"
        self.package.mkdir(parents=True)
        self.write_source("__init__.py", "# fixture package\n")
        self.write_source("__main__.py", "from .cli import main\nraise SystemExit(main())\n")
        self.write_source("cli.py", self.cli_source("release-one"))
        self.write_source("guard.php", "<?php /* fixture guard */\n")
        for module in ("events.py", "setup.py", "pages.py", "assets/__init__.py"):
            self.write_source(module, "# fixture dependency\n")
        self.write_source("assets/blocked.template.html", "<!doctype html><p>fixture</p>\n")
        self.write_source("assets/theme.json", '{"fixture":true}\n')
        self.stack = contextlib.ExitStack()
        self.stack.enter_context(patch.multiple(installer, ROOT=self.source,
                                                LIB=self.library, BIN=self.launcher))
        self.stack.enter_context(patch.object(installer.os, "getuid", return_value=0))
        self.stack.enter_context(patch.object(installer, "trusted_path", side_effect=self.fixture_trust))

    def tearDown(self):
        self.stack.close()
        self.tmp.cleanup()

    @staticmethod
    def cli_source(label):
        return f'def main():\n    print({label!r})\n    return 0\n'

    def write_source(self, relative, text):
        path = self.package / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        path.chmod(0o644)
        return path

    def fixture_trust(self, value):
        path = Path(value)
        try:
            relative = path.relative_to(self.base)
        except ValueError as exc:
            raise AssertionError("installer escaped the temporary prefix") from exc
        current = self.base
        for part in (None, *relative.parts):
            if part is not None:
                current /= part
            try:
                info = current.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(info.st_mode) or info.st_uid != self.uid or info.st_mode & 0o022:
                raise SystemExit("fixture root trust check rejected input")

    def install(self):
        with contextlib.redirect_stdout(io.StringIO()):
            installer.main()

    def releases(self):
        directory = self.library / "releases"
        return sorted(path for path in directory.iterdir() if path.is_dir() and not path.name.startswith("."))

    def run_launcher(self):
        result = subprocess.run([sys.executable, "-I", str(self.launcher)],
                                capture_output=True, text=True, timeout=10, check=True)
        return result.stdout.strip()

    def test_identical_source_reuses_one_immutable_release(self):
        self.install()
        release = self.releases()[0]
        original = {path.relative_to(release): (path.read_bytes(), path.stat().st_ino)
                    for path in release.rglob("*") if path.is_file()}
        launcher = self.launcher.read_bytes()
        self.install()
        self.assertEqual(self.releases(), [release])
        self.assertRegex(release.name, r"^[a-f0-9]{64}$")
        self.assertEqual(self.launcher.read_bytes(), launcher)
        for relative, (data, inode) in original.items():
            self.assertEqual((release / relative).read_bytes(), data)
            self.assertEqual((release / relative).stat().st_ino, inode)
        self.assertEqual(self.run_launcher(), "release-one")

    def test_upgrade_publishes_complete_new_release_before_atomic_launcher_switch(self):
        self.install()
        old_release = self.releases()[0]
        old_launcher = self.launcher.read_bytes()
        old_source = (old_release / "phese/cli.py").read_bytes()
        self.write_source("cli.py", self.cli_source("release-two"))
        real_replace = os.replace
        observed = []
        def replace(source, destination):
            self.assertEqual(Path(destination), self.launcher)
            self.assertEqual(self.launcher.read_bytes(), old_launcher)
            self.assertEqual(len(self.releases()), 2)
            self.assertEqual(self.run_launcher(), "release-one")
            for release in self.releases():
                manifest = json.loads((release / "manifest.json").read_text())
                for name, expected in manifest.items():
                    self.assertEqual(hashlib.sha256((release / "phese" / name).read_bytes()).hexdigest(), expected)
            observed.append(True)
            return real_replace(source, destination)
        with patch.object(installer.os, "replace", side_effect=replace):
            self.install()
        self.assertEqual(observed, [True])
        self.assertEqual(self.run_launcher(), "release-two")
        self.assertEqual((old_release / "phese/cli.py").read_bytes(), old_source)
        self.assertEqual(self.launcher.stat().st_mode & 0o777, 0o755)

    def test_unmanaged_launcher_is_not_overwritten(self):
        self.launcher.parent.mkdir(parents=True)
        self.launcher.write_text("#!/bin/false\n# unrelated program\n")
        before, inode = self.launcher.read_bytes(), self.launcher.stat().st_ino
        with self.assertRaises(SystemExit):
            self.install()
        self.assertEqual(self.launcher.read_bytes(), before)
        self.assertEqual(self.launcher.stat().st_ino, inode)
        self.assertFalse(self.library.exists())

    def test_installed_release_source_tampering_refuses_reinstall(self):
        self.install()
        launcher, inode = self.launcher.read_bytes(), self.launcher.stat().st_ino
        release = self.releases()[0]
        (release / "phese/cli.py").write_text("# altered installed file\n")
        with self.assertRaises(SystemExit):
            self.install()
        self.assertEqual(self.launcher.read_bytes(), launcher)
        self.assertEqual(self.launcher.stat().st_ino, inode)

    def test_installed_manifest_tampering_refuses_reinstall(self):
        self.install()
        launcher = self.launcher.read_bytes()
        (self.releases()[0] / "manifest.json").write_text("{}\n")
        with self.assertRaises(SystemExit):
            self.install()
        self.assertEqual(self.launcher.read_bytes(), launcher)

    def test_symlinked_source_file_refused_and_old_launcher_preserved(self):
        self.install()
        launcher = self.launcher.read_bytes()
        target = self.base / "outside-source.py"
        target.write_text(self.cli_source("must-never-run"))
        source = self.package / "cli.py"
        source.unlink()
        source.symlink_to(target)
        with self.assertRaises(SystemExit):
            self.install()
        self.assertEqual(self.launcher.read_bytes(), launcher)
        self.assertEqual(self.run_launcher(), "release-one")

    def test_symlinked_source_directory_is_refused_not_silently_omitted(self):
        self.install()
        launcher = self.launcher.read_bytes()
        outside = self.base / "outside-assets"
        outside.mkdir()
        (outside / "extra.py").write_text("# fixture module\n")
        (self.package / "linked-assets").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(SystemExit):
            self.install()
        self.assertEqual(self.launcher.read_bytes(), launcher)

    def test_missing_cli_entrypoint_does_not_replace_working_launcher(self):
        self.install()
        launcher = self.launcher.read_bytes()
        (self.package / "cli.py").unlink()
        with self.assertRaises(SystemExit):
            self.install()
        self.assertEqual(self.launcher.read_bytes(), launcher)
        self.assertEqual(self.run_launcher(), "release-one")

    def test_release_publication_failure_keeps_previous_launcher(self):
        self.install()
        launcher = self.launcher.read_bytes()
        self.write_source("cli.py", self.cli_source("release-two"))
        with patch.object(installer.os, "rename", side_effect=OSError("injected publication failure")):
            with self.assertRaises(OSError):
                self.install()
        self.assertEqual(self.launcher.read_bytes(), launcher)
        self.assertEqual(self.run_launcher(), "release-one")
        self.assertEqual(len(self.releases()), 1)
        self.assertEqual(list((self.library / "releases").glob(".stage-*")), [])

    def test_missing_asset_or_invalid_python_preserves_working_launcher(self):
        self.install()
        launcher = self.launcher.read_bytes()
        theme = self.package / "assets/theme.json"
        theme.unlink()
        with self.assertRaises(SystemExit):
            self.install()
        self.write_source("assets/theme.json", '{"fixture":true}\n')
        self.write_source("events.py", "def invalid(:\n")
        with self.assertRaises(SystemExit):
            self.install()
        self.assertEqual(self.launcher.read_bytes(), launcher)
        self.assertEqual(self.run_launcher(), "release-one")

    def test_launcher_switch_failure_keeps_old_release_and_retry_completes_upgrade(self):
        self.install()
        launcher = self.launcher.read_bytes()
        self.write_source("cli.py", self.cli_source("release-two"))
        with patch.object(installer.os, "replace", side_effect=OSError("injected launcher failure")):
            with self.assertRaises(OSError):
                self.install()
        self.assertEqual(self.launcher.read_bytes(), launcher)
        self.assertEqual(self.run_launcher(), "release-one")
        self.assertEqual(len(self.releases()), 2)
        self.assertEqual(list(self.launcher.parent.glob(".phese-*")), [])
        self.install()
        self.assertEqual(self.run_launcher(), "release-two")
        self.assertEqual(len(self.releases()), 2)

    def test_package_assets_are_part_of_the_release_manifest(self):
        self.install()
        release = self.releases()[0]
        manifest = json.loads((release / "manifest.json").read_text())
        self.assertIn("assets/blocked.template.html", manifest)
        self.assertIn("assets/theme.json", manifest)
        self.assertIn("guard.php", manifest)
        for name in manifest:
            self.assertEqual((release / "phese" / name).stat().st_mode & 0o777, 0o644)


if __name__ == "__main__":
    unittest.main()
