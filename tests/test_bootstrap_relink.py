from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
NAMES = ("authentik", "postgresql", "nas-secrets")


class BootstrapRelinkTests(unittest.TestCase):
    def make_paths(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = pathlib.Path(temporary.name)
        self.homes = self.root / "service homes"
        self.target = self.root / "target $literal"
        self.homes.mkdir()
        self.target.mkdir()
        for name in NAMES:
            (self.target / name).mkdir()
            (self.target / name / "authority").write_bytes(b"preserved target data\x00")

    def run_relink(self) -> subprocess.CompletedProcess[str]:
        source = (ROOT / "modules/nas/config/application-services.nix").read_text(encoding="utf-8")
        start = "for name in authentik postgresql nas-secrets; do"
        body = start + source.split(start, 1)[1].split("        done", 1)[0] + "done\n"
        self.assertEqual(body.count('destination="/var/lib/$name"'), 1)
        body = body.replace('destination="/var/lib/$name"', 'destination="$TEST_SERVICE_ROOT/$name"')
        body = body.replace("${pkgs.coreutils}/bin/", "")
        result = subprocess.run(
            ["bash", "--noprofile", "--norc", "-c", 'set -euo pipefail\ntarget="$TEST_TARGET"\n' + body],
            env={
                "PATH": os.environ["PATH"],
                "TEST_SERVICE_ROOT": str(self.homes),
                "TEST_TARGET": str(self.target),
            },
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        for name in NAMES:
            self.assertEqual((self.target / name / "authority").read_bytes(), b"preserved target data\x00")
        return result

    def assert_linked(self) -> None:
        for name in NAMES:
            self.assertTrue((self.homes / name).is_symlink())
            self.assertEqual((self.homes / name).resolve(), self.target / name)

    def test_missing_paths_are_linked_and_repeated_boot_is_safe(self) -> None:
        self.make_paths()
        for _ in range(2):
            result = self.run_relink()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assert_linked()

    def test_empty_directories_are_replaced(self) -> None:
        self.make_paths()
        for name in NAMES:
            (self.homes / name).mkdir()
        result = self.run_relink()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_linked()

    def test_symlinks_are_replaced_without_touching_their_targets(self) -> None:
        self.make_paths()
        legacy = self.root / "legacy"
        legacy.mkdir()
        sentinel = legacy / "authority"
        sentinel.write_bytes(b"preserved legacy data\x00")
        for name in NAMES:
            (self.homes / name).symlink_to(legacy)
        result = self.run_relink()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_linked()
        self.assertEqual(sentinel.read_bytes(), b"preserved legacy data\x00")

    def test_broken_symlinks_are_replaced(self) -> None:
        self.make_paths()
        for name in NAMES:
            (self.homes / name).symlink_to(self.root / "missing")
        result = self.run_relink()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_linked()

    def test_populated_directories_fail_closed_without_losing_data(self) -> None:
        for name in reversed(NAMES):
            with self.subTest(name=name):
                self.make_paths()
                directory = self.homes / name
                directory.mkdir()
                sentinel = directory / "authority"
                sentinel.write_bytes(b"preserved preexisting data\x00")
                result = self.run_relink()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"Refusing to replace populated service data at {directory}", result.stderr)
                self.assertFalse(directory.is_symlink())
                self.assertEqual(sentinel.read_bytes(), b"preserved preexisting data\x00")

    def test_regular_files_fail_closed_without_losing_data(self) -> None:
        for name in reversed(NAMES):
            with self.subTest(name=name):
                self.make_paths()
                path = self.homes / name
                path.write_bytes(b"preserved regular file\x00")
                result = self.run_relink()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"Refusing to replace unexpected service data at {path}", result.stderr)
                self.assertFalse(path.is_symlink())
                self.assertEqual(path.read_bytes(), b"preserved regular file\x00")


if __name__ == "__main__":
    unittest.main()
