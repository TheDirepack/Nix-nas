from __future__ import annotations

import hashlib
import importlib.util
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from repo_test_utils import ROOT, text

SPEC = importlib.util.spec_from_file_location("manifest", ROOT / "scripts/lib/manifest.py")
assert SPEC is not None and SPEC.loader is not None
manifest = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(manifest)


class ManifestTraversalTests(unittest.TestCase):
    def test_preflight_fresh_manifest_uses_the_canonical_generator(self) -> None:
        source = text("scripts/preflight.sh")
        step = source.split('step "fresh manifest generation" ', 1)[1].split('\nstep "fresh manifest verification"', 1)[
            0
        ]
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw) / "source"
            root.mkdir()
            (root / "keep.txt").write_text("keep")
            (root / "scripts/lib").mkdir(parents=True)
            shutil.copyfile(ROOT / "scripts/lib/manifest.py", root / "scripts/lib/manifest.py")
            (root / ".ruff_cache").mkdir()
            (root / ".ruff_cache/ignored-link").symlink_to(root / "keep.txt")
            output = pathlib.Path(raw) / "fresh"
            env = {**os.environ, "repo_root": str(root), "fresh_manifest": str(output)}
            result = subprocess.run(
                ["bash", "-c", step],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            expected = pathlib.Path(raw) / "expected"
            manifest.generate_manifest(root, expected)
            self.assertEqual(output.read_text(), expected.read_text())
            self.assertIn(f"{hashlib.sha256(b'keep').hexdigest()}  ./keep.txt\n", output.read_text())
        self.assertNotIn("import hashlib", step)

    def test_ignored_directories_are_pruned_before_enumeration(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw) / "source"
            root.mkdir()
            for directory in (".git", "node_modules", ".hypothesis", ".ruff_cache", "demo.egg-info"):
                (root / directory).mkdir()
                (root / directory / "ignored").write_text("ignored")
            (root / "z.txt").write_text("z")
            (root / "sub").mkdir()
            (root / "sub/a.txt").write_text("a")
            output = pathlib.Path(raw) / "manifest"
            with mock.patch.object(os, "scandir", wraps=os.scandir) as scanned:
                manifest.generate_manifest(root, output)
            visited = {pathlib.Path(call.args[0]) for call in scanned.call_args_list}
            self.assertEqual(visited, {root, root / "sub"})
            self.assertEqual(
                [row.split("  ", 1)[1] for row in output.read_text().splitlines()], ["./sub/a.txt", "./z.txt"]
            )

    def test_unignored_directory_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw) / "source"
            root.mkdir()
            (root / "link").symlink_to(pathlib.Path(raw), target_is_directory=True)
            with self.assertRaisesRegex(SystemExit, "unsupported object: link"):
                manifest.generate_manifest(root, pathlib.Path(raw) / "manifest")
