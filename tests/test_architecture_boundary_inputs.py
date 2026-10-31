from __future__ import annotations

import importlib.util
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/check-architecture-boundary.py"
REQUIRED = (
    "modules/nas/config/managed-services.nix",
    "modules/nas/config/managed-services-lifecycle.nix",
    "modules/nas/config/managed-services-transactions.nix",
    "modules/nas/config/managed-services-network-platform.nix",
    "modules/nas/config/managed-services-authentik-blueprint.nix",
    "modules/nas/config/managed-services-compose-import.nix",
)


class ArchitectureBoundaryInputTests(unittest.TestCase):
    def run_fixture(
        self, *, missing: str | None = None, directory: bool = False, python_files: int = 2, application: bool = False
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            (root / "scripts").mkdir()
            shutil.copy2(SCRIPT, root / "scripts" / SCRIPT.name)
            for relative in REQUIRED:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                if relative == missing:
                    if directory:
                        target.mkdir()
                else:
                    target.write_text("{ ... }: {}\n")
            (root / "services").mkdir()
            for index in range(python_files):
                (root / f"services/nas_v2_fixture_{index}.py").write_text(
                    "# syncthing\n" if application and index == 0 else "# Generic source\n"
                )
            return subprocess.run(
                [sys.executable, str(root / "scripts" / SCRIPT.name)],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

    def test_missing_required_module_fails_without_a_success_banner(self) -> None:
        for relative in REQUIRED:
            with self.subTest(relative=relative):
                result = self.run_fixture(missing=relative)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn(relative, result.stderr)
                self.assertIn("missing", result.stderr.lower())
                self.assertNotIn("architecture boundary ok", result.stdout)

    def test_directory_cannot_replace_a_required_file(self) -> None:
        result = self.run_fixture(missing=REQUIRED[0], directory=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(REQUIRED[0], result.stderr)
        self.assertNotIn("architecture boundary ok", result.stdout)

    def test_empty_generic_python_discovery_is_fatal(self) -> None:
        result = self.run_fixture(python_files=0)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("services/nas_v2_*.py", result.stderr)
        self.assertNotIn("architecture boundary ok", result.stdout)

    def test_valid_fixture_reports_the_number_of_checked_files(self) -> None:
        result = self.run_fixture()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("architecture boundary ok: 8 generic paths", result.stdout)
        self.assertEqual(result.stderr, "")

    def test_existing_application_name_detection_remains_fatal(self) -> None:
        result = self.run_fixture(application=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("services/nas_v2_fixture_0.py:1: syncthing", result.stderr)
        self.assertNotIn("architecture boundary ok", result.stdout)

    def test_explicit_missing_path_is_reported_as_a_violation(self) -> None:
        spec = importlib.util.spec_from_file_location("boundary_input_fixture", SCRIPT)
        assert spec is not None and spec.loader is not None
        boundary = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(boundary)
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            missing = root / "missing.py"
            with mock.patch.object(boundary, "ROOT", root):
                found = boundary.violations((missing,))
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0][0], pathlib.Path("missing.py"))
        self.assertIn("missing", found[0][1].lower())
