from __future__ import annotations

import pathlib
import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
_SPEC = importlib.util.spec_from_file_location(
    "check_architecture_boundary", SCRIPTS / "check-architecture-boundary.py"
)
assert _SPEC is not None and _SPEC.loader is not None
boundary = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(boundary)


class ArchitectureBoundaryTests(unittest.TestCase):
    def test_generic_v2_paths_do_not_name_installed_applications(self) -> None:
        self.assertEqual(boundary.violations(), [])

    def test_scanner_detects_application_names_in_a_generic_path(self) -> None:
        source = ROOT / "services" / "nas_v2_systemd_native.py"
        original = source.read_text(encoding="utf-8")
        try:
            source.write_text(original + "\n# syncthing\n", encoding="utf-8")
            found = boundary.violations((source,))
        finally:
            source.write_text(original, encoding="utf-8")
        self.assertEqual(
            [(path, name) for path, name, _line in found],
            [(pathlib.Path("services/nas_v2_systemd_native.py"), "syncthing")],
        )

    def test_scan_fails_when_a_required_generic_path_is_missing(self) -> None:
        missing = ROOT / "services" / "nas_v2_does_not_exist.py"
        self.assertFalse(missing.exists())
        with self.assertRaises(SystemExit) as raised:
            boundary.violations((missing,))
        self.assertIn("missing generic path", str(raised.exception))
        self.assertIn(str(missing), str(raised.exception))

    def test_required_module_registry_matches_the_services_directory(self) -> None:
        on_disk = {path.name for path in (ROOT / "services").glob("nas_v2_*.py")}
        self.assertEqual(set(boundary.REQUIRED_V2_MODULES), on_disk)
        self.assertEqual(
            tuple(ROOT / "services" / name for name in boundary.REQUIRED_V2_MODULES),
            tuple(path for path in boundary.GENERIC_PATHS if path.parent == ROOT / "services"),
        )

    def test_script_fails_when_a_pinned_module_is_absent(self) -> None:
        absent = boundary.REQUIRED_V2_MODULES[0]
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            script = root / "scripts" / "check-architecture-boundary.py"
            script.parent.mkdir()
            shutil.copyfile(SCRIPTS / "check-architecture-boundary.py", script)
            services = root / "services"
            services.mkdir()
            for name in boundary.REQUIRED_V2_MODULES:
                if name != absent:
                    (services / name).write_text("", encoding="utf-8")
            for path in boundary.GENERIC_PATHS:
                if path.parent == ROOT / "services":
                    continue
                copy = root / path.relative_to(ROOT)
                copy.parent.mkdir(parents=True, exist_ok=True)
                copy.write_text("", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(script)],
                cwd=root,
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(absent, result.stderr)


if __name__ == "__main__":
    unittest.main()
