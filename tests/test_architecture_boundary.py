from __future__ import annotations

import pathlib
import importlib.util
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


if __name__ == "__main__":
    unittest.main()
