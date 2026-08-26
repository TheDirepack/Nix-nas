from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"

sys.path.insert(0, str(SERVICES))
import nas_v2_quadlet as quadlet  # noqa: E402


class QuadletSourceSecurityTests(unittest.TestCase):
    def test_source_outside_managed_app_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            app_root = root / "apps"
            outside = root / "outside.container"
            outside.write_text("[Container]\nImage=example.invalid/test\n", encoding="utf-8")
            with mock.patch.object(quadlet, "APP_ROOT", app_root):
                with self.assertRaisesRegex(quadlet.QuadletProjectionError, "beneath its managed app root"):
                    quadlet._managed_source("svc", outside)

    def test_symlink_escape_from_managed_app_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            app_root = root / "apps"
            service_root = app_root / "svc"
            service_root.mkdir(parents=True)
            outside = root / "outside.container"
            outside.write_text("[Container]\nImage=example.invalid/test\n", encoding="utf-8")
            link = service_root / "service.container"
            link.symlink_to(outside)
            with mock.patch.object(quadlet, "APP_ROOT", app_root):
                with self.assertRaisesRegex(quadlet.QuadletProjectionError, "escapes its managed app root"):
                    quadlet._managed_source("svc", link)

    def test_regular_source_beneath_managed_app_root_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            app_root = root / "apps"
            service_root = app_root / "svc"
            service_root.mkdir(parents=True)
            source = service_root / "service.container"
            source.write_text("[Container]\nImage=example.invalid/test\n", encoding="utf-8")
            with mock.patch.object(quadlet, "APP_ROOT", app_root):
                self.assertEqual(quadlet._managed_source("svc", source), source.resolve())


if __name__ == "__main__":
    unittest.main()
