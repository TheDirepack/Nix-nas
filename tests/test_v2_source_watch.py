from __future__ import annotations

import pathlib
import stat
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_source_watch as source_watch  # noqa: E402
import nas_v2_systemd_reconcile as reconcile  # noqa: E402


class V2SourceWatchTests(unittest.TestCase):
    def manifest(self) -> dict:
        return {
            "schemaVersion": 1,
            "links": [],
            "quadletLinks": [],
            "ownedUnits": [],
            "startUnits": [],
            "stopUnits": [],
            "fingerprints": {},
        }

    def test_managed_disabled_compose_source_stays_watched(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            app_root = root / "apps"
            service_root = app_root / "demo"
            service_root.mkdir(parents=True)
            source = service_root / "compose.yaml"
            source.write_text("services: {web: {image: test}}\n", encoding="utf-8")
            effective = {
                "services": {
                    "demo": {
                        "managed": True,
                        "enabled": False,
                        "runtime": {"type": "compose", "source": str(source)},
                    }
                }
            }
            files: dict[pathlib.Path, bytes] = {}
            manifest = self.manifest()
            output = root / "projection"
            with mock.patch.object(source_watch, "APP_ROOT", app_root):
                source_watch.augment_projection(effective, output_dir=output, files=files, manifest=manifest)

        unit_name = "nas-v2-source-demo.path"
        unit = files[output / "units" / unit_name].decode()
        self.assertIn(f'PathChanged="{source.resolve()}"', unit)
        self.assertIn("Unit=nas-managed-services-reconcile.service", unit)
        self.assertIn(unit_name, manifest["ownedUnits"])
        self.assertIn(unit_name, manifest["startUnits"])
        self.assertNotIn(unit_name, manifest["stopUnits"])

    def test_unmanaged_source_does_not_get_v2_watch(self):
        effective = {
            "services": {
                "demo": {
                    "managed": False,
                    "runtime": {"type": "compose", "source": "/var/lib/nas-control/apps/demo/compose.yaml"},
                }
            }
        }
        files: dict[pathlib.Path, bytes] = {}
        manifest = self.manifest()
        source_watch.augment_projection(
            effective,
            output_dir=pathlib.Path("/run/nas-control/systemd"),
            files=files,
            manifest=manifest,
        )
        self.assertEqual(files, {})
        self.assertEqual(manifest["ownedUnits"], [])
        self.assertEqual(manifest["startUnits"], [])

    def test_python_requirements_file_is_a_managed_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            app_root = root / "apps"
            service_root = app_root / "demo"
            service_root.mkdir(parents=True)
            requirements = service_root / "requirements.lock"
            requirements.write_text("example==1\n", encoding="utf-8")
            service = {
                "managed": True,
                "runtime": {
                    "type": "python",
                    "dependencies": {"requirementsFile": str(requirements)},
                },
            }
            with mock.patch.object(source_watch, "APP_ROOT", app_root):
                self.assertEqual(
                    source_watch.source_paths({}, "demo", service),
                    [requirements.resolve()],
                )

    def test_source_symlink_escape_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            app_root = root / "apps"
            service_root = app_root / "demo"
            service_root.mkdir(parents=True)
            outside = root / "outside.yaml"
            outside.write_text("services: {}\n", encoding="utf-8")
            source = service_root / "compose.yaml"
            source.symlink_to(outside)
            service = {
                "managed": True,
                "runtime": {"type": "compose", "source": str(source)},
            }
            with (
                mock.patch.object(source_watch, "APP_ROOT", app_root),
                self.assertRaisesRegex(source_watch.SourceWatchProjectionError, "managed app root"),
            ):
                source_watch.source_paths({}, "demo", service)

    def test_native_systemd_validation_failure_is_fatal(self):
        files = {
            pathlib.Path("/projection/units/nas-v2-source-demo.path"): b"[Path]\nPathChanged=/tmp/demo\n",
        }
        with tempfile.TemporaryDirectory() as tmp:
            validator = pathlib.Path(tmp) / "systemd-analyze"
            validator.write_text("#!/bin/sh\nexit 9\n", encoding="utf-8")
            validator.chmod(validator.stat().st_mode | stat.S_IXUSR)
            with self.assertRaisesRegex(source_watch.SourceWatchProjectionError, "rejected"):
                source_watch.validate_source_watches(files, systemd_analyze_bin=str(validator))

    def test_reconciler_safe_target_accepts_path_units(self):
        target, affected = reconcile._safe_target(
            pathlib.Path("/run/systemd/system"),
            "nas-v2-source-demo.path",
        )
        self.assertEqual(target, pathlib.Path("/run/systemd/system/nas-v2-source-demo.path"))
        self.assertEqual(affected, "nas-v2-source-demo.path")


if __name__ == "__main__":
    unittest.main()
