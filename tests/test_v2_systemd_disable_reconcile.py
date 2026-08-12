from __future__ import annotations

import json
import os
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

import nas_v2_systemd_reconcile as reconcile  # noqa: E402


class V2SystemdDisableReconcileTests(unittest.TestCase):
    def make_systemctl(self, root: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
        log = root / "systemctl.log"
        script = root / "systemctl"
        script.write_text(
            '#!/bin/sh\nprintf "%s\\n" "$*" >> "$NAS_V2_SYSTEMCTL_LOG"\nexit 0\n',
            encoding="utf-8",
        )
        script.chmod(script.stat().st_mode | stat.S_IXUSR)
        return script, log

    def write_manifest(
        self,
        path: pathlib.Path,
        source: pathlib.Path | None,
        *,
        enabled: bool,
    ) -> None:
        present = source is not None
        owned = ["nas-v2-demo.service"] if present else []
        path.write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "links": [] if source is None else [{"target": "nas-v2-demo.service", "source": str(source)}],
                    "quadletLinks": [],
                    "ownedUnits": owned,
                    "startUnits": owned if enabled else [],
                    "stopUnits": [] if enabled or not present else owned,
                    "fingerprints": {} if not present else {"nas-v2-demo.service": "runtime-v1"},
                }
            ),
            encoding="utf-8",
        )

    def run(
        self,
        *,
        manifest: pathlib.Path,
        projection: pathlib.Path,
        runtime: pathlib.Path,
        quadlet_runtime: pathlib.Path,
        state: pathlib.Path,
        systemctl: pathlib.Path,
        log: pathlib.Path,
    ) -> dict[str, object]:
        with mock.patch.dict(os.environ, {"NAS_V2_SYSTEMCTL_LOG": str(log)}):
            return reconcile.reconcile(
                manifest_path=manifest,
                projection_root=projection,
                systemd_runtime_dir=runtime,
                quadlet_runtime_dir=quadlet_runtime,
                state_path=state,
                systemctl=str(systemctl),
            )

    def test_persistent_to_disabled_to_removed_never_restarts_disabled_unit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            projection = root / "projection"
            units = projection / "units"
            units.mkdir(parents=True)
            source = units / "nas-v2-demo.service"
            source.write_text("[Service]\nExecStart=/bin/true\n", encoding="utf-8")
            manifest = projection / "manifest.json"
            runtime = root / "systemd"
            runtime.mkdir()
            quadlet_runtime = root / "quadlet"
            quadlet_runtime.mkdir()
            state = root / "state.json"
            systemctl, log = self.make_systemctl(root)

            self.write_manifest(manifest, source, enabled=True)
            self.run(
                manifest=manifest,
                projection=projection,
                runtime=runtime,
                quadlet_runtime=quadlet_runtime,
                state=state,
                systemctl=systemctl,
                log=log,
            )
            self.assertTrue((runtime / "nas-v2-demo.service").is_symlink())

            log.write_text("", encoding="utf-8")
            self.write_manifest(manifest, source, enabled=False)
            disabled = self.run(
                manifest=manifest,
                projection=projection,
                runtime=runtime,
                quadlet_runtime=quadlet_runtime,
                state=state,
                systemctl=systemctl,
                log=log,
            )
            commands = log.read_text(encoding="utf-8")
            self.assertEqual(disabled["stopped"], ["nas-v2-demo.service"])
            self.assertIn("stop nas-v2-demo.service", commands)
            self.assertNotIn("start nas-v2-demo.service", commands)
            self.assertNotIn("restart nas-v2-demo.service", commands)
            self.assertTrue((runtime / "nas-v2-demo.service").is_symlink())

            log.write_text("", encoding="utf-8")
            self.write_manifest(manifest, None, enabled=False)
            removed = self.run(
                manifest=manifest,
                projection=projection,
                runtime=runtime,
                quadlet_runtime=quadlet_runtime,
                state=state,
                systemctl=systemctl,
                log=log,
            )
            commands = log.read_text(encoding="utf-8")
            self.assertEqual(removed["stopped"], ["nas-v2-demo.service"])
            self.assertIn("stop nas-v2-demo.service", commands)
            self.assertNotIn("start nas-v2-demo.service", commands)
            self.assertNotIn("restart nas-v2-demo.service", commands)
            self.assertFalse((runtime / "nas-v2-demo.service").exists())


if __name__ == "__main__":
    unittest.main()
