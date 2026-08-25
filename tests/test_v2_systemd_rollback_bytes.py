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


class V2SystemdRollbackBytesTests(unittest.TestCase):
    def _systemctl(self, root: pathlib.Path, *, fail_restart: bool) -> tuple[pathlib.Path, pathlib.Path]:
        log = root / ("failed-systemctl.log" if fail_restart else "systemctl.log")
        script = root / ("failed-systemctl" if fail_restart else "systemctl")
        body = '#!/bin/sh\nprintf "%s\\n" "$*" >> "$NAS_V2_SYSTEMCTL_LOG"\n'
        if fail_restart:
            body += 'if [ "$1" = restart ] && [ "$2" = nas-v2-demo.service ]; then exit 1; fi\n'
        body += 'if [ "$1" = is-active ]; then printf "active\\n"; fi\nexit 0\n'
        script.write_text(body, encoding="utf-8")
        script.chmod(script.stat().st_mode | stat.S_IXUSR)
        return script, log

    @staticmethod
    def _manifest(path: pathlib.Path, source: pathlib.Path) -> None:
        path.write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "links": [{"target": "nas-v2-demo.service", "source": str(source)}],
                    "quadletLinks": [],
                    "ownedUnits": ["nas-v2-demo.service"],
                    "startUnits": ["nas-v2-demo.service"],
                    "stopUnits": [],
                    "fingerprints": {},
                }
            ),
            encoding="utf-8",
        )

    def _run(
        self,
        *,
        manifest: pathlib.Path,
        projection: pathlib.Path,
        runtime: pathlib.Path,
        quadlet: pathlib.Path,
        state: pathlib.Path,
        systemctl: pathlib.Path,
        log: pathlib.Path,
    ) -> dict[str, object]:
        with mock.patch.dict(os.environ, {"NAS_V2_SYSTEMCTL_LOG": str(log)}):
            return reconcile.reconcile(
                manifest_path=manifest,
                projection_root=projection,
                systemd_runtime_dir=runtime,
                quadlet_runtime_dir=quadlet,
                state_path=state,
                systemctl=str(systemctl),
            )

    def test_restart_failure_restores_runtime_link_without_mutating_generations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            control = root / "nas-control"
            generations = control / "generations"
            generations.mkdir(parents=True)
            runtime = root / "systemd-runtime"
            runtime.mkdir()
            quadlet = root / "quadlet-runtime"
            quadlet.mkdir()
            state = control / "systemd-reconciled.json"
            projection = control / "systemd"

            old_revision = "1" * 40
            old_projection = generations / old_revision / "systemd"
            old_units = old_projection / "units"
            old_units.mkdir(parents=True)
            old_source = old_units / "nas-v2-demo.service"
            old_bytes = b"[Service]\nExecStart=/bin/true\n"
            old_source.write_bytes(old_bytes)
            old_manifest = old_projection / "manifest.json"
            self._manifest(old_manifest, old_source)
            projection.symlink_to(old_projection)

            systemctl, log = self._systemctl(root, fail_restart=False)
            self._run(
                manifest=old_manifest,
                projection=projection,
                runtime=runtime,
                quadlet=quadlet,
                state=state,
                systemctl=systemctl,
                log=log,
            )
            previous_state = state.read_bytes()
            target = runtime / "nas-v2-demo.service"
            self.assertEqual(target.resolve(), old_source.resolve())

            new_revision = "2" * 40
            new_projection = generations / new_revision / "systemd"
            new_units = new_projection / "units"
            new_units.mkdir(parents=True)
            new_source = new_units / "nas-v2-demo.service"
            new_bytes = b"[Service]\nExecStart=/bin/false\n"
            new_source.write_bytes(new_bytes)
            new_manifest = new_projection / "manifest.json"
            self._manifest(new_manifest, new_source)

            projection.unlink()
            projection.symlink_to(new_projection)
            failed_systemctl, failed_log = self._systemctl(root, fail_restart=True)
            with self.assertRaisesRegex(reconcile.SystemdReconcileError, "restart nas-v2-demo.service"):
                self._run(
                    manifest=new_manifest,
                    projection=projection,
                    runtime=runtime,
                    quadlet=quadlet,
                    state=state,
                    systemctl=failed_systemctl,
                    log=failed_log,
                )

            self.assertEqual(old_source.read_bytes(), old_bytes)
            self.assertEqual(new_source.read_bytes(), new_bytes)
            self.assertEqual(state.read_bytes(), previous_state)
            self.assertTrue(target.is_symlink())
            self.assertEqual(target.resolve(), old_source.resolve())
            self.assertFalse((old_projection / ".activated").exists())
            self.assertFalse((new_projection / ".activated").exists())


if __name__ == "__main__":
    unittest.main()
