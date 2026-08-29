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


class V2SystemdReconcileTests(unittest.TestCase):
    def test_systemctl_timeout_leaves_headroom_for_the_outer_rollback_guard(self) -> None:
        completed = mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch.object(reconcile.subprocess, "run", return_value=completed) as run:
            reconcile._run_systemctl("systemctl", "restart", "nas-v2-demo.service")

        self.assertEqual(run.call_args.kwargs["timeout"], 180)

    def make_systemctl(
        self, root: pathlib.Path, *, fail_on: set[str] | None = None
    ) -> tuple[pathlib.Path, pathlib.Path]:
        fail_on = fail_on or set()
        log = root / "systemctl.log"
        script = root / "systemctl"
        body = '#!/bin/sh\nprintf "%s\\n" "$*" >> "$NAS_V2_SYSTEMCTL_LOG"\n'
        for frag in fail_on:
            body += f'if echo "$*" | grep -q "{frag}"; then exit 1; fi\n'
        body += "exit 0\n"
        script.write_text(body, encoding="utf-8")
        script.chmod(script.stat().st_mode | stat.S_IXUSR)
        return script, log

    def write_manifest(
        self,
        path: pathlib.Path,
        source: pathlib.Path | None,
        *,
        start: bool = True,
        fingerprint: str = "runtime-v1",
        quadlet_source: pathlib.Path | None = None,
    ) -> None:
        links = [] if source is None else [{"target": "nas-v2-demo.service", "source": str(source)}]
        quadlet_links = (
            [] if quadlet_source is None else [{"target": "nas-v2-demo.container", "source": str(quadlet_source)}]
        )
        present = source is not None or quadlet_source is not None
        owned = ["nas-v2-demo.service"] if present else []
        payload = {
            "schemaVersion": 1,
            "links": links,
            "quadletLinks": quadlet_links,
            "ownedUnits": owned,
            "startUnits": owned if start else [],
            "stopUnits": [],
            "fingerprints": {} if not present else {"nas-v2-demo.service": fingerprint},
        }
        path.write_text(json.dumps(payload), encoding="utf-8")

    def run_reconcile(
        self,
        *,
        manifest: pathlib.Path,
        projection: pathlib.Path,
        runtime: pathlib.Path,
        state: pathlib.Path,
        systemctl: pathlib.Path,
        log: pathlib.Path,
        quadlet_runtime: pathlib.Path | None = None,
    ) -> dict[str, object]:
        quadlet_runtime = quadlet_runtime or runtime.parent / "quadlet"
        quadlet_runtime.mkdir(parents=True, exist_ok=True)
        with mock.patch.dict(os.environ, {"NAS_V2_SYSTEMCTL_LOG": str(log)}):
            return reconcile.reconcile(
                manifest_path=manifest,
                projection_root=projection,
                systemd_runtime_dir=runtime,
                quadlet_runtime_dir=quadlet_runtime,
                state_path=state,
                systemctl=str(systemctl),
            )

    def test_reconcile_links_reloads_and_starts_without_resident_controller(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            projection = root / "projection"
            units = projection / "units"
            units.mkdir(parents=True)
            source = units / "nas-v2-demo.service"
            source.write_text("[Service]\nExecStart=/bin/true\n", encoding="utf-8")
            manifest = projection / "manifest.json"
            self.write_manifest(manifest, source)
            runtime = root / "systemd"
            runtime.mkdir()
            state = root / "state.json"
            systemctl, log = self.make_systemctl(root)

            result = self.run_reconcile(
                manifest=manifest,
                projection=projection,
                runtime=runtime,
                state=state,
                systemctl=systemctl,
                log=log,
            )

            linked = runtime / "nas-v2-demo.service"
            self.assertTrue(linked.is_symlink())
            self.assertEqual(linked.resolve(), source.resolve())
            commands = log.read_text(encoding="utf-8")
            self.assertIn("daemon-reload", commands)
            self.assertIn("restart nas-v2-demo.service", commands)
            self.assertEqual(result["started"], ["nas-v2-demo.service"])
            self.assertFalse(result["noop"])
            self.assertTrue(state.is_file())

    def test_identical_second_reconcile_is_a_true_noop(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            projection = root / "projection"
            units = projection / "units"
            units.mkdir(parents=True)
            source = units / "nas-v2-demo.service"
            source.write_text("[Service]\nExecStart=/bin/true\n", encoding="utf-8")
            manifest = projection / "manifest.json"
            self.write_manifest(manifest, source)
            runtime = root / "systemd"
            runtime.mkdir()
            state = root / "state.json"
            systemctl, log = self.make_systemctl(root)

            self.run_reconcile(
                manifest=manifest,
                projection=projection,
                runtime=runtime,
                state=state,
                systemctl=systemctl,
                log=log,
            )
            log.write_text("", encoding="utf-8")
            result = self.run_reconcile(
                manifest=manifest,
                projection=projection,
                runtime=runtime,
                state=state,
                systemctl=systemctl,
                log=log,
            )

            self.assertTrue(result["noop"])
            self.assertEqual(result["changed"], [])
            self.assertEqual(result["started"], [])
            self.assertEqual(result["stopped"], [])
            self.assertEqual(log.read_text(encoding="utf-8"), "")

    def test_runtime_fingerprint_change_restarts_without_daemon_reload(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            projection = root / "projection"
            units = projection / "units"
            units.mkdir(parents=True)
            source = units / "nas-v2-demo.service"
            source.write_text("[Service]\nExecStart=/bin/true\n", encoding="utf-8")
            manifest = projection / "manifest.json"
            self.write_manifest(manifest, source)
            runtime = root / "systemd"
            runtime.mkdir()
            state = root / "state.json"
            systemctl, log = self.make_systemctl(root)

            self.run_reconcile(
                manifest=manifest,
                projection=projection,
                runtime=runtime,
                state=state,
                systemctl=systemctl,
                log=log,
            )
            log.write_text("", encoding="utf-8")
            self.write_manifest(manifest, source, fingerprint="runtime-v2")
            result = self.run_reconcile(
                manifest=manifest,
                projection=projection,
                runtime=runtime,
                state=state,
                systemctl=systemctl,
                log=log,
            )

            commands = log.read_text(encoding="utf-8")
            self.assertIn("restart nas-v2-demo.service", commands)
            self.assertNotIn("daemon-reload", commands)
            self.assertEqual(result["changed"], ["nas-v2-demo.service"])

    def test_missing_managed_link_is_repaired_even_when_state_matches(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            projection = root / "projection"
            units = projection / "units"
            units.mkdir(parents=True)
            source = units / "nas-v2-demo.service"
            source.write_text("[Service]\nExecStart=/bin/true\n", encoding="utf-8")
            manifest = projection / "manifest.json"
            self.write_manifest(manifest, source)
            runtime = root / "systemd"
            runtime.mkdir()
            state = root / "state.json"
            systemctl, log = self.make_systemctl(root)

            self.run_reconcile(
                manifest=manifest,
                projection=projection,
                runtime=runtime,
                state=state,
                systemctl=systemctl,
                log=log,
            )
            (runtime / "nas-v2-demo.service").unlink()
            log.write_text("", encoding="utf-8")
            result = self.run_reconcile(
                manifest=manifest,
                projection=projection,
                runtime=runtime,
                state=state,
                systemctl=systemctl,
                log=log,
            )

            self.assertFalse(result["noop"])
            self.assertTrue((runtime / "nas-v2-demo.service").is_symlink())
            self.assertIn("daemon-reload", log.read_text(encoding="utf-8"))

    def test_removed_owned_unit_is_stopped_and_unlinked(self):
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
            state = root / "state.json"
            systemctl, log = self.make_systemctl(root)

            self.write_manifest(manifest, source)
            self.run_reconcile(
                manifest=manifest,
                projection=projection,
                runtime=runtime,
                state=state,
                systemctl=systemctl,
                log=log,
            )
            self.write_manifest(manifest, None)
            self.run_reconcile(
                manifest=manifest,
                projection=projection,
                runtime=runtime,
                state=state,
                systemctl=systemctl,
                log=log,
            )

            self.assertFalse((runtime / "nas-v2-demo.service").exists())
            self.assertIn("stop nas-v2-demo.service", log.read_text(encoding="utf-8"))

    def test_quadlet_source_is_linked_and_change_restarts_generated_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            projection = root / "projection"
            quadlets = projection / "quadlet"
            quadlets.mkdir(parents=True)
            source = quadlets / "nas-v2-demo.container"
            source.write_text("[Container]\nImage=demo:v1\n", encoding="utf-8")
            manifest = projection / "manifest.json"
            self.write_manifest(manifest, None, quadlet_source=source)
            runtime = root / "systemd"
            runtime.mkdir()
            quadlet_runtime = root / "containers" / "systemd"
            quadlet_runtime.mkdir(parents=True)
            state = root / "state.json"
            systemctl, log = self.make_systemctl(root)

            self.run_reconcile(
                manifest=manifest,
                projection=projection,
                runtime=runtime,
                quadlet_runtime=quadlet_runtime,
                state=state,
                systemctl=systemctl,
                log=log,
            )
            linked = quadlet_runtime / "nas-v2-demo.container"
            self.assertTrue(linked.is_symlink())
            self.assertEqual(linked.resolve(), source.resolve())

            log.write_text("", encoding="utf-8")
            source.write_text("[Container]\nImage=demo:v2\n", encoding="utf-8")
            result = self.run_reconcile(
                manifest=manifest,
                projection=projection,
                runtime=runtime,
                quadlet_runtime=quadlet_runtime,
                state=state,
                systemctl=systemctl,
                log=log,
            )
            commands = log.read_text(encoding="utf-8")
            self.assertIn("daemon-reload", commands)
            self.assertIn("restart nas-v2-demo.service", commands)
            self.assertEqual(result["changed"], ["nas-v2-demo.service"])

            log.write_text("", encoding="utf-8")
            self.write_manifest(manifest, None)
            self.run_reconcile(
                manifest=manifest,
                projection=projection,
                runtime=runtime,
                quadlet_runtime=quadlet_runtime,
                state=state,
                systemctl=systemctl,
                log=log,
            )
            self.assertFalse(linked.exists())
            self.assertIn("stop nas-v2-demo.service", log.read_text(encoding="utf-8"))

    def test_existing_non_v2_unit_or_quadlet_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            projection = root / "projection"
            units = projection / "units"
            quadlets = projection / "quadlet"
            units.mkdir(parents=True)
            quadlets.mkdir(parents=True)
            runtime = root / "systemd"
            runtime.mkdir()
            quadlet_runtime = root / "containers" / "systemd"
            quadlet_runtime.mkdir(parents=True)
            manifest = projection / "manifest.json"
            systemctl, log = self.make_systemctl(root)

            source = units / "nas-v2-demo.service"
            source.write_text("[Service]\nExecStart=/bin/true\n", encoding="utf-8")
            self.write_manifest(manifest, source)
            target = runtime / "nas-v2-demo.service"
            target.write_text("do not replace", encoding="utf-8")
            with (
                mock.patch.dict(os.environ, {"NAS_V2_SYSTEMCTL_LOG": str(log)}),
                self.assertRaisesRegex(reconcile.SystemdReconcileError, "refusing to overwrite"),
            ):
                reconcile.reconcile(
                    manifest_path=manifest,
                    projection_root=projection,
                    systemd_runtime_dir=runtime,
                    quadlet_runtime_dir=quadlet_runtime,
                    state_path=root / "state.json",
                    systemctl=str(systemctl),
                )
            self.assertEqual(target.read_text(encoding="utf-8"), "do not replace")

            target.unlink()
            quadlet_source = quadlets / "nas-v2-demo.container"
            quadlet_source.write_text("[Container]\nImage=x\n", encoding="utf-8")
            self.write_manifest(manifest, None, quadlet_source=quadlet_source)
            quadlet_target = quadlet_runtime / "nas-v2-demo.container"
            quadlet_target.write_text("do not replace", encoding="utf-8")
            with (
                mock.patch.dict(os.environ, {"NAS_V2_SYSTEMCTL_LOG": str(log)}),
                self.assertRaisesRegex(reconcile.SystemdReconcileError, "refusing to overwrite"),
            ):
                reconcile.reconcile(
                    manifest_path=manifest,
                    projection_root=projection,
                    systemd_runtime_dir=runtime,
                    quadlet_runtime_dir=quadlet_runtime,
                    state_path=root / "state.json",
                    systemctl=str(systemctl),
                )
            self.assertEqual(quadlet_target.read_text(encoding="utf-8"), "do not replace")

    def test_stop_failure_is_transactional_and_restores_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            projection = root / "projection"
            units = projection / "units"
            units.mkdir(parents=True)
            source = units / "nas-v2-demo.service"
            source.write_text("[Service]\nExecStart=/bin/true\n", encoding="utf-8")
            manifest = projection / "manifest.json"
            self.write_manifest(manifest, source)
            runtime = root / "systemd"
            runtime.mkdir()
            state = root / "state.json"
            systemctl, log = self.make_systemctl(root)
            self.run_reconcile(
                manifest=manifest,
                projection=projection,
                runtime=runtime,
                state=state,
                systemctl=systemctl,
                log=log,
            )
            before_state = state.read_text(encoding="utf-8")
            before_target = (runtime / "nas-v2-demo.service").resolve()
            self.write_manifest(manifest, None)
            fail_ctl, fail_log = self.make_systemctl(root, fail_on={"stop nas-v2-demo.service"})
            quadlet_runtime = runtime.parent / "quadlet"
            quadlet_runtime.mkdir(parents=True, exist_ok=True)
            with mock.patch.dict(os.environ, {"NAS_V2_SYSTEMCTL_LOG": str(fail_log)}):
                with self.assertRaisesRegex(reconcile.SystemdReconcileError, "stop nas-v2-demo.service"):
                    reconcile.reconcile(
                        manifest_path=manifest,
                        projection_root=projection,
                        systemd_runtime_dir=runtime,
                        quadlet_runtime_dir=quadlet_runtime,
                        state_path=state,
                        systemctl=str(fail_ctl),
                    )
            self.assertTrue((runtime / "nas-v2-demo.service").is_symlink())
            self.assertEqual((runtime / "nas-v2-demo.service").resolve(), before_target)
            self.assertEqual(state.read_text(encoding="utf-8"), before_state)

    def test_rollback_failure_reports_manual_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            projection = root / "projection"
            units = projection / "units"
            units.mkdir(parents=True)
            source = units / "nas-v2-demo.service"
            source.write_text("[Service]\nExecStart=/bin/true\n", encoding="utf-8")
            manifest = projection / "manifest.json"
            self.write_manifest(manifest, source)
            runtime = root / "systemd"
            runtime.mkdir()
            state = root / "state.json"
            systemctl, log = self.make_systemctl(root)
            self.run_reconcile(
                manifest=manifest,
                projection=projection,
                runtime=runtime,
                state=state,
                systemctl=systemctl,
                log=log,
            )
            source.write_text("[Service]\nExecStart=/bin/false\n", encoding="utf-8")
            fail_ctl, fail_log = self.make_systemctl(root, fail_on={"daemon-reload"})
            quadlet_runtime = runtime.parent / "quadlet"
            quadlet_runtime.mkdir(parents=True, exist_ok=True)
            with mock.patch.dict(os.environ, {"NAS_V2_SYSTEMCTL_LOG": str(fail_log)}):
                with self.assertRaisesRegex(reconcile.SystemdReconcileError, "manual recovery"):
                    reconcile.reconcile(
                        manifest_path=manifest,
                        projection_root=projection,
                        systemd_runtime_dir=runtime,
                        quadlet_runtime_dir=quadlet_runtime,
                        state_path=state,
                        systemctl=str(fail_ctl),
                    )


if __name__ == "__main__":
    unittest.main()
