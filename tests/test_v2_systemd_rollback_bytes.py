from __future__ import annotations

import json
import os
import pathlib
import stat
import subprocess
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

    def test_rejected_apply_restores_live_owner_as_well_as_links(self) -> None:
        for failure_stage, initially_active, fail_restore in (
            (stage, active, restore)
            for stage in ("restart", "readiness", "commit", "publish", "durability")
            for active, restore in ((True, False), (False, False), (True, True), (False, True))
        ):
            with (
                self.subTest(stage=failure_stage, active=initially_active, fail_restore=fail_restore),
                tempfile.TemporaryDirectory() as raw,
            ):
                root = pathlib.Path(raw)
                control = root / "control"
                runtime = root / "units"
                quadlet = root / "quadlets"
                runtime.mkdir()
                quadlet.mkdir()
                projection = control / "systemd"
                state = control / "state.json"
                owner = "nas-v2-demo.service"
                ready = "nas-v2-ready-demo.service"
                manifests = {}
                sources = {}
                for version in ("healthy", "candidate"):
                    generation = control / "generations" / version / "systemd"
                    generation.mkdir(parents=True)
                    source = generation / "nas-v2-demo.container"
                    source.write_text(f"[Container]\nImage={version}\n")
                    gate = generation / ready
                    gate.write_text(f"[Unit]\nRequires={owner}\nAfter={owner}\n[Service]\nExecStart=/bin/true\n")
                    manifest = generation / "manifest.json"
                    manifest.write_text(
                        json.dumps(
                            {
                                "schemaVersion": 1,
                                "links": [{"target": ready, "source": str(gate)}],
                                "quadletLinks": [{"target": source.name, "source": str(source)}],
                                "ownedUnits": [owner, ready],
                                "startUnits": [owner, ready],
                                "readinessUnits": [ready],
                                "readinessOwners": {ready: owner},
                                "stopUnits": [],
                                "fingerprints": {owner: version, ready: "unchanged-probe"},
                            }
                        )
                    )
                    manifests[version] = manifest
                    sources[version] = source
                projection.symlink_to(manifests["healthy"].parent)
                running = {"version": None, "allow_candidate": False, "fail_restore": False}
                calls = []

                def systemctl(_binary, operation, *units, check=True):
                    calls.append((operation, *units))
                    code, output = 0, ""
                    if operation == "is-active":
                        active = units[0] == owner and running["version"] is not None
                        code, output = (0, "active") if active else (3, "inactive")
                    elif operation in {"restart", "start", "try-restart"} and units[0] == owner:
                        desired = (quadlet / "nas-v2-demo.container").read_text().split("Image=", 1)[1].strip()
                        if running["fail_restore"] and desired == "healthy":
                            code = 1
                        else:
                            running["version"] = desired
                            if desired == "candidate" and failure_stage == "restart":
                                code = 1
                    elif operation == "restart" and units[0] == ready:
                        code = int(running["version"] == "candidate" and not running["allow_candidate"])
                    elif operation == "stop" and units[0] == owner:
                        if running["fail_restore"]:
                            code = 1
                        else:
                            running["version"] = None
                    if code and check:
                        raise reconcile.SystemdReconcileError(f"systemctl {operation} {' '.join(units)} failed")
                    return subprocess.CompletedProcess([], code, output, "")

                def apply(manifest: pathlib.Path) -> dict[str, object]:
                    return reconcile.reconcile(
                        manifest_path=manifest,
                        projection_root=projection,
                        systemd_runtime_dir=runtime,
                        quadlet_runtime_dir=quadlet,
                        state_path=state,
                        systemctl="systemctl",
                    )

                with mock.patch.object(reconcile, "_run_systemctl", side_effect=systemctl):
                    apply(manifests["healthy"])
                    previous_state = state.read_bytes() + b"\n "
                    state.write_bytes(previous_state)
                    running["version"] = "healthy" if initially_active else None
                    running["fail_restore"] = fail_restore
                    running["allow_candidate"] = failure_stage in {"commit", "publish", "durability"}
                    projection.unlink()
                    projection.symlink_to(manifests["candidate"].parent)
                    message = (
                        "manual recovery required"
                        if fail_restore or failure_stage == "durability"
                        else (
                            "No space left"
                            if failure_stage in {"commit", "publish", "durability"}
                            else owner
                            if failure_stage == "restart"
                            else ready
                        )
                    )
                    write_state = reconcile._atomic_json
                    sync_directory = reconcile._fsync_directory
                    sync_calls = 0

                    def sync(path):
                        nonlocal sync_calls
                        sync_calls += 1
                        if failure_stage == "durability" or failure_stage == "publish" and sync_calls == 1:
                            raise OSError(28, "No space left on device")
                        sync_directory(path)

                    with (
                        mock.patch.object(reconcile, "_fsync_directory", side_effect=sync),
                        mock.patch.object(
                            reconcile,
                            "_atomic_json",
                            side_effect=OSError(28, "No space left on device")
                            if failure_stage == "commit"
                            else write_state,
                        ),
                        self.assertRaisesRegex(reconcile.SystemdReconcileError, message),
                    ):
                        apply(manifests["candidate"])
                    self.assertEqual(state.read_bytes(), previous_state)
                    self.assertEqual((quadlet / "nas-v2-demo.container").resolve(), sources["healthy"])
                    for version, source in sources.items():
                        self.assertEqual(source.read_text(), f"[Container]\nImage={version}\n")
                    if fail_restore or failure_stage == "durability":
                        continue
                    self.assertEqual(running["version"], "healthy" if initially_active else None)
                    projection.unlink()
                    projection.symlink_to(manifests["healthy"].parent)
                    calls.clear()
                    self.assertTrue(apply(manifests["healthy"])["noop"])
                    self.assertEqual(calls, [])
                    self.assertEqual(running["version"], "healthy" if initially_active else None)
                    projection.unlink()
                    projection.symlink_to(manifests["candidate"].parent)
                    running["allow_candidate"] = True
                    failure_stage = "retry"
                    apply(manifests["candidate"])
                    self.assertEqual(running["version"], "candidate")

    def test_failed_first_state_publication_restores_absence(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            projection = root / "projection"
            projection.mkdir()
            source = projection / "nas-v2-demo.service"
            source.write_text("[Service]\nExecStart=/bin/true\n")
            manifest = projection / "manifest.json"
            self._manifest(manifest, source)
            state = root / "state.json"
            active = set()

            def systemctl(_binary, operation, *units, check=True):
                if operation in {"start", "restart"}:
                    active.add(units[0])
                elif operation == "stop":
                    active.discard(units[0])
                output = "active" if units and units[0] in active else "inactive"
                return subprocess.CompletedProcess([], 0, output, "")

            sync = reconcile._fsync_directory
            with (
                mock.patch.object(reconcile, "_run_systemctl", side_effect=systemctl),
                mock.patch.object(reconcile, "_fsync_directory", side_effect=[OSError("sync failed"), None]),
                self.assertRaisesRegex(reconcile.SystemdReconcileError, "sync failed"),
            ):
                reconcile.reconcile(
                    manifest_path=manifest,
                    projection_root=projection,
                    systemd_runtime_dir=root / "runtime",
                    quadlet_runtime_dir=root / "quadlets",
                    state_path=state,
                    systemctl="systemctl",
                )
            self.assertFalse(state.exists())
            self.assertFalse(active)
            self.assertFalse((root / "runtime" / source.name).exists())
            sync(root)

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
