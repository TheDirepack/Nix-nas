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
    def test_newly_disabled_session_does_not_stop_a_nonexistent_target(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            projection = root / "projection"
            projection.mkdir()
            unit = "nas-v2-session-agent.target"
            manifest = projection / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "links": [],
                        "quadletLinks": [],
                        "ownedUnits": [unit],
                        "startUnits": [],
                        "stopUnits": [unit],
                        "fingerprints": {},
                    }
                ),
                encoding="utf-8",
            )
            runtime = root / "systemd"
            runtime.mkdir()
            systemctl, log = self.make_systemctl(root)
            kwargs = dict(
                manifest=manifest,
                projection=projection,
                runtime=runtime,
                state=root / "state.json",
                systemctl=systemctl,
                log=log,
            )
            self.run_reconcile(**kwargs)
            self.assertNotIn("stop " + unit, log.read_text(encoding="utf-8"))
            # A disabled target has no unit file, even if the old state had
            # marked it for start.
            state = json.loads((root / "state.json").read_text(encoding="utf-8"))
            state["startUnits"] = [unit]
            (root / "state.json").write_text(json.dumps(state), encoding="utf-8")
            log.write_text("", encoding="utf-8")
            self.run_reconcile(**kwargs)
            self.assertNotIn("stop " + unit, log.read_text(encoding="utf-8"))

            manifest.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "links": [],
                        "quadletLinks": [],
                        "ownedUnits": [],
                        "startUnits": [],
                        "stopUnits": [],
                        "fingerprints": {},
                    }
                ),
                encoding="utf-8",
            )
            log.write_text("", encoding="utf-8")
            self.run_reconcile(**kwargs)
            self.assertNotIn("stop " + unit, log.read_text(encoding="utf-8"))

    def test_enabling_previously_disabled_session_never_stops_uninstalled_target(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            projection = root / "projection"
            units = projection / "units"
            units.mkdir(parents=True)
            unit = "nas-v2-session-agent.target"
            source = units / unit
            source.write_text("[Unit]\nDescription=Agent\n", encoding="utf-8")
            manifest = projection / "manifest.json"
            runtime = root / "systemd"
            runtime.mkdir()
            systemctl, log = self.make_systemctl(root, fail_on={f"stop {unit}"})
            kwargs = dict(
                manifest=manifest,
                projection=projection,
                runtime=runtime,
                state=root / "state.json",
                systemctl=systemctl,
                log=log,
            )
            manifest.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "links": [],
                        "quadletLinks": [],
                        "ownedUnits": [unit],
                        "startUnits": [],
                        "stopUnits": [unit],
                        "fingerprints": {},
                    }
                ),
                encoding="utf-8",
            )
            self.run_reconcile(**kwargs)
            log.write_text("", encoding="utf-8")
            manifest.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "links": [{"target": unit, "source": str(source)}],
                        "quadletLinks": [],
                        "ownedUnits": [unit],
                        "startUnits": [],
                        "stopUnits": [],
                        "fingerprints": {unit: "enabled-generation"},
                    }
                ),
                encoding="utf-8",
            )
            result = self.run_reconcile(**kwargs)
            self.assertFalse(result["noop"])
            self.assertEqual((runtime / unit).resolve(), source.resolve())
            self.assertNotIn("stop " + unit, log.read_text(encoding="utf-8"))

    def test_active_unlinked_session_is_stopped_before_enabling_new_descriptor(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            projection = root / "projection"
            units = projection / "units"
            units.mkdir(parents=True)
            unit = "nas-v2-session-agent.target"
            source = units / unit
            source.write_text("[Unit]\\nDescription=Agent\\n", encoding="utf-8")
            manifest = projection / "manifest.json"
            runtime = root / "systemd"
            runtime.mkdir()
            systemctl, log = self.make_systemctl(root)
            kwargs = dict(
                manifest=manifest, projection=projection, runtime=runtime,
                state=root / "state.json", systemctl=systemctl, log=log,
            )
            manifest.write_text(
                json.dumps({
                    "schemaVersion": 1, "links": [], "quadletLinks": [],
                    "ownedUnits": [unit], "startUnits": [], "stopUnits": [unit],
                    "fingerprints": {},
                }),
                encoding="utf-8",
            )
            self.run_reconcile(**kwargs)
            # Simulate an orphaned active unit after the disabled generation,
            # even though the manifest contains no previous target link.
            systemctl.write_text(
                '#!/bin/sh\\nprintf "%s\\\\n" "$*" >> "$NAS_V2_SYSTEMCTL_LOG"\\n'
                'if [ "$1" = is-active ]; then printf "active\\\\n"; fi\\n'
                'exit 0\\n',
                encoding="utf-8",
            )
            log.write_text("", encoding="utf-8")
            manifest.write_text(
                json.dumps({
                    "schemaVersion": 1,
                    "links": [{"target": unit, "source": str(source)}],
                    "quadletLinks": [], "ownedUnits": [unit],
                    "startUnits": [], "stopUnits": [],
                    "fingerprints": {unit: "new-descriptor"},
                }),
                encoding="utf-8",
            )
            result = self.run_reconcile(**kwargs)
            commands = log.read_text(encoding="utf-8").splitlines()
            self.assertIn("stop " + unit, commands)
            self.assertNotIn("try-restart " + unit, commands)
            self.assertNotIn("restart " + unit, commands)
            self.assertEqual(result["stopped"], [unit])
            self.assertEqual((runtime / unit).resolve(), source.resolve())
            self.assertEqual(
                json.loads((root / "state.json").read_text(encoding="utf-8"))["fingerprints"][unit],
                "new-descriptor",
            )

    def test_session_fingerprint_migration_preserves_unchanged_transients(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            generation = root / "generations" / ("a" * 40) / "systemd"
            current = root / "generations" / ("b" * 40) / "systemd"
            changed = root / "generations" / ("c" * 40) / "systemd"
            projection_link = root / "current"
            unit = "nas-v2-session-agent.target"
            for projection in (generation, current, changed):
                (projection / "units").mkdir(parents=True)
                (projection / "descriptors").mkdir()
                (projection / "units" / unit).write_text("[Unit]\nStopWhenUnneeded=yes\n", encoding="utf-8")
                (projection / "descriptors" / "agent.session.json").write_text(
                    json.dumps({"serviceId": "agent", "runArgs": ["--volume=/srv/old:/data"]}),
                    encoding="utf-8",
                )
            projection_link.symlink_to(generation)
            manifest = root / "manifest.json"
            runtime = root / "live-systemd"
            runtime.mkdir()
            state = root / "state.json"
            systemctl, log = self.make_systemctl(root)

            def run(projection, fingerprint):
                projection_link.unlink()
                projection_link.symlink_to(projection)
                manifest.write_text(
                    json.dumps(
                        {
                            "schemaVersion": 1,
                            "links": [{"target": unit, "source": str(projection / "units" / unit)}],
                            "quadletLinks": [],
                            "ownedUnits": [unit],
                            "startUnits": [],
                            "stopUnits": [],
                            "fingerprints": {unit: fingerprint},
                        }
                    ),
                    encoding="utf-8",
                )
                return self.run_reconcile(
                    manifest=manifest,
                    projection=projection_link,
                    runtime=runtime,
                    state=state,
                    systemctl=systemctl,
                    log=log,
                )

            run(generation, "legacy-hash")
            log.write_text("", encoding="utf-8")
            # A digest-format change with an identical launch descriptor
            # must preserve running sessions.
            run(current, "full-descriptor-hash")
            commands = log.read_text(encoding="utf-8")
            self.assertNotIn("stop " + unit, commands)
            self.assertNotIn("restart " + unit, commands)
            self.assertIn("full-descriptor-hash", state.read_text(encoding="utf-8"))

            # Changed mount arguments must stop the target rather than
            # restarting running transient units with stale arguments.
            (changed / "descriptors" / "agent.session.json").write_text(
                json.dumps({"serviceId": "agent", "runArgs": ["--volume=/srv/new:/data"]}),
                encoding="utf-8",
            )
            log.write_text("", encoding="utf-8")
            run(changed, "path-changed-hash")
            commands = log.read_text(encoding="utf-8")
            self.assertIn("stop " + unit, commands)
            self.assertNotIn("try-restart " + unit, commands)
            self.assertNotIn("restart " + unit, commands)

    def test_failed_reconcile_reports_transient_loss_instead_of_false_rollback(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            old = root / "generations" / ("a" * 40) / "systemd"
            new = root / "generations" / ("b" * 40) / "systemd"
            unit = "nas-v2-session-agent.target"
            for directory, image in ((old, "v1"), (new, "v2")):
                (directory / "units").mkdir(parents=True)
                (directory / "descriptors").mkdir()
                (directory / "units" / unit).write_text("[Unit]\\n", encoding="utf-8")
                (directory / "descriptors" / "agent.session.json").write_text(
                    json.dumps({"serviceId": "agent", "image": image}),
                    encoding="utf-8",
                )
            current = root / "current"
            current.symlink_to(old)
            runtime = root / "systemd"
            runtime.mkdir()
            manifest = root / "manifest.json"
            state = root / "state.json"
            systemctl, log = self.make_systemctl(root)
            active_marker = root / "active-marker"
            systemctl.write_text(
                "#!/bin/sh\n"
                'printf "%s\\n" "$*" >> "$NAS_V2_SYSTEMCTL_LOG"\n'
                'case "$1" in\n'
                "  is-active)\n"
                '    if [ -e "$NAS_V2_ACTIVE_MARKER" ]; then printf "active\\n"; else printf "inactive\\n"; fi ;;\n'
                '  stop) rm -f -- "$NAS_V2_ACTIVE_MARKER" ;;\n'
                '  start) : > "$NAS_V2_ACTIVE_MARKER" ;;\n'
                "esac\n"
                "exit 0\n",
                encoding="utf-8",
            )

            def apply(directory, digest):
                current.unlink()
                current.symlink_to(directory)
                manifest.write_text(
                    json.dumps(
                        {
                            "schemaVersion": 1,
                            "links": [{"target": unit, "source": str(directory / "units" / unit)}],
                            "quadletLinks": [],
                            "ownedUnits": [unit],
                            "startUnits": [],
                            "stopUnits": [],
                            "fingerprints": {unit: digest},
                        }
                    ),
                    encoding="utf-8",
                )
                return self.run_reconcile(
                    manifest=manifest,
                    projection=current,
                    runtime=runtime,
                    state=state,
                    systemctl=systemctl,
                    log=log,
                )

            with mock.patch.dict(os.environ, {"NAS_V2_ACTIVE_MARKER": str(active_marker)}):
                apply(old, "v1")
                log.write_text("", encoding="utf-8")
                active_marker.touch()
                before = state.read_bytes()
                with mock.patch.object(reconcile, "_atomic_json", side_effect=OSError("disk full")):
                    with self.assertRaisesRegex(reconcile.SystemdReconcileError, "manual recovery required") as error:
                        apply(new, "v2")
            self.assertIn("transient instances may have been terminated", str(error.exception))
            commands = log.read_text(encoding="utf-8").splitlines()
            self.assertIn("stop " + unit, commands)
            self.assertNotIn("start " + unit, commands)
            self.assertNotIn("restart " + unit, commands)
            self.assertNotIn("try-restart " + unit, commands)
            self.assertFalse(active_marker.exists())
            self.assertEqual(before, state.read_bytes())
            self.assertEqual((runtime / unit).resolve(), (old / "units" / unit).resolve())

    def test_on_demand_restart_failure_preserves_previous_state_and_retry(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            projection = root / "projection"
            projection.mkdir()
            source = projection / "nas-v2-demo.service"
            source.write_text("[Service]\nExecStart=/bin/true\n")
            manifest = projection / "manifest.json"
            runtime = root / "systemd"
            runtime.mkdir()
            state = root / "state.json"
            ctl, log = self.make_systemctl(root)
            self.write_manifest(manifest, source, start=False)
            kwargs = dict(
                manifest=manifest, projection=projection, runtime=runtime, state=state, systemctl=ctl, log=log
            )
            self.run_reconcile(**kwargs)
            before = state.read_bytes()
            self.write_manifest(manifest, source, start=False, fingerprint="changed")
            self.make_systemctl(root, fail_on={"try-restart"})
            with self.assertRaisesRegex(reconcile.SystemdReconcileError, "try-restart"):
                self.run_reconcile(**kwargs)
            self.assertEqual(state.read_bytes(), before)
            self.assertEqual((runtime / source.name).resolve(), source)
            self.make_systemctl(root)
            self.assertFalse(self.run_reconcile(**kwargs)["noop"])
            self.assertEqual(json.loads(state.read_text())["fingerprints"][source.name], "changed")

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

    def test_unrecorded_dropin_from_interrupted_reconcile_is_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            projection = root / "projection"
            projection.mkdir()
            manifest = projection / "manifest.json"
            self.write_manifest(manifest, None)
            runtime = root / "systemd"
            dropin_dir = runtime / "copyparty.service.d"
            dropin_dir.mkdir(parents=True)
            stale_generation = root / "generations" / ("a" * 40) / "systemd" / "units"
            stale_generation.mkdir(parents=True)
            stale_source = stale_generation / "copyparty.service.d" / "50-nas-v2.conf"
            stale_source.parent.mkdir()
            stale_source.write_text("[Unit]\n", encoding="utf-8")
            stale_link = dropin_dir / "50-nas-v2.conf"
            stale_link.symlink_to(stale_source)
            state = root / "state.json"
            state.write_text("{}\n", encoding="utf-8")
            systemctl, log = self.make_systemctl(root)

            result = self.run_reconcile(
                manifest=manifest,
                projection=projection,
                runtime=runtime,
                state=state,
                systemctl=systemctl,
                log=log,
            )

            self.assertFalse(result["noop"])
            self.assertFalse(stale_link.exists())
            self.assertFalse(dropin_dir.exists())
            self.assertIn("daemon-reload", log.read_text(encoding="utf-8"))

    def test_unrecorded_direct_v2_unit_from_interrupted_reconcile_is_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            projection = root / "projection"
            projection.mkdir()
            manifest = projection / "manifest.json"
            self.write_manifest(manifest, None)
            runtime = root / "systemd"
            runtime.mkdir()
            stale_source = root / "generations" / ("a" * 40) / "systemd" / "units" / "nas-v2-orphan.service"
            stale_source.parent.mkdir(parents=True)
            stale_source.write_text("[Service]\nExecStart=/bin/true\n", encoding="utf-8")
            stale_link = runtime / "nas-v2-orphan.service"
            stale_link.symlink_to(stale_source)
            state = root / "state.json"
            state.write_text("{}\n", encoding="utf-8")
            systemctl, log = self.make_systemctl(root)

            result = self.run_reconcile(
                manifest=manifest,
                projection=projection,
                runtime=runtime,
                state=state,
                systemctl=systemctl,
                log=log,
            )

            self.assertFalse(result["noop"])
            self.assertFalse(stale_link.exists())
            self.assertIn("daemon-reload", log.read_text(encoding="utf-8"))

    def test_unrecorded_broken_dropin_is_removed_after_generation_pruning(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            projection = root / "projection"
            projection.mkdir()
            manifest = projection / "manifest.json"
            self.write_manifest(manifest, None)
            runtime = root / "systemd"
            dropin_dir = runtime / "copyparty.service.d"
            dropin_dir.mkdir(parents=True)
            stale_link = dropin_dir / "50-nas-v2.conf"
            stale_link.symlink_to(root / "generations" / ("a" * 40) / "systemd" / "missing.conf")
            state = root / "state.json"
            state.write_text("{}\n", encoding="utf-8")
            systemctl, log = self.make_systemctl(root)

            result = self.run_reconcile(
                manifest=manifest,
                projection=projection,
                runtime=runtime,
                state=state,
                systemctl=systemctl,
                log=log,
            )

            self.assertFalse(result["noop"])
            self.assertFalse(stale_link.is_symlink())
            self.assertFalse(dropin_dir.exists())
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
            log.write_text("", encoding="utf-8")
            self.run_reconcile(
                manifest=manifest,
                projection=projection,
                runtime=runtime,
                state=state,
                systemctl=systemctl,
                log=log,
            )

            self.assertFalse((runtime / "nas-v2-demo.service").exists())
            commands = log.read_text(encoding="utf-8").splitlines()
            self.assertIn("stop nas-v2-demo.service", commands)
            self.assertIn("reset-failed nas-v2-demo.service", commands)
            self.assertLess(
                commands.index("stop nas-v2-demo.service"),
                commands.index("reset-failed nas-v2-demo.service"),
            )

    def test_unloaded_retired_unit_does_not_abort_failed_state_cleanup(self):
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
            fail_ctl, fail_log = self.make_systemctl(root, fail_on={"reset-failed nas-v2-demo.service"})
            self.run_reconcile(
                manifest=manifest,
                projection=projection,
                runtime=runtime,
                state=state,
                systemctl=fail_ctl,
                log=fail_log,
            )

            self.assertFalse((runtime / "nas-v2-demo.service").exists())
            self.assertIn("reset-failed nas-v2-demo.service", fail_log.read_text(encoding="utf-8"))

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
            self.assertNotIn("reset-failed nas-v2-demo.service", fail_log.read_text(encoding="utf-8"))

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
