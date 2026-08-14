from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import stat
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
SCHEMA = ROOT / "schemas" / "managed-services-v3.schema.json"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_backup as backup  # noqa: E402
import nas_v2_caddy as caddy  # noqa: E402
import nas_v2_network as net  # noqa: E402
import nas_v2_spec as spec  # noqa: E402
import nas_v2_systemd_reconcile as sysrec  # noqa: E402
import nas_v2_bootstrap as bootstrap  # noqa: E402

try:
    from hypothesis import HealthCheck, given, settings, strategies as st
except ImportError:
    HAS_HYPOTHESIS = False
else:
    HAS_HYPOTHESIS = True


# ---------------------------------------------------------------------------
# Seed generation (Nix + bootstrap)
# ---------------------------------------------------------------------------


class V2SeedGenerationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = spec.load_schema(SCHEMA)

    def test_nix_helpers_module_defines_required_symbols(self):
        text = (ROOT / "modules/nas/config/managed-services-helpers.nix").read_text(encoding="utf-8")
        for sym in ("daemon", "onDemand", "job", "pathRoute", "httpTarget", "identity", "adminCapability"):
            self.assertIn(sym, text)

    def test_seed_v2_nix_merges_all_built_in_categories(self):
        seed = (ROOT / "modules/nas/config/managed-services-seed-v2.nix").read_text(encoding="utf-8")
        for token in ("baselineServices", "operationServices", "backupResources", "backupServices", "platformServices"):
            self.assertIn(token, seed)
        self.assertIn("mergedServices = baselineServices // operationServices", seed)
        self.assertIn("schemaVersion = 3", seed)

    def test_actual_seed_would_compile_without_route_overlap(self):
        # Simulate Nix seed: a small subset that mirrors real seed shape.
        doc = {
            "schemaVersion": 3,
            "services": {
                "copyparty": {
                    "name": "CopyParty",
                    "workload": {"kind": "daemon"},
                    "runtime": {"type": "systemd", "unit": "copyparty.service"},
                    "authorization": {"capabilities": [{"id": "files", "title": "Files"}]},
                    "routes": {
                        "files": {
                            "target": {"type": "http", "port": 8000},
                            "exposure": {"type": "path", "paths": ["/shares"]},
                            "auth": {"mode": "identity", "capability": "files"},
                        },
                        "dav": {
                            "target": {"type": "http", "port": 8000},
                            "exposure": {"type": "path", "paths": ["/dav"]},
                            "auth": {"mode": "identity", "capability": "files"},
                        },
                    },
                },
                "cockpit": {
                    "name": "Cockpit",
                    "workload": {"kind": "daemon"},
                    "runtime": {"type": "systemd", "unit": "cockpit.socket"},
                    "authorization": {"capabilities": [{"id": "admin", "title": "Admin"}]},
                    "routes": {
                        "console": {
                            "target": {"type": "http", "port": 9090},
                            "exposure": {"type": "path", "paths": ["/console"]},
                            "auth": {"mode": "identity", "capability": "admin"},
                        }
                    },
                },
            },
        }
        effective = spec.compile_document(doc, self.schema)
        # Caddy must render without overlap error and include both routes
        rendered = caddy.generate_caddyfile(effective)
        self.assertIn("/shares", rendered)
        self.assertIn("/console", rendered)

    def test_longest_prefix_overlap_is_rejected_by_spec(self):
        doc = {
            "schemaVersion": 3,
            "services": {
                "a": {
                    "name": "A",
                    "workload": {"kind": "daemon"},
                    "runtime": {"type": "systemd", "unit": "a.service"},
                    "routes": {
                        "api": {
                            "target": {"type": "http", "port": 8080},
                            "exposure": {"type": "path", "paths": ["/api"]},
                            "auth": {"mode": "public"},
                        }
                    },
                },
                "b": {
                    "name": "B",
                    "workload": {"kind": "daemon"},
                    "runtime": {"type": "systemd", "unit": "b.service"},
                    "routes": {
                        "api-users": {
                            "target": {"type": "http", "port": 8081},
                            "exposure": {"type": "path", "paths": ["/api/users"]},
                            "auth": {"mode": "public"},
                        }
                    },
                },
            },
        }
        with self.assertRaisesRegex(spec.ManagedServicesV2Error, "overlaps"):
            spec.compile_document(doc, self.schema)

    def test_bootstrap_consumes_marker_only_on_fresh_stub(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            desired = root / "services.yaml"
            seed = root / "seed.yaml"
            marker = root / ".initial-seed"
            desired.write_text("schemaVersion: 3\nservices: {}\n", encoding="utf-8")
            marker.touch()
            seed.write_text(
                "schemaVersion: 3\nservices:\n  demo:\n    name: Demo\n    workload: {kind: daemon}\n    runtime: {type: systemd, unit: demo.service}\n",
                encoding="utf-8",
            )
            result = bootstrap.migrate(desired=desired, seed=seed, marker=marker, schema=SCHEMA, platform=None)
            self.assertTrue(result["changed"])
            self.assertEqual(result["reason"], "initial-seed")
            self.assertFalse(marker.exists())
            # second call with existing authority must not clobber
            marker.touch()
            seed.write_text(
                "schemaVersion: 3\nservices:\n  new:\n    name: New\n    workload: {kind: daemon}\n    runtime: {type: systemd, unit: new.service}\n",
                encoding="utf-8",
            )
            result2 = bootstrap.migrate(desired=desired, seed=seed, marker=marker, schema=SCHEMA, platform=None)
            self.assertFalse(result2["changed"])
            self.assertIn(result2["reason"], ("authority-exists", "authority-created-concurrently"))
            self.assertIn("demo:", desired.read_text(encoding="utf-8"))
            self.assertNotIn("new:", desired.read_text(encoding="utf-8"))

    def test_invalid_seed_never_replaces_stub_or_consumes_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            desired = root / "services.yaml"
            seed = root / "seed.yaml"
            marker = root / ".initial-seed"
            original = "schemaVersion: 3\nservices: {}\n"
            desired.write_text(original, encoding="utf-8")
            marker.touch()
            seed.write_text(
                'schemaVersion: 3\nservices:\n  bad:\n    name: Bad\n    workload: {kind: daemon}\n    runtime: {type: systemd, unit: ""}\n',
                encoding="utf-8",
            )
            with self.assertRaises(Exception):
                bootstrap.migrate(desired=desired, seed=seed, marker=marker, schema=SCHEMA, platform=None)
            self.assertEqual(desired.read_text(encoding="utf-8"), original)
            self.assertTrue(marker.exists())


# ---------------------------------------------------------------------------
# Nested-route and Caddy behavior
# ---------------------------------------------------------------------------


class V2NestedRouteCaddyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = spec.load_schema(SCHEMA)

    def compile(self, services: dict) -> dict:
        return spec.compile_document({"schemaVersion": 3, "services": services}, self.schema)

    def test_caddy_generates_deterministic_sorted_routes(self):
        def svc(sid: str, path: str) -> dict:
            return {
                "name": sid,
                "workload": {"kind": "daemon"},
                "runtime": {"type": "systemd", "unit": f"{sid}.service"},
                "routes": {
                    "web": {
                        "target": {"type": "http", "port": 8080},
                        "exposure": {"type": "path", "paths": [path]},
                        "auth": {"mode": "public"},
                    }
                },
            }

        a = self.compile({"zzz": svc("zzz", "/zzz/"), "aaa": svc("aaa", "/aaa/")})
        b = self.compile({"aaa": svc("aaa", "/aaa/"), "zzz": svc("zzz", "/zzz/")})
        self.assertEqual(caddy.generate_caddyfile(a), caddy.generate_caddyfile(b))

    def test_nested_path_without_trailing_slash_still_overlaps(self):
        doc = {
            "schemaVersion": 3,
            "services": {
                "a": {
                    "name": "A",
                    "workload": {"kind": "daemon"},
                    "runtime": {"type": "systemd", "unit": "a.service"},
                    "routes": {
                        "x": {
                            "target": {"type": "http", "port": 8080},
                            "exposure": {"type": "path", "paths": ["/a/"]},
                            "auth": {"mode": "public"},
                        }
                    },
                },
                "b": {
                    "name": "B",
                    "workload": {"kind": "daemon"},
                    "runtime": {"type": "systemd", "unit": "b.service"},
                    "routes": {
                        "y": {
                            "target": {"type": "http", "port": 8081},
                            "exposure": {"type": "path", "paths": ["/a"]},
                            "auth": {"mode": "public"},
                        }
                    },
                },
            },
        }
        # /a and /a/ are canonicalized to same shadow set -> overlap
        with self.assertRaisesRegex(spec.ManagedServicesV2Error, "overlaps|Duplicate"):
            spec.compile_document(doc, self.schema)

    def test_caddy_hostname_collision_with_lan_host_fails_closed(self):
        effective = self.compile(
            {
                "demo": {
                    "name": "Demo",
                    "workload": {"kind": "daemon"},
                    "runtime": {"type": "systemd", "unit": "demo.service"},
                    "routes": {
                        "web": {
                            "target": {"type": "http", "port": 8080},
                            "exposure": {"type": "hostname", "hostnames": ["nas.local"], "path": "/"},
                            "auth": {"mode": "public"},
                        }
                    },
                }
            }
        )
        with self.assertRaisesRegex(caddy.CaddyProjectionError, "collides"):
            caddy.generate_caddyfile(effective, lan_host="nas.local")

    def test_multiple_routes_per_service_render_all(self):
        effective = self.compile(
            {
                "demo": {
                    "name": "Demo",
                    "workload": {"kind": "daemon"},
                    "runtime": {"type": "systemd", "unit": "demo.service"},
                    "authorization": {"capabilities": [{"id": "access", "title": "Access"}]},
                    "routes": {
                        "a": {
                            "target": {"type": "http", "port": 8080},
                            "exposure": {"type": "path", "paths": ["/a/"]},
                            "auth": {"mode": "public"},
                        },
                        "b": {
                            "target": {"type": "http", "port": 8081},
                            "exposure": {"type": "path", "paths": ["/b/"]},
                            "auth": {"mode": "identity", "capability": "access"},
                        },
                    },
                }
            }
        )
        rendered = caddy.generate_caddyfile(effective)
        self.assertIn("/a/", rendered)
        self.assertIn("/b/", rendered)
        self.assertIn("reverse_proxy 127.0.0.1:8080", rendered)
        self.assertIn("reverse_proxy 127.0.0.1:8081", rendered)

    def test_caddy_path_patterns_are_quoted_and_root_uses_wildcard(self):
        effective = self.compile(
            {
                "root": {
                    "name": "Root",
                    "workload": {"kind": "daemon"},
                    "runtime": {"type": "systemd", "unit": "root.service"},
                    "routes": {
                        "web": {
                            "target": {"type": "http", "port": 8080},
                            "exposure": {"type": "path", "paths": ["/"]},
                            "auth": {"mode": "public"},
                        }
                    },
                }
            }
        )
        rendered = caddy.generate_caddyfile(effective)
        self.assertIn('path "/*"', rendered)

    def test_caddy_identity_headers_stripped_before_forward_auth(self):
        effective = self.compile(
            {
                "demo": {
                    "name": "Demo",
                    "workload": {"kind": "daemon"},
                    "runtime": {"type": "systemd", "unit": "demo.service"},
                    "authorization": {"capabilities": [{"id": "admin", "title": "Admin"}]},
                    "routes": {
                        "web": {
                            "target": {"type": "http", "port": 8080},
                            "exposure": {"type": "path", "paths": ["/demo/"]},
                            "auth": {"mode": "identity", "capability": "admin"},
                        }
                    },
                }
            }
        )
        rendered = caddy.generate_caddyfile(effective)
        first_strip = rendered.index("request_header -Remote-User")
        forward = rendered.index("forward_auth 127.0.0.1:9000")
        self.assertLess(first_strip, forward)


# ---------------------------------------------------------------------------
# Backup cleanup (idempotent, symlinks, staging)
# ---------------------------------------------------------------------------


class V2BackupCleanupExtendedTests(unittest.TestCase):
    def inventory(self, artifact: pathlib.Path) -> dict:
        return {
            "schemaVersion": 1,
            "resources": [
                {
                    "id": "db",
                    "path": "/var/lib/db",
                    "consistency": "native-dump",
                    "nativeDump": {
                        "preparationService": "db-dump",
                        "preparationUnit": "nas-v2-db-dump.service",
                        "artifactResource": "db-artifact",
                        "artifactPath": str(artifact),
                    },
                }
            ],
        }

    def test_prepare_is_atomic_and_cleans_stale_even_on_empty_job(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            artifact = root / "artifact"
            artifact.mkdir()
            (artifact / "old.dump").write_bytes(b"old")
            inv = root / "inv.json"
            paths = root / "paths.txt"
            state = root / "state.json"
            inv.write_text(json.dumps(self.inventory(artifact)), encoding="utf-8")
            orig = backup._run
            backup._run = lambda _argv: ""  # type: ignore[assignment]
            try:
                with self.assertRaisesRegex(backup.BackupRuntimeError, "without producing data"):
                    backup.prepare(
                        inventory_path=inv,
                        paths_path=paths,
                        state_path=state,
                        zfs_bin="/bin/zfs",
                        systemctl_bin="/bin/systemctl",
                    )
            finally:
                backup._run = orig  # type: ignore[assignment]
            self.assertEqual(list(artifact.iterdir()), [])
            self.assertFalse(paths.exists())
            self.assertFalse(state.exists())

    def test_cleanup_is_idempotent_when_no_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            state = root / "state.json"
            paths = root / "paths.txt"
            paths.write_text("stale\n", encoding="utf-8")
            result = backup.cleanup(state_path=state, paths_path=paths, zfs_bin="/bin/zfs")
            self.assertEqual(result["destroyed"], [])
            self.assertFalse(paths.exists())

    def test_cleanup_is_idempotent_when_called_twice(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            state = root / "state.json"
            paths = root / "paths.txt"
            state.write_text(json.dumps({"schemaVersion": 1, "snapshots": []}), encoding="utf-8")
            paths.write_text("x\n", encoding="utf-8")
            first = backup.cleanup(state_path=state, paths_path=paths, zfs_bin="/bin/zfs")
            self.assertEqual(first["destroyed"], [])
            second = backup.cleanup(state_path=state, paths_path=paths, zfs_bin="/bin/zfs")
            self.assertEqual(second["destroyed"], [])

    def test_verify_rejects_symlink_in_snapshot_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            restore = root / "restore"
            snap_root = restore / "tank" / "data" / ".zfs" / "snapshot"
            snap_root.mkdir(parents=True)
            real = snap_root / "nas-v2-restic-real"
            real.mkdir()
            (real / "file.txt").write_text("hi", encoding="utf-8")
            # symlink attack: snapshot root is symlink
            # Replace snapshot dir's parent .zfs as symlink
            linked_zfs = restore / "tank" / "data" / ".zfs_link"
            linked_zfs.symlink_to(snap_root)
            inventory = root / "inv.json"
            inventory.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "resources": [{"id": "data", "path": "/tank/data", "consistency": "zfs-snapshot"}],
                    }
                ),
                encoding="utf-8",
            )
            # Create a real symlink for native-dump artifact
            artifact = restore / "run" / "backup" / "x"
            artifact.mkdir(parents=True)
            outside = root / "outside"
            outside.write_text("evil", encoding="utf-8")
            (artifact / "escape").symlink_to(outside)
            inventory2 = root / "inv2.json"
            inventory2.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "resources": [
                            {
                                "id": "nd",
                                "path": "/var/lib/x",
                                "consistency": "native-dump",
                                "nativeDump": {"artifactPath": "/run/backup/x"},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(backup.BackupVerificationError, "symlink"):
                backup.verify(inventory_path=inventory2, restore_root=restore, pg_restore_bin="/bin/false")

    def test_staging_path_escapes_are_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "restore"
            root.mkdir()
            outside = pathlib.Path(tmp) / "outside.txt"
            outside.write_text("x", encoding="utf-8")
            with self.assertRaisesRegex(backup.BackupVerificationError, "escapes verification root"):
                backup._assert_within_restore_root(outside, root)

    def test_zfs_prepare_cleans_snapshot_on_mountpoint_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            inv = root / "inv.json"
            paths = root / "paths.txt"
            state = root / "state.json"
            inv.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "resources": [
                            {
                                "id": "data",
                                "path": "/tank/data",
                                "dataset": "tank/data",
                                "consistency": "zfs-snapshot",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            calls: list[list[str]] = []

            def fake_run(argv: list[str]) -> str:
                calls.append(argv)
                if argv[:3] == ["/bin/zfs", "get", "-H"]:
                    return "/tank/other"  # mismatch -> should fail closed
                return ""

            orig = backup._run
            backup._run = fake_run  # type: ignore[assignment]
            try:
                with self.assertRaisesRegex(backup.BackupRuntimeError, "does not match ZFS dataset.*mountpoint"):
                    backup.prepare(
                        inventory_path=inv,
                        paths_path=paths,
                        state_path=state,
                        zfs_bin="/bin/zfs",
                        systemctl_bin="/bin/systemctl",
                    )
            finally:
                backup._run = orig  # type: ignore[assignment]
            self.assertFalse(paths.exists())
            self.assertFalse(state.exists())


# ---------------------------------------------------------------------------
# Fault-inject every systemd reconciliation step
# ---------------------------------------------------------------------------


class V2SystemdFaultInjectionTests(unittest.TestCase):
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

    def write_manifest(self, path: pathlib.Path, source: pathlib.Path | None, *, start: bool = True) -> None:
        links = [] if source is None else [{"target": "nas-v2-demo.service", "source": str(source)}]
        owned = ["nas-v2-demo.service"] if source is not None else []
        payload = {
            "schemaVersion": 1,
            "links": links,
            "quadletLinks": [],
            "ownedUnits": owned,
            "startUnits": owned if start else [],
            "stopUnits": [],
            "fingerprints": {} if not owned else {"nas-v2-demo.service": "v1"},
        }
        path.write_text(json.dumps(payload), encoding="utf-8")

    def test_daemon_reload_failure_propagates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            proj = root / "proj"
            units = proj / "units"
            units.mkdir(parents=True)
            src = units / "nas-v2-demo.service"
            src.write_text("[Service]\nExecStart=/bin/true\n", encoding="utf-8")
            manifest = proj / "manifest.json"
            self.write_manifest(manifest, src)
            runtime = root / "systemd"
            runtime.mkdir()
            state = root / "state.json"
            systemctl, log = self.make_systemctl(root, fail_on={"daemon-reload"})
            with self.assertRaisesRegex(sysrec.SystemdReconcileError, "daemon-reload"):
                sysrec.reconcile(
                    manifest_path=manifest,
                    projection_root=proj,
                    systemd_runtime_dir=runtime,
                    quadlet_runtime_dir=root / "quadlet",
                    state_path=state,
                    systemctl=str(systemctl),
                )

    def test_restart_failure_propagates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            proj = root / "proj"
            units = proj / "units"
            units.mkdir(parents=True)
            src = units / "nas-v2-demo.service"
            src.write_text("[Service]\nExecStart=/bin/true\n", encoding="utf-8")
            manifest = proj / "manifest.json"
            self.write_manifest(manifest, src)
            runtime = root / "systemd"
            runtime.mkdir()
            systemctl, _ = self.make_systemctl(root, fail_on={"restart"})
            with self.assertRaisesRegex(sysrec.SystemdReconcileError, "restart"):
                sysrec.reconcile(
                    manifest_path=manifest,
                    projection_root=proj,
                    systemd_runtime_dir=runtime,
                    quadlet_runtime_dir=root / "quadlet",
                    state_path=root / "state.json",
                    systemctl=str(systemctl),
                )

    def test_stop_is_best_effort_even_when_failed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            proj = root / "proj"
            proj.mkdir()
            manifest = proj / "manifest.json"
            # first reconcile with a unit, then remove it but systemctl stop fails
            units = proj / "units"
            units.mkdir()
            src = units / "nas-v2-demo.service"
            src.write_text("[Service]\nExecStart=/bin/true\n", encoding="utf-8")
            self.write_manifest(manifest, src)
            runtime = root / "systemd"
            runtime.mkdir()
            quad = root / "quadlet"
            quad.mkdir()
            ok_ctl, _ = self.make_systemctl(root)
            state = root / "state.json"
            sysrec.reconcile(
                manifest_path=manifest,
                projection_root=proj,
                systemd_runtime_dir=runtime,
                quadlet_runtime_dir=quad,
                state_path=state,
                systemctl=str(ok_ctl),
            )
            # now remove unit, but make stop fail
            self.write_manifest(manifest, None)
            fail_ctl, log = self.make_systemctl(root, fail_on={"stop nas-v2-demo.service"})
            # stop is called with check=False, so reconcile must succeed despite failure
            result = sysrec.reconcile(
                manifest_path=manifest,
                projection_root=proj,
                systemd_runtime_dir=runtime,
                quadlet_runtime_dir=quad,
                state_path=state,
                systemctl=str(fail_ctl),
            )
            self.assertIn("nas-v2-demo.service", result["stopped"])

    def test_unsafe_target_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            proj = root / "proj"
            proj.mkdir()
            bad_src = proj / "evil"
            bad_src.write_text("x", encoding="utf-8")
            manifest = proj / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "links": [{"target": "../escape.service", "source": str(bad_src)}],
                        "quadletLinks": [],
                        "ownedUnits": [],
                        "startUnits": [],
                        "stopUnits": [],
                        "fingerprints": {},
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(sysrec.SystemdReconcileError, "unsafe"):
                sysrec.reconcile(
                    manifest_path=manifest,
                    projection_root=proj,
                    systemd_runtime_dir=root / "runtime",
                    quadlet_runtime_dir=root / "quadlet",
                    state_path=root / "state.json",
                    systemctl="/bin/false",
                )

    def test_non_regular_projection_entry_triggers_rollback(self):
        # _source_under must reject non-file source
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            proj = root / "proj"
            proj.mkdir()
            manifest = proj / "manifest.json"
            missing = proj / "missing.service"
            manifest.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "links": [{"target": "nas-v2-demo.service", "source": str(missing)}],
                        "quadletLinks": [],
                        "ownedUnits": ["nas-v2-demo.service"],
                        "startUnits": ["nas-v2-demo.service"],
                        "stopUnits": [],
                        "fingerprints": {},
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(sysrec.SystemdReconcileError, "escapes|not a file|is not a file"):
                sysrec.reconcile(
                    manifest_path=manifest,
                    projection_root=proj,
                    systemd_runtime_dir=root / "runtime",
                    quadlet_runtime_dir=root / "quadlet",
                    state_path=root / "state.json",
                    systemctl="/bin/false",
                )

    def test_start_failure_propagates_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            proj = root / "proj"
            units = proj / "units"
            units.mkdir(parents=True)
            src = units / "nas-v2-demo.service"
            src.write_text("[Service]\nExecStart=/bin/true\n", encoding="utf-8")
            manifest = proj / "manifest.json"
            self.write_manifest(manifest, src)
            runtime = root / "systemd"
            runtime.mkdir()
            ctl, _ = self.make_systemctl(root, fail_on={"start nas-v2-demo.service"})
            with self.assertRaisesRegex(sysrec.SystemdReconcileError, "start"):
                sysrec.reconcile(
                    manifest_path=manifest,
                    projection_root=proj,
                    systemd_runtime_dir=runtime,
                    quadlet_runtime_dir=root / "quadlet",
                    state_path=root / "state.json",
                    systemctl=str(ctl),
                )


# ---------------------------------------------------------------------------
# Cross-component partial failures and firewall deadman
# ---------------------------------------------------------------------------


class V2CrossComponentAndDeadmanTests(unittest.TestCase):
    def test_zfs_partial_snapshot_is_cleaned_on_second_resource_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            inv = root / "inv.json"
            paths = root / "paths.txt"
            state = root / "state.json"
            inv.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "resources": [
                            {"id": "a", "path": "/tank/a", "dataset": "tank/a", "consistency": "zfs-snapshot"},
                            {"id": "b", "path": "/tank/b", "dataset": "tank/b", "consistency": "zfs-snapshot"},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            created: list[str] = []

            def fake_run(argv: list[str]) -> str:
                if argv[0] == "/bin/zfs" and argv[1] == "get":
                    dataset = argv[-1]
                    return f"/tank/{dataset.split('/')[-1]}"
                if argv[:2] == ["/bin/zfs", "snapshot"]:
                    created.append(argv[2])
                    return ""
                if argv[:2] == ["/bin/zfs", "destroy"]:
                    created.remove(argv[2]) if argv[2] in created else None
                    return ""
                raise AssertionError(f"unexpected {argv}")

            call = 0
            orig = backup._run

            def failing_run(argv: list[str]) -> str:
                nonlocal call
                if argv[0] == "/bin/zfs" and argv[1] == "get":
                    call += 1
                    if call == 2:
                        raise backup.BackupRuntimeError("simulated ZFS get failure")
                    return fake_run(argv)
                return fake_run(argv)

            backup._run = failing_run  # type: ignore[assignment]
            try:
                with self.assertRaisesRegex(backup.BackupRuntimeError, "simulated ZFS get failure"):
                    backup.prepare(
                        inventory_path=inv,
                        paths_path=paths,
                        state_path=state,
                        zfs_bin="/bin/zfs",
                        systemctl_bin="/bin/systemctl",
                    )
            finally:
                backup._run = orig  # type: ignore[assignment]
            self.assertFalse(paths.exists())
            self.assertFalse(state.exists())
            self.assertEqual(created, [])

    def test_firewall_deadman_rollback_on_reload_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            proj = root / "proj"
            zone_content = b"<zone/>\n"
            target = "zones/nv2z0123456789ab.xml"
            src = proj / target
            src.parent.mkdir(parents=True)
            src.write_bytes(zone_content)
            manifest = proj / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "files": [{"target": target, "sha256": hashlib.sha256(zone_content).hexdigest()}],
                        "owners": [],
                    }
                ),
                encoding="utf-8",
            )
            system_config = root / "firewalld"
            (system_config / "zones").mkdir(parents=True)
            (system_config / "policies").mkdir(parents=True)
            dest = system_config / target
            dest.write_bytes(b"<zone><short>old</short></zone>\n")
            offline = root / "offline"
            offline.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            offline.chmod(offline.stat().st_mode | stat.S_IXUSR)
            firewall = root / "firewall"
            firewall.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
            firewall.chmod(firewall.stat().st_mode | stat.S_IXUSR)
            with self.assertRaisesRegex(net.FirewalldReconcileError, "rollback"):
                net.reconcile(
                    manifest_path=manifest,
                    projection_root=proj,
                    system_config=system_config,
                    firewall_cmd=str(firewall),
                    firewall_offline_cmd=str(offline),
                )
            self.assertEqual(dest.read_bytes(), b"<zone><short>old</short></zone>\n")

    def test_firewall_offline_check_failure_does_not_mutate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            proj = root / "proj"
            content = b"<zone/>\n"
            target = "zones/nv2z0123456789ab.xml"
            src = proj / target
            src.parent.mkdir(parents=True)
            src.write_bytes(content)
            manifest = proj / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "files": [{"target": target, "sha256": hashlib.sha256(content).hexdigest()}],
                        "owners": [],
                    }
                ),
                encoding="utf-8",
            )
            system_config = root / "firewalld"
            (system_config / "zones").mkdir(parents=True)
            (system_config / "policies").mkdir(parents=True)
            offline = root / "offline"
            offline.write_text("#!/bin/sh\necho bad >&2; exit 1\n", encoding="utf-8")
            offline.chmod(offline.stat().st_mode | stat.S_IXUSR)
            firewall = root / "firewall"
            firewall.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            firewall.chmod(firewall.stat().st_mode | stat.S_IXUSR)
            with self.assertRaisesRegex(net.FirewalldReconcileError, "invalid|rollback"):
                net.reconcile(
                    manifest_path=manifest,
                    projection_root=proj,
                    system_config=system_config,
                    firewall_cmd=str(firewall),
                    firewall_offline_cmd=str(offline),
                )
            self.assertFalse((system_config / target).exists())

    def test_network_projection_rejects_unsafe_lan_zone(self):
        effective = {
            "schemaVersion": 3,
            "services": {
                "demo": {
                    "enabled": True,
                    "managed": True,
                    "workload": {"kind": "daemon"},
                    "runtime": {"type": "systemd", "unit": "demo.service"},
                }
            },
        }
        with self.assertRaisesRegex(net.FirewalldProjectionError, "unsafe firewalld LAN zone"):
            net.compile_projection(effective, lan_zone="../escape")


# ---------------------------------------------------------------------------
# Release-manifest, idempotence, backend projection
# ---------------------------------------------------------------------------


class V2ReleaseManifestIdempotenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = spec.load_schema(SCHEMA)

    def test_backup_projection_is_deterministic_and_sorted(self):
        eff = {
            "schemaVersion": 3,
            "storageResources": {
                "b": {
                    "path": "/b",
                    "scope": "system",
                    "stateClass": "authoritative",
                    "backup": {"enabled": True, "consistency": "filesystem"},
                },
                "a": {
                    "path": "/a",
                    "scope": "system",
                    "stateClass": "authoritative",
                    "backup": {"enabled": True, "consistency": "filesystem"},
                },
            },
            "services": {},
            "derived": {"backupResources": ["b", "a"], "runtime": {}},
        }
        first = backup.compile_backup_projection(eff)
        second = backup.compile_backup_projection(eff)
        self.assertEqual(first, second)
        self.assertEqual(first[1], b"/a\n/b\n")

    def test_manifest_sha256_entries_are_valid_and_sorted(self):
        # MANIFEST.sha256 is an allowlist; verify format without requiring Nix.
        manifest = ROOT / "MANIFEST.sha256"
        if not manifest.is_file():
            self.skipTest("MANIFEST.sha256 not present in worktree")
        lines = manifest.read_text(encoding="utf-8").strip().splitlines()
        pattern = re.compile(r"^[0-9a-f]{64}  .+")
        for line in lines:
            self.assertRegex(line, pattern, msg=f"malformed manifest line: {line}")
        # must be sorted by filename for deterministic packaging
        filenames = [line.split("  ", 1)[1] for line in lines]
        self.assertEqual(filenames, sorted(filenames))

    def test_systemd_reconcile_noop_on_identical_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            proj = root / "proj"
            units = proj / "units"
            units.mkdir(parents=True)
            src = units / "nas-v2-demo.service"
            src.write_text("[Service]\nExecStart=/bin/true\n", encoding="utf-8")
            manifest = proj / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "links": [{"target": "nas-v2-demo.service", "source": str(src)}],
                        "quadletLinks": [],
                        "ownedUnits": ["nas-v2-demo.service"],
                        "startUnits": ["nas-v2-demo.service"],
                        "stopUnits": [],
                        "fingerprints": {"nas-v2-demo.service": "v1"},
                    }
                ),
                encoding="utf-8",
            )
            runtime = root / "systemd"
            runtime.mkdir()
            quad = root / "quadlet"
            quad.mkdir()
            log = root / "log"
            script = root / "systemctl"
            script.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$NAS_V2_SYSTEMCTL_LOG"\nexit 0\n', encoding="utf-8")
            script.chmod(script.stat().st_mode | stat.S_IXUSR)
            state = root / "state.json"
            with mock.patch.dict(os.environ, {"NAS_V2_SYSTEMCTL_LOG": str(log)}):
                sysrec.reconcile(
                    manifest_path=manifest,
                    projection_root=proj,
                    systemd_runtime_dir=runtime,
                    quadlet_runtime_dir=quad,
                    state_path=state,
                    systemctl=str(script),
                )
                log.write_text("", encoding="utf-8")
                result = sysrec.reconcile(
                    manifest_path=manifest,
                    projection_root=proj,
                    systemd_runtime_dir=runtime,
                    quadlet_runtime_dir=quad,
                    state_path=state,
                    systemctl=str(script),
                )
            self.assertTrue(result["noop"])
            self.assertEqual(log.read_text(encoding="utf-8"), "")

    def test_firewall_backend_projection_filters_disabled_services(self):
        eff = {
            "schemaVersion": 3,
            "services": {
                "enabled": {
                    "enabled": True,
                    "managed": True,
                    "workload": {"kind": "daemon"},
                    "runtime": {"type": "systemd", "unit": "enabled.service"},
                    "network": {"mode": "host"},
                    "listeners": {"web": {"protocol": "tcp", "exposure": {"port": 8080}, "firewall": True}},
                },
                "disabled": {
                    "enabled": False,
                    "managed": True,
                    "workload": {"kind": "daemon"},
                    "runtime": {"type": "systemd", "unit": "disabled.service"},
                    "network": {"mode": "host"},
                    "listeners": {"web": {"protocol": "tcp", "exposure": {"port": 8080}, "firewall": True}},
                },
            },
        }
        files, manifest = net.compile_projection(eff, lan_zone="trusted")
        # only one service policy + global remote admin (priority -300) because disabled service is ignored
        self.assertEqual(len(files), 2)
        self.assertIn(f"policies/{net.remote_admin_policy_name()}.xml", files)

    def test_backend_projection_has_no_application_names(self):
        text = (ROOT / "services/nas_v2_backup.py").read_text(encoding="utf-8").lower()
        for name in ("authentik", "copyparty", "syncthing", "vaultwarden"):
            self.assertNotIn(name, text)
        text2 = (ROOT / "services/nas_v2_network.py").read_text(encoding="utf-8").lower()
        # network module also must not hardcode application names
        for name in ("authentik", "copyparty", "vaultwarden"):
            self.assertNotIn(name, text2)

    def test_portal_projection_is_sorted_and_visible_only(self):
        import nas_v2_caddy as portal  # noqa: E402

        eff = spec.compile_document(
            {
                "schemaVersion": 3,
                "services": {
                    "demo": {
                        "name": "Demo",
                        "workload": {"kind": "daemon"},
                        "runtime": {"type": "systemd", "unit": "demo.service"},
                        "routes": {
                            "web": {
                                "target": {"type": "http", "port": 8080},
                                "exposure": {"type": "path", "paths": ["/demo/"]},
                                "auth": {"mode": "public"},
                                "portal": {
                                    "visible": True,
                                    "title": "Demo",
                                    "category": "Home",
                                    "icon": "box",
                                    "order": 1,
                                },
                            }
                        },
                    }
                },
            },
            self.schema,
        )
        data = portal.compile_portal_projection(eff)
        self.assertIn(data["schemaVersion"], (1, 2))
        self.assertEqual(len(data["entries"]), 1)
        # title vs label depending on schema version
        title = data["entries"][0].get("title") or data["entries"][0].get("label")
        self.assertEqual(title, "Demo")


# ---------------------------------------------------------------------------
# Property / fuzz tests with Hypothesis
# ---------------------------------------------------------------------------


if HAS_HYPOTHESIS:

    class V2HypothesisTests(unittest.TestCase):
        @classmethod
        def setUpClass(cls) -> None:
            cls.schema = spec.load_schema(SCHEMA)

        @settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow])
        @given(st.text(min_size=1, max_size=30))
        def test_absolute_path_validation_is_total(self, raw: str):
            # _validate_absolute_path must never crash
            result = backup._validate_absolute_path(raw)
            if result is not None:
                self.assertTrue(result.is_absolute())
                self.assertNotIn("..", result.parts)
                self.assertNotIn("\x00", str(result))

        @settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.too_slow])
        @given(st.lists(st.text(min_size=1, max_size=12), min_size=1, max_size=4))
        def test_route_path_conflict_is_symmetric(self, parts: list[str]):
            # Build two random path candidates and check conflict symmetry
            def to_path(p: list[str]) -> str:
                return "/" + "/".join(re.sub(r"[^A-Za-z0-9_-]", "x", s).strip("/") or "x" for s in p) + "/"

            a = to_path(parts)
            b = to_path(list(reversed(parts)))
            # spec helper is symmetric
            self.assertEqual(spec._routes_conflict(a, b), spec._routes_conflict(b, a))
            self.assertTrue(spec._routes_conflict("/", a))
            self.assertTrue(spec._routes_conflict(a, "/"))

        @settings(max_examples=30, deadline=None, suppress_health_check=[HealthCheck.too_slow])
        @given(st.text(alphabet=st.characters(blacklist_categories=("Cs",)), min_size=1, max_size=200))
        def test_caddy_generate_does_not_crash_on_any_compiled_doc(self, junk: str):
            # Create minimal compiled doc with one path route using sanitized junk
            safe = re.sub(r"[^A-Za-z0-9/_-]", "x", junk).strip("/")
            if not safe:
                safe = "x"
            path = f"/{safe}/"
            # path must start with / and not contain control/brace
            if any(c in path for c in ("\x00", "\r", "\n", "{", "}")):
                return
            doc = {
                "schemaVersion": 3,
                "services": {
                    "demo": {
                        "name": "Demo",
                        "workload": {"kind": "daemon"},
                        "runtime": {"type": "systemd", "unit": "demo.service"},
                        "routes": {
                            "web": {
                                "target": {"type": "http", "port": 8080},
                                "exposure": {"type": "path", "paths": [path]},
                                "auth": {"mode": "public"},
                            }
                        },
                    }
                },
            }
            try:
                eff = spec.compile_document(doc, self.schema)
            except spec.ManagedServicesV2Error:
                return
            rendered = caddy.generate_caddyfile(eff)
            self.assertIn(path.rstrip("/") or "/", rendered)

        @settings(max_examples=25, deadline=None, suppress_health_check=[HealthCheck.too_slow])
        @given(st.integers(min_value=0, max_value=70000))
        def test_listener_port_validation_never_crashes(self, port: int):
            exposure: dict = {"port": port}
            eff = {
                "schemaVersion": 3,
                "services": {
                    "demo": {
                        "enabled": True,
                        "managed": True,
                        "workload": {"kind": "daemon"},
                        "runtime": {"type": "systemd", "unit": "demo.service"},
                        "network": {"mode": "host"},
                        "listeners": {"p": {"protocol": "tcp", "exposure": exposure, "firewall": True}},
                    }
                },
            }
            # Should either succeed or raise FirewalldProjectionError, never crash
            try:
                net.compile_projection(eff, lan_zone="trusted")
            except (net.FirewalldProjectionError, net.PodmanNetworkProjectionError):
                return

else:

    @unittest.skip("Hypothesis is not installed; CI runs the property-test tier with it")
    class V2HypothesisPlaceholder(unittest.TestCase):  # type: ignore[no-redef]
        def test_hypothesis_tier_placeholder(self) -> None:
            pass

    V2HypothesisTests = V2HypothesisPlaceholder  # type: ignore[no-redef]


if __name__ == "__main__":
    unittest.main()
