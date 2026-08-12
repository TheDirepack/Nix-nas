from __future__ import annotations

import pathlib
import sys
import tempfile
import threading
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
SCHEMA = ROOT / "schemas" / "managed-services-v3.schema.json"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_bootstrap as bootstrap  # noqa: E402
import nas_v2_spec as spec  # noqa: E402


def _seed_with_categories() -> str:
    # Representative full seed containing baseline, operations, backup, platform.
    return """schemaVersion: 3
services:
  zfs-mount-guard:
    name: ZFS mount guard
    workload: {kind: job}
    runtime: {type: systemd, unit: nas-zfs-mount-guard.service}
  copyparty:
    name: CopyParty
    workload: {kind: daemon}
    runtime: {type: systemd, unit: copyparty.service}
  zfs-pool-health:
    name: Check ZFS pool health
    workload: {kind: job}
    runtime: {type: systemd, unit: nas-zfs-pool-health.service}
  backups:
    name: Back up authoritative NAS state
    workload: {kind: job}
    runtime: {type: systemd, unit: restic-backups-nas-boot-system.service}
  backup-restore-verify:
    name: Restore verify
    workload: {kind: job}
    runtime: {type: systemd, unit: nas-backup-restore-verify.service}
  zfs-replication:
    name: Replicate ZFS
    workload: {kind: job}
    runtime: {type: systemd, unit: nas-syncoid.service}
  cockpit:
    name: Cockpit
    managed: false
    workload: {kind: daemon}
    runtime: {type: systemd, unit: cockpit.socket}
    authorization: {capabilities: [{id: admin, title: Admin}]}
    routes:
      console:
        target: {type: http, host: 127.0.0.1, port: 9092}
        exposure: {type: path, paths: ["/console"]}
        auth: {mode: identity, capability: admin}
storageResources:
  authentik-database:
    path: /var/lib/postgresql
    scope: system
    stateClass: authoritative
    capabilities: [read]
    backup: {enabled: true, consistency: native-dump}
  syncthing-config:
    path: /var/lib/syncthing/.config/syncthing
    scope: system
    stateClass: authoritative
    capabilities: [read]
    backup: {enabled: true, consistency: filesystem}
"""


class AggregationSeedBehaviorTests(unittest.TestCase):
    def test_all_enabled_contributors_appear_on_fresh_init(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            desired = root / "services.yaml"
            seed = root / "seed.yaml"
            marker = root / ".marker"
            desired.write_text("schemaVersion: 3\nservices: {}\n", encoding="utf-8")
            marker.touch()
            seed.write_text(_seed_with_categories(), encoding="utf-8")
            result = bootstrap.migrate(desired=desired, seed=seed, marker=marker, schema=SCHEMA, platform=None)
            self.assertTrue(result["changed"])
            text = desired.read_text(encoding="utf-8")
            for name in ("zfs-mount-guard", "copyparty", "zfs-pool-health", "backups", "cockpit"):
                self.assertIn(name, text)
            # backup storage resources present
            self.assertIn("authentik-database", text)

    def test_seed_is_schema_valid_before_creation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            desired = root / "services.yaml"
            seed = root / "seed.yaml"
            marker = root / ".marker"
            desired.write_text("schemaVersion: 3\nservices: {}\n", encoding="utf-8")
            marker.touch()
            seed.write_text(_seed_with_categories(), encoding="utf-8")
            # validate directly
            doc = spec.parse_yaml_text(seed.read_text(encoding="utf-8"), source=str(seed))
            spec.compile_document(doc, spec.load_schema(SCHEMA))
            # migrate succeeds
            result = bootstrap.migrate(desired=desired, seed=seed, marker=marker, schema=SCHEMA, platform=None)
            self.assertTrue(result["changed"])

    def test_reboot_performs_zero_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            desired = root / "services.yaml"
            seed = root / "seed.yaml"
            marker = root / ".marker"
            original = _seed_with_categories()
            desired.write_text(original, encoding="utf-8")
            # no marker -> reboot should do nothing
            seed.write_text(original, encoding="utf-8")
            result = bootstrap.migrate(desired=desired, seed=seed, marker=marker, schema=SCHEMA, platform=None)
            self.assertFalse(result["changed"])
            self.assertEqual(result["reason"], "authority-exists")
            self.assertEqual(desired.read_text(encoding="utf-8"), original)

    def test_upgrade_does_not_add_new_built_in(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            desired = root / "services.yaml"
            seed_v1 = root / "seed-v1.yaml"
            seed_v2 = root / "seed-v2.yaml"
            marker = root / ".marker"
            # initial seed v1
            desired.write_text("schemaVersion: 3\nservices: {}\n", encoding="utf-8")
            marker.touch()
            seed_v1.write_text(
                """schemaVersion: 3
services:
  existing:
    name: Existing
    workload: {kind: daemon}
    runtime: {type: systemd, unit: existing.service}
""",
                encoding="utf-8",
            )
            bootstrap.migrate(desired=desired, seed=seed_v1, marker=marker, schema=SCHEMA, platform=None)
            # administrator state before upgrade
            admin_text = desired.read_text(encoding="utf-8")
            # upgrade seed contains new built-in
            seed_v2.write_text(
                """schemaVersion: 3
services:
  existing:
    name: Existing
    workload: {kind: daemon}
    runtime: {type: systemd, unit: existing.service}
  new-built-in:
    name: New Built In
    workload: {kind: daemon}
    runtime: {type: systemd, unit: new-built-in.service}
""",
                encoding="utf-8",
            )
            # no marker on upgrade, so no merge
            result = bootstrap.migrate(desired=desired, seed=seed_v2, marker=marker, schema=SCHEMA, platform=None)
            self.assertFalse(result["changed"])
            self.assertNotIn("new-built-in", desired.read_text(encoding="utf-8"))
            self.assertEqual(desired.read_text(encoding="utf-8"), admin_text)

    def test_admin_deleted_built_in_stays_deleted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            desired = root / "services.yaml"
            seed = root / "seed.yaml"
            marker = root / ".marker"
            desired.write_text("schemaVersion: 3\nservices: {}\n", encoding="utf-8")
            marker.touch()
            seed.write_text(
                """schemaVersion: 3
services:
  built-in:
    name: Built In
    workload: {kind: daemon}
    runtime: {type: systemd, unit: built-in.service}
  other:
    name: Other
    workload: {kind: daemon}
    runtime: {type: systemd, unit: other.service}
""",
                encoding="utf-8",
            )
            bootstrap.migrate(desired=desired, seed=seed, marker=marker, schema=SCHEMA, platform=None)
            # admin deletes built-in
            admin = """schemaVersion: 3
services:
  other:
    name: Other
    workload: {kind: daemon}
    runtime: {type: systemd, unit: other.service}
"""
            desired.write_text(admin, encoding="utf-8")
            # reboot with same seed but no marker
            result = bootstrap.migrate(desired=desired, seed=seed, marker=marker, schema=SCHEMA, platform=None)
            self.assertFalse(result["changed"])
            self.assertEqual(desired.read_text(encoding="utf-8"), admin)

    def test_admin_edits_preserved_across_reboot(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            desired = root / "services.yaml"
            seed = root / "seed.yaml"
            marker = root / ".marker"
            desired.write_text("schemaVersion: 3\nservices: {}\n", encoding="utf-8")
            marker.touch()
            seed.write_text(_seed_with_categories(), encoding="utf-8")
            bootstrap.migrate(desired=desired, seed=seed, marker=marker, schema=SCHEMA, platform=None)
            edited = desired.read_text(encoding="utf-8").replace("CopyParty", "My Files")
            desired.write_text(edited, encoding="utf-8")
            # simulate reboot
            result = bootstrap.migrate(desired=desired, seed=seed, marker=marker, schema=SCHEMA, platform=None)
            self.assertFalse(result["changed"])
            self.assertEqual(desired.read_text(encoding="utf-8"), edited)

    def test_concurrent_first_start_results_in_one_complete_authority(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            desired = root / "services.yaml"
            seed = root / "seed.yaml"
            marker = root / ".marker"
            desired.write_text("schemaVersion: 3\nservices: {}\n", encoding="utf-8")
            marker.touch()
            seed.write_text(_seed_with_categories(), encoding="utf-8")
            results = []

            def attempt():
                try:
                    r = bootstrap.migrate(desired=desired, seed=seed, marker=marker, schema=SCHEMA, platform=None)
                    results.append(r)
                except Exception as exc:  # noqa: BLE001
                    results.append(exc)

            threads = [threading.Thread(target=attempt) for _ in range(5)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            # exactly one should have changed, others should report no change or concurrently
            changed = sum(1 for r in results if isinstance(r, dict) and r.get("changed"))
            self.assertEqual(changed, 1)
            content = desired.read_text(encoding="utf-8")
            # must be complete, not partial union
            for name in ("zfs-mount-guard", "copyparty", "zfs-pool-health", "cockpit"):
                self.assertIn(name, content)
            # no marker left
            self.assertFalse(marker.exists())

    def test_failed_seed_validation_creates_no_authority(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            desired = root / "services.yaml"
            seed = root / "seed.yaml"
            marker = root / ".marker"
            desired.write_text("schemaVersion: 3\nservices: {}\n", encoding="utf-8")
            marker.touch()
            seed.write_text(
                """schemaVersion: 3
services:
  bad:
    name: Bad
    workload: {kind: daemon}
    runtime: {type: systemd, unit: ""}
""",
                encoding="utf-8",
            )
            with self.assertRaises(Exception):
                bootstrap.migrate(desired=desired, seed=seed, marker=marker, schema=SCHEMA, platform=None)
            self.assertEqual(desired.read_text(encoding="utf-8"), "schemaVersion: 3\nservices: {}\n")
            self.assertTrue(marker.exists())


if __name__ == "__main__":
    unittest.main()
