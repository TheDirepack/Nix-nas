from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
SCHEMA = ROOT / "schemas" / "managed-services-v3.schema.json"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_bootstrap as bootstrap  # noqa: E402


class V2BootstrapTests(unittest.TestCase):
    def test_adds_only_missing_entries_preserves_comments_and_never_readds_seen_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            desired = root / "services.yaml"
            seed = root / "seed.yaml"
            marker = root / ".bootstrap"
            desired.write_text(
                """# administrator comment
schemaVersion: 3
services:
  copyparty:
    name: Custom CopyParty
    managed: true
    workload:
      kind: daemon
    runtime:
      type: systemd
      unit: copyparty.service
""",
                encoding="utf-8",
            )
            seed.write_text(
                """schemaVersion: 3
services:
  copyparty:
    name: Baseline CopyParty
    managed: false
    workload:
      kind: daemon
    runtime:
      type: systemd
      unit: copyparty.service
  syncthing:
    name: Syncthing
    managed: false
    workload:
      kind: daemon
    runtime:
      type: systemd
      unit: syncthing.service
""",
                encoding="utf-8",
            )

            result = bootstrap.migrate(
                desired=desired,
                seed=seed,
                marker=marker,
                schema=SCHEMA,
                platform=None,
            )
            text = desired.read_text(encoding="utf-8")
            self.assertTrue(result["changed"])
            self.assertEqual(result["added"], ["services.syncthing"])
            self.assertIn("# administrator comment", text)
            self.assertIn("name: Custom CopyParty", text)
            self.assertIn("syncthing:", text)

            text = text.replace("  syncthing:\n", "  removed-syncthing:\n")
            desired.write_text(text, encoding="utf-8")
            second = bootstrap.migrate(
                desired=desired,
                seed=seed,
                marker=marker,
                schema=SCHEMA,
                platform=None,
            )
            self.assertFalse(second["changed"])
            self.assertEqual(second["reason"], "seed-current")
            self.assertNotIn("\n  syncthing:\n", desired.read_text(encoding="utf-8"))

    def test_new_seed_keys_are_added_without_readding_old_removed_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            desired = root / "services.yaml"
            seed = root / "seed.yaml"
            marker = root / ".bootstrap"
            desired.write_text("schemaVersion: 3\nservices: {}\n", encoding="utf-8")
            seed.write_text(
                """schemaVersion: 3
services:
  first:
    name: First
    workload: {kind: daemon}
    runtime: {type: systemd, unit: first.service}
""",
                encoding="utf-8",
            )
            bootstrap.migrate(desired=desired, seed=seed, marker=marker, schema=SCHEMA, platform=None)
            desired.write_text("schemaVersion: 3\nservices: {}\n", encoding="utf-8")
            seed.write_text(
                """schemaVersion: 3
services:
  first:
    name: First
    workload: {kind: daemon}
    runtime: {type: systemd, unit: first.service}
  second:
    name: Second
    workload: {kind: daemon}
    runtime: {type: systemd, unit: second.service}
""",
                encoding="utf-8",
            )
            result = bootstrap.migrate(desired=desired, seed=seed, marker=marker, schema=SCHEMA, platform=None)
            text = desired.read_text(encoding="utf-8")
            self.assertEqual(result["added"], ["services.second"])
            self.assertNotIn("\n  first:\n", text)
            self.assertIn("\n  second:\n", text)

    def test_invalid_new_seed_never_replaces_authority_or_advances_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            desired = root / "services.yaml"
            seed = root / "seed.yaml"
            marker = root / ".bootstrap"
            original = "schemaVersion: 3\nservices: {}\n"
            desired.write_text(original, encoding="utf-8")
            seed.write_text(
                """schemaVersion: 3
services:
  bad:
    name: Bad
    managed: false
    workload:
      kind: daemon
    runtime:
      type: systemd
      unit: ""
""",
                encoding="utf-8",
            )

            with self.assertRaises(Exception):
                bootstrap.migrate(
                    desired=desired,
                    seed=seed,
                    marker=marker,
                    schema=SCHEMA,
                    platform=None,
                )
            self.assertEqual(desired.read_text(encoding="utf-8"), original)
            self.assertFalse(marker.exists())

    def test_marker_records_complete_seen_seed_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            desired = root / "services.yaml"
            seed = root / "seed.yaml"
            marker = root / ".bootstrap"
            desired.write_text(
                """schemaVersion: 3
services:
  existing:
    name: Existing
    workload: {kind: daemon}
    runtime: {type: systemd, unit: existing.service}
""",
                encoding="utf-8",
            )
            seed.write_text(
                """schemaVersion: 3
services:
  existing:
    name: Baseline Existing
    workload: {kind: daemon}
    runtime: {type: systemd, unit: existing.service}
  caddy:
    name: Caddy
    managed: false
    workload:
      kind: daemon
    runtime:
      type: systemd
      unit: caddy.service
""",
                encoding="utf-8",
            )

            bootstrap.migrate(
                desired=desired,
                seed=seed,
                marker=marker,
                schema=SCHEMA,
                platform=None,
            )
            payload = json.loads(marker.read_text(encoding="utf-8"))
            self.assertEqual(payload["schemaVersion"], 2)
            self.assertEqual(payload["added"], ["services.caddy"])
            self.assertEqual(payload["seen"], ["services.caddy", "services.existing"])


if __name__ == "__main__":
    unittest.main()
