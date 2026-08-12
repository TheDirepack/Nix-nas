from __future__ import annotations

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
    def test_initial_seed_replaces_only_fresh_stub_and_consumes_marker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            desired = root / "services.yaml"
            seed = root / "seed.yaml"
            marker = root / ".initial-seed"
            desired.write_text("schemaVersion: 3\nservices: {}\n", encoding="utf-8")
            marker.touch()
            seed.write_text(
                """schemaVersion: 3
services:
  demo:
    name: Demo
    workload: {kind: daemon}
    runtime: {type: systemd, unit: demo.service}
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

            self.assertTrue(result["changed"])
            self.assertEqual(result["reason"], "initial-seed")
            self.assertEqual(result["services"], 1)
            self.assertIn("demo:", desired.read_text(encoding="utf-8"))
            self.assertFalse(marker.exists())

    def test_existing_authority_is_never_merged_or_rewritten(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            desired = root / "services.yaml"
            seed = root / "seed.yaml"
            marker = root / ".initial-seed"
            original = """# administrator-owned
schemaVersion: 3
services:
  custom:
    name: Custom
    workload: {kind: daemon}
    runtime: {type: systemd, unit: custom.service}
"""
            desired.write_text(original, encoding="utf-8")
            seed.write_text(
                """schemaVersion: 3
services:
  new-built-in:
    name: New Built In
    workload: {kind: daemon}
    runtime: {type: systemd, unit: new-built-in.service}
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

            self.assertFalse(result["changed"])
            self.assertEqual(result["reason"], "authority-exists")
            self.assertEqual(desired.read_text(encoding="utf-8"), original)

    def test_concurrent_authority_creation_wins_even_with_initial_marker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            desired = root / "services.yaml"
            seed = root / "seed.yaml"
            marker = root / ".initial-seed"
            original = """schemaVersion: 3
services:
  operator-created:
    name: Operator Created
    workload: {kind: daemon}
    runtime: {type: systemd, unit: operator-created.service}
"""
            desired.write_text(original, encoding="utf-8")
            marker.touch()
            seed.write_text(
                """schemaVersion: 3
services:
  baseline:
    name: Baseline
    workload: {kind: daemon}
    runtime: {type: systemd, unit: baseline.service}
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

            self.assertFalse(result["changed"])
            self.assertEqual(result["reason"], "authority-created-concurrently")
            self.assertEqual(desired.read_text(encoding="utf-8"), original)
            self.assertFalse(marker.exists())

    def test_invalid_initial_seed_never_replaces_stub_or_consumes_marker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            desired = root / "services.yaml"
            seed = root / "seed.yaml"
            marker = root / ".initial-seed"
            original = "schemaVersion: 3\nservices: {}\n"
            desired.write_text(original, encoding="utf-8")
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
                bootstrap.migrate(
                    desired=desired,
                    seed=seed,
                    marker=marker,
                    schema=SCHEMA,
                    platform=None,
                )

            self.assertEqual(desired.read_text(encoding="utf-8"), original)
            self.assertTrue(marker.exists())


if __name__ == "__main__":
    unittest.main()
