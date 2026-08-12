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
import nas_v2_spec as spec  # noqa: E402


class V2BootstrapDependencyErrorTests(unittest.TestCase):
    def test_unknown_release_seed_dependency_is_not_silently_deferred(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            desired = root / "services.yaml"
            seed = root / "seed.yaml"
            marker = root / ".bootstrap"
            desired.write_text("schemaVersion: 3\nservices: {}\n", encoding="utf-8")
            seed.write_text(
                """schemaVersion: 3
services:
  frontend:
    name: Frontend
    workload: {kind: daemon}
    runtime: {type: systemd, unit: frontend.service}
    dependencies:
      - service: misspelled-backend
        condition: started
""",
                encoding="utf-8",
            )

            with self.assertRaises(spec.ManagedServicesV2Error) as raised:
                bootstrap.migrate(
                    desired=desired,
                    seed=seed,
                    marker=marker,
                    schema=SCHEMA,
                    platform=None,
                )

            self.assertEqual(raised.exception.code, "missing-reference")
            self.assertFalse(marker.exists())
            self.assertEqual(desired.read_text(encoding="utf-8"), "schemaVersion: 3\nservices: {}\n")


if __name__ == "__main__":
    unittest.main()
