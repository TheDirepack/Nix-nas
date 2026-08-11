from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_readiness as readiness  # noqa: E402


class V2ReadinessTests(unittest.TestCase):
    def test_existing_path_is_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "ready"
            path.write_text("ok", encoding="utf-8")
            self.assertTrue(readiness.probe_ready({"type": "path", "path": str(path)}, systemctl="/bin/false"))

    def test_systemd_probe_uses_fixed_argv(self):
        self.assertTrue(
            readiness.probe_ready(
                {"type": "systemd", "unit": "demo.service"},
                systemctl="/bin/true",
            )
        )
        self.assertFalse(
            readiness.probe_ready(
                {"type": "systemd", "unit": "demo.service"},
                systemctl="/bin/false",
            )
        )

    def test_wait_ready_completes_without_resident_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "ready"
            path.touch()
            readiness.wait_ready(
                {
                    "timeoutSeconds": 1,
                    "intervalMilliseconds": 50,
                    "probes": [{"type": "path", "path": str(path)}],
                }
            )

    def test_unsafe_readiness_path_is_rejected(self):
        with self.assertRaisesRegex(readiness.ReadinessError, "absolute"):
            readiness.probe_ready({"type": "path", "path": "../ready"}, systemctl="/bin/false")


if __name__ == "__main__":
    unittest.main()
