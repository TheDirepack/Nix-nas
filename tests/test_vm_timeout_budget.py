from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tests" / "vm" / "timeout-budget.json"
TIMEOUT_HELPER = ROOT / "tests" / "vm" / "timeout-budget.sh"
INTEGRATION = ROOT / "tests" / "nixos" / "integration.nix"
GUEST_TEST = ROOT / "tests" / "vm" / "guest-test.sh"
QEMU = ROOT / "scripts" / "qemu-test.sh"


class VmTimeoutBudgetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))

    def test_manifest_derives_guest_watchdog_and_is_used_by_wrappers(self) -> None:
        expected = (
            sum(
                phase["fixedSeconds"]
                + phase["ordinaryWaits"] * self.manifest["ordinaryWaitSeconds"]
                + sum(self.manifest["timeouts"][key] for key in phase["timeoutKeys"])
                for phase in self.manifest["phases"]
            )
            + self.manifest["slackSeconds"]
        )
        result = subprocess.run(
            [
                "bash",
                "-c",
                f"source {TIMEOUT_HELPER!s}; nas_vm_guest_watchdog_seconds",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            env={**os.environ, "NAS_VM_TIMEOUT_BUDGET_FILE": str(MANIFEST)},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(int(result.stdout.strip()), expected)
        integration = INTEGRATION.read_text(encoding="utf-8")
        qemu = QEMU.read_text(encoding="utf-8")
        self.assertIn("timeoutBudget = builtins.fromJSON", integration)
        self.assertIn("guestWatchdog", integration)
        self.assertIn("nas_vm_guest_watchdog_seconds", qemu)
        self.assertIn("nas_vm_timeout_value", GUEST_TEST.read_text(encoding="utf-8"))

    def test_every_guest_phase_label_has_a_manifest_budget(self) -> None:
        guest = GUEST_TEST.read_text(encoding="utf-8")
        labels = set(re.findall(r'^log "([^"]+)"$', guest, re.MULTILINE))
        manifest_labels = {phase["label"] for phase in self.manifest["phases"]}
        self.assertEqual(labels, manifest_labels)


if __name__ == "__main__":
    unittest.main()
