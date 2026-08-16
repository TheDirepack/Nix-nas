from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
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

    def test_outer_budgets_are_derived_from_guest_and_follow_on_phases(self) -> None:
        helper_script = """
source "$1"
printf '%s\n' "$(nas_vm_integration_timeout_seconds)"
printf '%s\n' "$(nas_vm_encrypted_timeout_seconds)"
printf '%s\n' "$(nas_vm_installer_timeout_seconds)"
printf '%s\n' "$(nas_vm_full_suite_timeout_seconds)"
printf '%s\n' "$(nas_vm_ci_integration_timeout_seconds)"
printf '%s\n' "$(nas_vm_ci_installer_timeout_seconds)"
"""
        result = subprocess.run(
            ["bash", "-c", helper_script, "budget", str(TIMEOUT_HELPER)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            env={**os.environ, "NAS_VM_TIMEOUT_BUDGET_FILE": str(MANIFEST)},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        guest = int(
            subprocess.run(
                ["bash", "-c", 'source "$1"; nas_vm_guest_watchdog_seconds', "guest", str(TIMEOUT_HELPER)],
                cwd=ROOT,
                env={**os.environ, "NAS_VM_TIMEOUT_BUDGET_FILE": str(MANIFEST)},
                text=True,
                capture_output=True,
                check=True,
            ).stdout.strip()
        )
        integration, encrypted, installer, full_suite, ci_integration, ci_installer = map(
            int, result.stdout.splitlines()
        )
        outer = self.manifest["outer"]
        self.assertEqual(
            integration,
            guest
            + self.manifest["timeouts"]["secretAdversarial"]
            + self.manifest["timeouts"]["installedSmoke"]
            + outer["nativeBoot"]
            + outer["nativeShutdown"]
            + outer["slack"],
        )
        self.assertEqual(
            encrypted,
            self.manifest["timeouts"]["encryptedGuest"]
            + outer["nativeBoot"]
            + outer["nativeShutdown"]
            + outer["slack"],
        )
        self.assertEqual(
            installer,
            guest
            + self.manifest["timeouts"]["reconfigure"]
            + outer["installerSetup"]
            + outer["installerBoot"]
            + outer["installerReboot"]
            + outer["nativeShutdown"]
            + outer["slack"],
        )
        self.assertEqual(full_suite, outer["fullSuiteSetup"] + integration)
        self.assertEqual(ci_integration, integration + outer["ciSetup"])
        self.assertEqual(ci_installer, installer + outer["ciSetup"])

    def test_manifest_phase_labels_match_the_guest_runner(self) -> None:
        manifest_labels = [phase["label"] for phase in self.manifest["phases"]]
        guest_labels = []
        for line in GUEST_TEST.read_text(encoding="utf-8").splitlines():
            if line.startswith('log "') and line.endswith('"'):
                guest_labels.append(line[5:-1])
        self.assertEqual(guest_labels, manifest_labels)

    def test_every_guest_phase_label_has_a_manifest_budget(self) -> None:
        manifest_labels = [phase["label"] for phase in self.manifest["phases"]]
        for label in manifest_labels:
            with self.subTest(label=label):
                result = subprocess.run(
                    [
                        "bash",
                        "-c",
                        'source "$1"; nas_vm_phase_metadata "$2"',
                        "phase-metadata",
                        str(TIMEOUT_HELPER),
                        label,
                    ],
                    cwd=ROOT,
                    text=True,
                    capture_output=True,
                    check=False,
                    env={**os.environ, "NAS_VM_TIMEOUT_BUDGET_FILE": str(MANIFEST)},
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                phase_id, budget = result.stdout.strip().split("\t")
                self.assertEqual(
                    phase_id, next(phase["id"] for phase in self.manifest["phases"] if phase["label"] == label)
                )
                self.assertGreater(int(budget), 0)

    def test_real_phase_timeout_reports_the_failed_phase_and_outer_budget(self) -> None:
        scaled = json.loads(json.dumps(self.manifest))
        scaled["ordinaryWaitSeconds"] = 1
        scaled["slackSeconds"] = 2
        for phase in scaled["phases"]:
            phase["fixedSeconds"] = 1
            phase["ordinaryWaits"] = 0
            phase["timeoutKeys"] = []

        with tempfile.TemporaryDirectory() as temporary:
            manifest = pathlib.Path(temporary) / "timeout-budget.json"
            manifest.write_text(json.dumps(scaled), encoding="utf-8")
            env = {**os.environ, "NAS_VM_TIMEOUT_BUDGET_FILE": str(manifest)}
            label = scaled["phases"][3]["label"]
            phase_script = r"""
set -Eeuo pipefail
source "$1"
metadata="$(nas_vm_phase_metadata "$2")"
IFS=$'\t' read -r phase_id budget <<<"$metadata"
printf 'VM-PHASE-START: %s\n' "$phase_id"
if timeout --foreground "$budget" bash -c 'sleep "$1"' phase "$3"; then
  printf 'VM-PHASE-COMPLETE: %s\n' "$phase_id"
else
  status=$?
  printf 'VM-PHASE-FAILED: %s: %s\n' "$phase_id" "$status"
  exit "$status"
fi
"""
            slow = subprocess.run(
                ["bash", "-c", phase_script, "phase", str(TIMEOUT_HELPER), label, "2"],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(slow.returncode, 124, slow.stderr + slow.stdout)
            self.assertIn(f"VM-PHASE-FAILED: {scaled['phases'][3]['id']}: 124", slow.stdout)

            watchdog = int(
                subprocess.run(
                    ["bash", "-c", 'source "$1"; nas_vm_guest_watchdog_seconds', "watchdog", str(TIMEOUT_HELPER)],
                    cwd=ROOT,
                    env=env,
                    text=True,
                    capture_output=True,
                    check=True,
                ).stdout.strip()
            )
            self.assertEqual(watchdog, len(scaled["phases"]) + scaled["slackSeconds"])
            outer_script = r"""
set -Eeuo pipefail
source "$1"
while IFS= read -r label; do
  metadata="$(nas_vm_phase_metadata "$label")"
  IFS=$'\t' read -r phase_id budget <<<"$metadata"
  timeout --foreground "$budget" bash -c 'sleep "$1"' phase 0.05
  printf 'VM-PHASE-COMPLETE: %s\n' "$phase_id"
done < <(jq -er '.phases[].label' "$NAS_VM_TIMEOUT_BUDGET_FILE")
"""
            complete = subprocess.run(
                [
                    "timeout",
                    "--foreground",
                    str(watchdog),
                    "bash",
                    "-c",
                    outer_script,
                    "outer",
                    str(TIMEOUT_HELPER),
                ],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(complete.returncode, 0, complete.stderr + complete.stdout)
            self.assertEqual(complete.stdout.count("VM-PHASE-COMPLETE:"), len(scaled["phases"]))


if __name__ == "__main__":
    unittest.main()
