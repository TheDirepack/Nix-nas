from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "evaluate-reference-configurations.sh"

EXPECTED_CONFIGURATIONS = {
    "nas-ci-ready",
    "nas-qemu",
    "nas-module-consumer",
    "nas-profile-core-storage",
    "nas-profile-identity-sharing",
    "nas-profile-observability",
    "nas-profile-virtualization",
    "nas-profile-local-ai",
    "nas-profile-all",
}
EXPECTED_CHECKS = {"nas-vm", "nas-vm-encrypted"}


class ReferenceConfigurationEvaluatorTests(unittest.TestCase):
    def run_evaluator(self, *, fail_on: str = "") -> tuple[subprocess.CompletedProcess[str], list[str]]:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            log = root / "nix.log"
            fake_nix = root / "nix"
            fake_nix.write_text(
                "#!/usr/bin/env bash\n"
                "set -eu\n"
                'printf \'%s\\n\' "$*" >> "$NAS_TEST_NIX_LOG"\n'
                'case "$*" in\n'
                '  *"${NAS_TEST_NIX_FAIL_ON:-__never__}"*) exit 42 ;;\n'
                "esac\n",
                encoding="utf-8",
            )
            fake_nix.chmod(0o755)
            env = os.environ.copy()
            env["PATH"] = f"{root}:{env.get('PATH', '')}"
            env["NAS_TEST_NIX_LOG"] = str(log)
            if fail_on:
                env["NAS_TEST_NIX_FAIL_ON"] = fail_on
            result = subprocess.run(
                ["bash", str(SCRIPT)],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
            return result, calls

    def test_evaluates_every_complete_reference_configuration_and_vm_check_once(self) -> None:
        result, calls = self.run_evaluator()
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertEqual(len(calls), len(EXPECTED_CONFIGURATIONS) + len(EXPECTED_CHECKS))

        seen_configurations = set()
        seen_checks = set()
        for call in calls:
            self.assertTrue(call.startswith("eval --raw .#"), call)
            if "nixosConfigurations." in call:
                name = call.split("nixosConfigurations.", 1)[1].split(".config.system.build", 1)[0]
                seen_configurations.add(name)
            elif "checks.x86_64-linux." in call:
                name = call.split("checks.x86_64-linux.", 1)[1].split(".drvPath", 1)[0]
                seen_checks.add(name)
            else:
                self.fail(f"unexpected nix evaluation call: {call}")

        self.assertEqual(seen_configurations, EXPECTED_CONFIGURATIONS)
        self.assertEqual(seen_checks, EXPECTED_CHECKS)
        self.assertNotIn("nixosConfigurations.nas.config", "\n".join(calls))
        self.assertIn("reference configuration evaluation passed", result.stdout)

    def test_first_failed_nix_evaluation_fails_the_helper_and_stops_later_calls(self) -> None:
        result, calls = self.run_evaluator(fail_on="nas-profile-observability")
        self.assertEqual(result.returncode, 42)
        self.assertTrue(any("nas-profile-observability" in call for call in calls))
        self.assertFalse(any("nas-profile-virtualization" in call for call in calls))
        self.assertNotIn("reference configuration evaluation passed", result.stdout)

    def test_machine_specific_nas_output_is_documented_as_intentionally_excluded(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("hardware-configuration.nix placeholder", text)
        self.assertIn("nixosConfigurations.nas", text)
        self.assertIn("inventing a root filesystem or bootloader device", text)


if __name__ == "__main__":
    unittest.main()
