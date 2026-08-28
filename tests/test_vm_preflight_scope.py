from __future__ import annotations

import pathlib
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
VM_COMMON = ROOT / "tests" / "nixos" / "vm-common.nix"
GUEST_TEST = ROOT / "tests" / "vm" / "guest-test.sh"
FULL_SUITE = ROOT / "tests" / "vm" / "full-suite.sh"
PROFILE = ROOT / "scripts" / "lib" / "nas-vm-profile.sh"
FAILURE_INJECTION = ROOT / "tests" / "vm" / "cleanup-failure-injection.sh"


class VmPreflightScopeTests(unittest.TestCase):
    def test_full_stack_vm_does_not_rerun_ci_owned_qualification(self) -> None:
        vm_common = VM_COMMON.read_text(encoding="utf-8")
        for variable in (
            "NAS_PREFLIGHT_SKIP_TESTS",
            "NAS_PREFLIGHT_SKIP_TOOLING",
            "NAS_PREFLIGHT_SKIP_NIX",
            "NAS_PREFLIGHT_SKIP_COCKPIT_BUNDLE",
        ):
            self.assertIn(f"export {variable}=1", vm_common)

        # Keep exercising nas-preflight through the real first-run and installed
        # command surfaces; the VM wrapper only removes work that dedicated CI
        # jobs have already qualified before QEMU starts.
        guest_test = GUEST_TEST.read_text(encoding="utf-8")
        self.assertIn('"runPreflight": true', guest_test)
        self.assertIn("NAS_PREFLIGHT_VERIFY_MANIFEST=0 nas-preflight", guest_test)

    def test_full_stack_vm_profiles_existing_phase_boundaries(self) -> None:
        vm_common = VM_COMMON.read_text(encoding="utf-8")
        guest_test = GUEST_TEST.read_text(encoding="utf-8")
        profile = PROFILE.read_text(encoding="utf-8")

        self.assertIn("builtins.readFile ../../scripts/lib/nas-vm-profile.sh", vm_common)
        self.assertIn("nas_vm_profile_install", vm_common)
        self.assertIn("VM-PHASE-START:", profile)
        self.assertIn("VM-PHASE-TIMING:", profile)
        self.assertIn("VM-FIRST-RUN-START:", profile)
        self.assertIn("VM-FIRST-RUN-TIMING:", profile)
        self.assertIn("VM-PHASE-BUDGET:", profile)
        self.assertIn("nas_vm_cleanup_add nas_vm_profile_cleanup", profile)
        self.assertIn("python3*first-run-wizard.py*", profile)
        self.assertIn('log "Run the complete first-time setup GUI"', guest_test)
        self.assertIn('log "Browser-level authorization and deterministic bundle probes"', guest_test)
        self.assertIn('log "Observability, notifications, Syncthing, Vaultwarden, and Cockpit assets"', guest_test)
        self.assertIn('log "Final state"', guest_test)
        result = subprocess.run([str(FAILURE_INJECTION)], cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    def test_full_suite_surfaces_run_owned_cleanup_failures(self) -> None:
        full_suite = FULL_SUITE.read_text(encoding="utf-8")
        self.assertIn('source "$repo/scripts/lib/nas-vm-cleanup.sh"', full_suite)
        self.assertIn("nas_vm_cleanup_add cleanup_work", full_suite)
        self.assertIn("nas_vm_cleanup_add nas_vm_js_deps_cleanup", full_suite)
        self.assertIn('nas_vm_cockpit_js_deps_prepare "$repo"', full_suite)
        self.assertIn("NAS_PREFLIGHT_ALLOW_COCKPIT_NODE_MODULES=1", full_suite)
        self.assertIn("NAS_UNIT_TEST_TIMEOUT=300", full_suite)
        self.assertIn("trap nas_vm_cleanup_trap EXIT", full_suite)
        self.assertNotIn('nas_vm_js_deps_cleanup "$status" || :', full_suite)


if __name__ == "__main__":
    unittest.main()
