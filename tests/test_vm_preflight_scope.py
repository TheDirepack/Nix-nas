from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
VM_COMMON = ROOT / "tests" / "nixos" / "vm-common.nix"
GUEST_TEST = ROOT / "tests" / "vm" / "guest-test.sh"


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

        self.assertIn("VM-PHASE-TIMING:", vm_common)
        self.assertIn("trap 'nas_vm_profile_phase \"$BASH_COMMAND\"' DEBUG", vm_common)
        self.assertIn('log "Run the complete first-time setup CLI"', guest_test)
        self.assertIn('log "Browser-level Authentik and capability authorization"', guest_test)
        self.assertIn('log "Observability, notifications, Syncthing, Vaultwarden, and Cockpit assets"', guest_test)
        self.assertIn('log "Final state"', guest_test)


if __name__ == "__main__":
    unittest.main()
