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
            self.assertIn(f'{variable} = "1";', vm_common)

        # Keep exercising nas-preflight through the real first-run and installed
        # command surfaces; the VM-specific environment only removes work that
        # dedicated CI jobs have already qualified before QEMU starts.
        guest_test = GUEST_TEST.read_text(encoding="utf-8")
        self.assertIn('"runPreflight": true', guest_test)
        self.assertIn("NAS_PREFLIGHT_VERIFY_MANIFEST=0 nas-preflight", guest_test)


if __name__ == "__main__":
    unittest.main()
