from __future__ import annotations

import pathlib
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "scripts" / "vm-pytest.sh"
QEMU = ROOT / "scripts" / "qemu-test.sh"
GUEST_SUITE = ROOT / "tests" / "vm" / "full-suite.sh"


class VmSuiteWrapperTests(unittest.TestCase):
    def test_help_is_safe_and_describes_the_persistent_vm_contract(self) -> None:
        result = subprocess.run(
            ["bash", str(WRAPPER), "--help"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("persistent NixOS QEMU VM", result.stdout)
        self.assertIn("host bridge", result.stdout)
        self.assertNotIn("nix build", result.stdout)

    def test_wrapper_uses_the_existing_official_iso_lifecycle(self) -> None:
        wrapper = WRAPPER.read_text(encoding="utf-8")
        qemu = QEMU.read_text(encoding="utf-8")
        installer = (ROOT / "tests" / "vm" / "install-system.sh").read_text(encoding="utf-8")
        guest_suite = GUEST_SUITE.read_text(encoding="utf-8")
        for mode in (
            "persistent-start",
            "persistent-test",
            "persistent-stop",
            "persistent-reset",
        ):
            self.assertIn(mode, qemu)
        self.assertIn('exec "$ROOT/scripts/qemu-test.sh" persistent-test', wrapper)
        self.assertIn("tests/vm/install.expect", qemu)
        self.assertIn("nixos-install", installer)
        self.assertIn("-netdev user,id=net0", qemu)
        self.assertNotIn("-netdev tap", qemu)
        self.assertNotIn("bridge=", qemu)
        self.assertIn("sync_source_to_guest", qemu)
        self.assertIn("selected.extend(", qemu)
        self.assertIn('policy = "git-tracked-and-worktree"', qemu)
        self.assertIn('tar --exclude=./.nas-source-selection.json -C "$source_stage" -cf - .', qemu)
        self.assertIn("nix develop path:/var/lib/nas-test/repo#test", qemu)
        self.assertIn("./scripts/preflight.sh", guest_suite)
        self.assertIn("./scripts/run-fuzz.py", guest_suite)
        self.assertIn("nas-vm-guest-test /dev/vdb", guest_suite)

    def test_persistent_controls_are_additive_to_existing_ci_modes(self) -> None:
        qemu = QEMU.read_text(encoding="utf-8")
        self.assertIn("static) run_static", qemu)
        self.assertIn("native) run_native", qemu)
        self.assertIn("installer) run_installer", qemu)
        self.assertIn("all) run_static; run_native; run_installer", qemu)
        self.assertNotIn("nix develop .#test", qemu)


if __name__ == "__main__":
    unittest.main()
