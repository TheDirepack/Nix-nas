from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile
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
        install_expect = (ROOT / "tests" / "vm" / "install.expect").read_text(encoding="utf-8")
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
        self.assertIn('OS_DISK_GIB="${NAS_QEMU_OS_DISK_GIB:-64}"', qemu)
        self.assertIn('BASELINE_SNAPSHOT="nas-test-clean"', qemu)
        self.assertIn("restore_persistent_baseline", qemu)
        self.assertIn("CACHE_MARKER_CONTENT=", qemu)
        self.assertIn("qemu_pid_from_pidfile", qemu)
        self.assertIn("QEMU source path is missing", qemu)
        self.assertIn("realpath", qemu)
        self.assertIn('qemu-img snapshot -c "$BASELINE_SNAPSHOT"', qemu)
        self.assertIn('qemu-img snapshot -a "$BASELINE_SNAPSHOT"', qemu)
        self.assertIn('mount -t ext4 "$ROOT_PARTITION" "$TARGET"', installer)
        self.assertIn('fallocate -l "${NAS_INSTALL_SWAP_GIB:-8}G" "$swap_file"', installer)
        self.assertIn(
            'swapDevices = [{ device = "/swapfile"; }];',
            (ROOT / "tests" / "nixos" / "qemu-installed.nix").read_text(encoding="utf-8"),
        )
        self.assertNotIn('send -- "root\\r"', install_expect)
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

    def test_reset_and_clean_refuse_unmanaged_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cache = pathlib.Path(tmp) / "cache"
            cache.mkdir()
            env = {**os.environ, "NAS_QEMU_CACHE_DIR": str(cache)}
            reset = subprocess.run(
                ["bash", str(QEMU), "persistent-reset"],
                cwd=ROOT,
                env={**env, "NAS_QEMU_STATE_DIR": str(pathlib.Path(tmp) / "outside")},
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(reset.returncode, 0)
            self.assertIn("state path must be below", reset.stderr)
            clean = subprocess.run(
                ["bash", str(QEMU), "clean"],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(clean.returncode, 0)
            self.assertTrue(cache.exists())
            self.assertIn("unrecognized QEMU cache", clean.stderr)

    def test_source_stage_fails_on_a_manifest_entry_missing_from_the_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = pathlib.Path(tmp) / "source"
            cache = pathlib.Path(tmp) / "cache"
            state = cache / "state"
            source.mkdir()
            (source / "MANIFEST.sha256").write_text(
                "0000000000000000000000000000000000000000000000000000000000000000  missing.txt\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                ["bash", str(QEMU), "stage-source"],
                cwd=ROOT,
                env={
                    **os.environ,
                    "NAS_QEMU_SOURCE_ROOT": str(source),
                    "NAS_QEMU_CACHE_DIR": str(cache),
                    "NAS_QEMU_STATE_DIR": str(state),
                },
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("QEMU source path is missing", result.stderr)

    def test_source_stage_does_not_skip_a_missing_ignored_manifest_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = pathlib.Path(tmp) / "source"
            cache = pathlib.Path(tmp) / "cache"
            source.mkdir()
            (source / "MANIFEST.sha256").write_text(
                "0000000000000000000000000000000000000000000000000000000000000000  node_modules/missing.js\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                ["bash", str(QEMU), "stage-source"],
                cwd=ROOT,
                env={
                    **os.environ,
                    "NAS_QEMU_SOURCE_ROOT": str(source),
                    "NAS_QEMU_CACHE_DIR": str(cache),
                    "NAS_QEMU_STATE_DIR": str(cache / "state"),
                },
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("QEMU source path is missing", result.stderr)


if __name__ == "__main__":
    unittest.main()
