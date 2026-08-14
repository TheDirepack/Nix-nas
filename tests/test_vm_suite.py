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
    def _stage(self, source: pathlib.Path, cache: pathlib.Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
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
            self.assertFalse(list((state).glob(".reviewed-source.*")))

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

    def test_source_stage_rejects_traversal_and_incomplete_archives(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            traversal = root / "traversal"
            traversal.mkdir()
            (traversal / "MANIFEST.sha256").write_text("0" * 64 + "  ../outside.txt\n", encoding="utf-8")
            result = self._stage(traversal, root / "traversal-cache")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("invalid QEMU source path", result.stderr)

            incomplete = root / "incomplete"
            incomplete.mkdir()
            result = self._stage(incomplete, root / "incomplete-cache")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("requires MANIFEST.sha256", result.stderr)

    def test_source_stage_rejects_broken_symlinks_and_special_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            broken = root / "broken"
            broken.mkdir()
            (broken / "MANIFEST.sha256").write_text("0" * 64 + "  broken\n", encoding="utf-8")
            (broken / "broken").symlink_to("missing-target")
            result = self._stage(broken, root / "broken-cache")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("contains a symlink", result.stderr)

            special = root / "special"
            special.mkdir()
            (special / "MANIFEST.sha256").write_text("0" * 64 + "  fifo\n", encoding="utf-8")
            os.mkfifo(special / "fifo")
            result = self._stage(special, root / "special-cache")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("non-regular object", result.stderr)

    def test_source_stage_includes_untracked_worktree_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = pathlib.Path(tmp) / "source"
            cache = pathlib.Path(tmp) / "cache"
            source.mkdir()
            subprocess.run(["git", "init", "-q", str(source)], check=True)
            subprocess.run(["git", "-C", str(source), "config", "user.name", "VM test"], check=True)
            subprocess.run(["git", "-C", str(source), "config", "user.email", "vm-test@example.invalid"], check=True)
            (source / "tracked.txt").write_text("tracked\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(source), "add", "tracked.txt"], check=True)
            subprocess.run(["git", "-C", str(source), "commit", "-qm", "tracked"], check=True)
            (source / "untracked.txt").write_text("untracked\n", encoding="utf-8")
            result = self._stage(source, cache)
            self.assertEqual(result.returncode, 0, result.stderr)
            staged = cache / "state" / "reviewed-source"
            self.assertEqual((staged / "tracked.txt").read_text(encoding="utf-8"), "tracked\n")
            self.assertEqual((staged / "untracked.txt").read_text(encoding="utf-8"), "untracked\n")


if __name__ == "__main__":
    unittest.main()
