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
GUEST_TEST = ROOT / "tests" / "vm" / "guest-test.sh"
FIRST_RUN_BROWSER = ROOT / "tests" / "browser" / "first-run-wizard.py"
FINAL_BROWSER = ROOT / "scripts" / "qemu-final-browser.sh"
VM_COMMON = ROOT / "tests" / "nixos" / "vm-common.nix"


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
        final_browser = FINAL_BROWSER.read_text(encoding="utf-8")
        installer = (ROOT / "tests" / "vm" / "install-system.sh").read_text(encoding="utf-8")
        install_expect = (ROOT / "tests" / "vm" / "install.expect").read_text(encoding="utf-8")
        guest_suite = GUEST_SUITE.read_text(encoding="utf-8")
        guest_test = GUEST_TEST.read_text(encoding="utf-8")
        first_run_browser = FIRST_RUN_BROWSER.read_text(encoding="utf-8")
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
        self.assertIn("nas_qemu_pid_from_pidfile", qemu)
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
        self.assertIn('"user,id=net0,hostfwd=', qemu)
        self.assertIn('HOST_BIND_ADDRESS="${NAS_QEMU_HOST_BIND_ADDRESS:-127.0.0.1}"', qemu)
        self.assertIn("qemu_network_args", qemu)
        self.assertNotIn("hostfwd=tcp:$HOST_BIND_ADDRESS:$HTTP_PORT-:80", qemu)
        self.assertIn("hostfwd=tcp:$HOST_BIND_ADDRESS:$HTTPS_PORT-:443", qemu)
        self.assertNotIn("hostfwd=tcp:$HOST_BIND_ADDRESS:$COCKPIT_PORT-:9092", qemu)
        self.assertIn('HOST_BIND_ADDRESS="${NAS_QEMU_HOST_BIND_ADDRESS:-127.0.0.1}"', final_browser)
        self.assertIn("hostfwd=tcp:$HOST_BIND_ADDRESS:$COCKPIT_PORT-:9092", final_browser)
        self.assertNotIn("-netdev tap", qemu)
        self.assertNotIn("bridge=", qemu)
        self.assertIn("sync_source_to_guest", qemu)
        self.assertIn("selected.extend(", qemu)
        self.assertIn('policy = "git-tracked-and-worktree"', qemu)
        self.assertIn('tar --exclude=./.nas-source-selection.json -C "$source_stage" -cf - .', qemu)
        self.assertIn("git -C /var/lib/nas-test/repo config gc.auto 0", qemu)
        self.assertIn("nix develop path:/var/lib/nas-test/repo#test", qemu)
        self.assertIn(
            "systemctl start caddy.service authentik-worker.service authentik.service nas-cockpit-sso.service",
            qemu,
        )
        self.assertIn(
            "systemctl start nas-authentik-proxy-outpost.service || true",
            qemu,
        )
        self.assertIn(
            "until systemctl is-active --quiet nas-authentik-proxy-outpost.service",
            qemu,
        )
        self.assertIn("./scripts/preflight.sh", guest_suite)
        self.assertIn("./scripts/run-fuzz.py", guest_suite)
        self.assertIn("nas-vm-guest-test /dev/vdb", guest_suite)
        self.assertIn("args.keepass_password_file", first_run_browser)
        self.assertNotIn("args.kee_pass_password_file", first_run_browser)
        self.assertIn("def search_roots", first_run_browser)
        self.assertIn("child.shadow_root", first_run_browser)
        self.assertIn('origin.rstrip("/") + "/setup/"', first_run_browser)
        self.assertIn('send("#wizard-admin-password-confirm"', first_run_browser)
        self.assertIn('send("#wizard-keepass-password-confirm"', first_run_browser)
        self.assertIn('click_button("Run setup")', first_run_browser)
        self.assertNotIn("#first-start-", first_run_browser)
        self.assertIn(
            "export NAS_VM_TIMEOUT_BUDGET_FILE=/var/lib/nas-test/repo/tests/vm/timeout-budget.json",
            VM_COMMON.read_text(encoding="utf-8"),
        )
        self.assertIn("systemd-socket-activate", guest_test)
        self.assertIn("systemd-socket-proxyd", guest_test)
        self.assertIn('public_address="${NAS_BROWSER_HOST_ADDRESS:-127.0.0.1}"', guest_test)
        self.assertIn('"$activate_path" --listen "$public_address:$public_port"', guest_test)
        self.assertNotIn('"$activate_path" --accept --listen', guest_test)
        self.assertNotIn("--exit-idle-time=300s", guest_test)
        self.assertIn("run_setup_reboot_e2e", qemu)
        self.assertIn("setupRebootLifecycle", qemu)
        self.assertIn("nas-vm-guest-test --setup-reboot-e2e --start", qemu)

    def test_first_run_uses_the_bootstrap_then_promoted_local_administrator(self) -> None:
        guest = GUEST_TEST.read_text(encoding="utf-8")
        self.assertIn('administrator="nas-bootstrap"', guest)
        self.assertIn("/var/lib/nas-setup/local-administrator.json", guest)
        self.assertIn("chown nas-bootstrap:users /var/lib/nas-test/setup/first-run.json", guest)
        self.assertIn("install -d -m 0700 -o nas-bootstrap -g users /var/lib/nas-test/setup", guest)
        self.assertIn('.result.localAdministrator.username == "nasadmin"', guest)
        self.assertIn("getent passwd nas-bootstrap", guest)
        self.assertNotIn("chown operator:users /var/lib/nas-test/setup", guest)
        self.assertIn('runuser -u "$administrator" -- env HOME="$home"', guest)
        self.assertIn("--setup-reboot-e2e", (ROOT / "tests/nixos/vm-common.nix").read_text(encoding="utf-8"))

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

    def test_source_stage_fails_on_a_manifest_digest_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = pathlib.Path(tmp) / "source"
            source.mkdir()
            (source / "payload.txt").write_text("actual\n", encoding="utf-8")
            (source / "MANIFEST.sha256").write_text(
                "0" * 64 + "  payload.txt\n",
                encoding="utf-8",
            )
            result = self._stage(source, pathlib.Path(tmp) / "cache")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("manifest digest mismatch", result.stderr)

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
