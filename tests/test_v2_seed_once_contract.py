from __future__ import annotations

import os
import pathlib
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class V2SeedOnceContractTests(unittest.TestCase):
    def test_vm_authority_reads_follow_the_completed_storage_setup(self) -> None:
        guest = (ROOT / "tests/vm/guest-test.sh").read_text(encoding="utf-8")
        setup_complete = guest.index('pass "GUI first start created the expected storage, accounts, and administrator"')
        for command in (
            "nas-managed-services-control status >/dev/null",
            "nas-managed-services-control document >/dev/null",
        ):
            with self.subTest(command=command):
                self.assertGreater(guest.index(command), setup_complete)

    def test_seed_marker_is_written_only_after_the_exact_dataset_check(self) -> None:
        source = (ROOT / "modules/nas/config/managed-services-lifecycle.nix").read_text(encoding="utf-8")
        script = source.split("preStart = lib.mkBefore ''", 1)[1].split("\n        '';", 1)[0]
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            authority = root / "nas-control"
            desired = authority / "services.yaml"
            marker = authority / ".managed-services-native-seed-v2"
            checker = root / "nas-zfs-mount-check"
            checker.write_text('#!/bin/sh\nexit "$MOUNT_STATUS"\n', encoding="utf-8")
            checker.chmod(0o755)
            install = shutil.which("install")
            assert install is not None
            coreutils = pathlib.Path(install).parent.parent
            script = script.replace(
                "${nasInternal.nasZfsMountCheck}/bin/nas-zfs-mount-check", shlex.quote(str(checker))
            )
            script = script.replace("${pkgs.coreutils}", str(coreutils))
            script = script.replace("${lib.escapeShellArg desiredPath}", shlex.quote(str(desired)))
            script = script.replace("${lib.escapeShellArg initialSeedMarker}", shlex.quote(str(marker)))
            script = script.replace("/var/lib/nas-control", shlex.quote(str(authority)))
            script = script.replace("-o root -g nas-operations", f"-o {os.geteuid()} -g {os.getegid()}")

            def invoke(status: int) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    ["bash", "-c", "set -euo pipefail\n" + script],
                    env={**os.environ, "MOUNT_STATUS": str(status)},
                    text=True,
                    capture_output=True,
                    check=False,
                )

            for status in (1, 75):
                with self.subTest(status=status):
                    result = invoke(status)
                    self.assertEqual(result.returncode, status, result.stderr)
                    self.assertFalse(authority.exists())
            self.assertEqual(invoke(0).returncode, 0)
            self.assertTrue(marker.is_file())
            marker.unlink()
            desired.write_text("operator-owned\n", encoding="utf-8")
            self.assertEqual(invoke(0).returncode, 0)
            self.assertFalse(marker.exists())
            self.assertEqual(desired.read_text(encoding="utf-8"), "operator-owned\n")

    def test_nix_records_missing_authority_before_base_seed_execstart(self) -> None:
        lifecycle = (ROOT / "modules/nas/config/managed-services-lifecycle.nix").read_text(encoding="utf-8")
        self.assertIn('desiredPath = "/var/lib/nas-control/services.yaml";', lifecycle)
        self.assertIn('initialSeedMarker = "/var/lib/nas-control/.managed-services-native-seed-v2";', lifecycle)
        self.assertIn("if [ ! -e ${lib.escapeShellArg desiredPath} ]; then", lifecycle)
        self.assertIn(": > ${lib.escapeShellArg initialSeedMarker}", lifecycle)
        self.assertNotIn("rm -f ${lib.escapeShellArg initialSeedMarker}", lifecycle)

    def test_native_seed_uses_same_one_shot_marker_and_bootstrap_helper(self) -> None:
        seed = (ROOT / "modules/nas/config/managed-services-seed-v2.nix").read_text(encoding="utf-8")
        self.assertIn('markerPath = "/var/lib/nas-control/.managed-services-native-seed-v2";', seed)
        self.assertIn("${v2Source}/nas_v2_bootstrap.py", seed)
        self.assertIn("--marker ${lib.escapeShellArg markerPath}", seed)
        # Old split seed modules are gone; managed-services-seed-v2.nix is the sole authority.
        for path in (
            "modules/nas/config/managed-services-native-services.nix",
            "modules/nas/config/managed-services-platform-routes.nix",
        ):
            self.assertFalse((ROOT / path).exists(), f"split seed {path} must stay deleted")

    def test_seed_aggregation_contains_all_built_in_categories(self) -> None:
        seed = (ROOT / "modules/nas/config/managed-services-seed-v2.nix").read_text(encoding="utf-8")
        # Must contain baseline, operations, backup, and platform fragments in one document.
        self.assertIn("baselineServices", seed)
        self.assertIn("operationServices", seed)
        self.assertIn("backupResources", seed)
        self.assertIn("backupServices", seed)
        self.assertIn("platformServices", seed)
        self.assertIn("mergedServices = baselineServices // operationServices", seed)
        self.assertIn("storageResources = mergedStorageResources", seed)
        self.assertIn("schemaVersion = 3", seed)

    def test_bootstrap_contains_no_upgrade_merge_database(self) -> None:
        bootstrap = (ROOT / "services/nas_v2_bootstrap.py").read_text(encoding="utf-8")
        self.assertNotIn("_merge_new_keys", bootstrap)
        self.assertNotIn("_load_seen", bootstrap)
        self.assertNotIn('"seen"', bootstrap)
        self.assertIn('"authority-exists"', bootstrap)
        self.assertIn('"initial-seed"', bootstrap)


if __name__ == "__main__":
    unittest.main()
