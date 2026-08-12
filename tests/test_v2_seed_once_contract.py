from __future__ import annotations

import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class V2SeedOnceContractTests(unittest.TestCase):
    def test_nix_records_preexisting_authority_before_base_seed_execstart(self) -> None:
        lifecycle = (ROOT / "modules/nas/config/managed-services-lifecycle.nix").read_text(encoding="utf-8")
        self.assertIn('desiredPath = "/var/lib/nas-control/services.yaml";', lifecycle)
        self.assertIn('initialSeedMarker = "/var/lib/nas-control/.managed-services-native-seed-v2";', lifecycle)
        self.assertIn("if [ ! -e ${lib.escapeShellArg desiredPath} ]; then", lifecycle)
        self.assertIn(": > ${lib.escapeShellArg initialSeedMarker}", lifecycle)
        self.assertIn("${pkgs.coreutils}/bin/rm -f ${lib.escapeShellArg initialSeedMarker}", lifecycle)

    def test_native_seed_uses_same_one_shot_marker_and_bootstrap_helper(self) -> None:
        native = (ROOT / "modules/nas/config/managed-services-native-services.nix").read_text(encoding="utf-8")
        self.assertIn('markerPath = "/var/lib/nas-control/.managed-services-native-seed-v2";', native)
        self.assertIn("${v2Source}/nas_v2_bootstrap.py", native)
        self.assertIn("--marker ${lib.escapeShellArg markerPath}", native)

    def test_bootstrap_contains_no_upgrade_merge_database(self) -> None:
        bootstrap = (ROOT / "services/nas_v2_bootstrap.py").read_text(encoding="utf-8")
        self.assertNotIn("_merge_new_keys", bootstrap)
        self.assertNotIn("_load_seen", bootstrap)
        self.assertNotIn('"seen"', bootstrap)
        self.assertIn('"authority-exists"', bootstrap)
        self.assertIn('"initial-seed"', bootstrap)


if __name__ == "__main__":
    unittest.main()
