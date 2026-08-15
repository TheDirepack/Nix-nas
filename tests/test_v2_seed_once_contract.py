from __future__ import annotations

import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class V2SeedOnceContractTests(unittest.TestCase):
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
        # Old split seeds must no longer declare their own bootstrap seeds.
        for path in (
            "modules/nas/config/managed-services-native-services.nix",
            "modules/nas/config/managed-services-platform-routes.nix",
        ):
            content = (ROOT / path).read_text(encoding="utf-8")
            self.assertNotIn('yamlFormat.generate "managed-services-', content)

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
