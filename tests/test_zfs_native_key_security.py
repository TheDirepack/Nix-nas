from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ZfsNativeKeySecurityTests(unittest.TestCase):
    def test_zfs_key_validation_is_native(self) -> None:
        source = (ROOT / "modules" / "nas" / "internal" / "zfs-tools.nix").read_text(encoding="utf-8")

        self.assertIn("load-key -L", source)
        self.assertIn("keyformat=hex", source)
        self.assertIn("^[0-9a-fA-F]{64}$", source)
        self.assertNotIn("keystore-sha256", source)
        self.assertNotIn("zfsKeyFingerprintProperty", source)
        self.assertNotIn("stored_fingerprint", source)
        self.assertNotIn("staged_fingerprint", source)
        self.assertNotIn("sha256sum", source)

    def test_root_dataset_bootstrap_requires_live_operation_coordination(self) -> None:
        zfs_source = (ROOT / "modules" / "nas" / "internal" / "zfs-tools.nix").read_text(encoding="utf-8")
        setup_source = (ROOT / "services" / "nas_setup.py").read_text(encoding="utf-8")
        self.assertIn("NAS_OPERATION_COORDINATION_TOKEN", zfs_source)
        self.assertIn("^[0-9a-f]{32}$", zfs_source)
        self.assertIn('coordinated_child(["nas-zfs-create-encrypted-dataset"])', setup_source)

    def test_base_exports_no_parallel_zfs_key_fingerprint_authority(self) -> None:
        source = (ROOT / "modules" / "nas" / "internal" / "base.nix").read_text(encoding="utf-8")

        self.assertNotIn("zfsKeyFingerprintProperty", source)
        self.assertNotIn("org.nixos:keystore-sha256", source)


if __name__ == "__main__":
    unittest.main()
