from __future__ import annotations

import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class V2PlatformRuntimeOwnershipTests(unittest.TestCase):
    def test_libvirt_daemon_is_platform_substrate_not_application_lifecycle(self) -> None:
        seed = (ROOT / "modules/nas/config/managed-services-native-services.nix").read_text(encoding="utf-8")

        self.assertIn(
            'virtualization = platformService ((daemon "libvirtd.service" "libvirt virtual-machine runtime") // {',
            seed,
        )
        self.assertIn('vm-storage = (job "nas-vm-storage.service" "Prepare VM storage") // {', seed)
        self.assertIn(
            'vm-storage-pool = (daemon "nas-vm-storage-pool.service" "Activate the ZFS-backed libvirt storage pool") // {',
            seed,
        )
        self.assertNotIn('virtualization = (daemon "libvirtd.service"', seed)


if __name__ == "__main__":
    unittest.main()
