from __future__ import annotations

import pathlib
import re
import sys
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_state  # noqa: E402


class V2StateAuthorityContractTests(unittest.TestCase):
    def test_generated_state_registry_tracks_only_services_yaml_for_managed_services(self) -> None:
        account_tools = (ROOT / "modules/nas/internal/account-tools.nix").read_text(encoding="utf-8")
        managed = account_tools.split('name = "managed-services";', 1)[1].split("})", 1)[0]
        self.assertIn('source = "/var/lib/nas-control/services.yaml";', managed)
        self.assertIn('owner = "root";', managed)
        self.assertIn('group = "nas-operations";', managed)
        self.assertIn('rootMode = "0640";', managed)
        self.assertNotIn('source = "/var/lib/nas-control";', managed)

    def test_installed_nas_state_uses_generated_registry_not_legacy_feature_root(self) -> None:
        account_tools = (ROOT / "modules/nas/internal/account-tools.nix").read_text(encoding="utf-8")
        wrapper = account_tools.split("nasState = pkgs.writeShellApplication {", 1)[1].split("nasDoctorScript =", 1)[0]
        self.assertIn("NAS_STATE_REGISTRY_REQUIRED=1", wrapper)
        self.assertNotIn("NAS_FEATURE_STATE_ROOT", wrapper)

    def test_registry_contains_only_control_configuration(self) -> None:
        account_tools = (ROOT / "modules/nas/internal/account-tools.nix").read_text(encoding="utf-8")
        registry = account_tools.split("stateRegistry =", 1)[1].split("stateQuiesceUnits =", 1)[0]
        self.assertEqual(
            re.findall(r'name = "([^"]+)";', registry),
            ["managed-services", "copyparty-config", "networkmanager", "scheduler"],
        )

    def test_copyparty_registry_uses_canonical_zfs_authority_not_public_symlink(self) -> None:
        account_tools = (ROOT / "modules/nas/internal/account-tools.nix").read_text(encoding="utf-8")
        copyparty = account_tools.split('name = "copyparty-config";', 1)[1].split("})", 1)[0]

        self.assertIn("copypartyUserConfigDir", account_tools.split("inherit (args)", 1)[1].split(";", 1)[0])
        self.assertIn("source = copypartyUserConfigDir;", copyparty)
        self.assertIn("sensitive = true;", copyparty)
        self.assertIn('owner = "copyparty";', copyparty)
        self.assertIn('rootMode = "0770";', copyparty)
        self.assertNotIn('source = "/var/lib/copyparty";', copyparty)

    def test_export_does_not_stop_application_workloads(self) -> None:
        account_tools = (ROOT / "modules/nas/internal/account-tools.nix").read_text(encoding="utf-8")
        self.assertIn("stateQuiesceUnits = [ ];", account_tools)
        self.assertNotIn("pkgs.postgresql", account_tools)

    def test_network_configuration_remains_sensitive_and_restore_restarts_consumers(self) -> None:
        account_tools = (ROOT / "modules/nas/internal/account-tools.nix").read_text(encoding="utf-8")
        network = account_tools.split('name = "networkmanager";', 1)[1].split("})", 1)[0]
        self.assertIn("sensitive = true;", network)
        self.assertIn('rootMode = "0700";', network)
        self.assertIn('lib.optional cfg.networking.enable "NetworkManager.service"', account_tools)
        self.assertIn('"nas-protected-services.target"', account_tools.split("stateRestoreUnits =", 1)[1])

    def test_development_fallback_has_one_v2_managed_services_authority(self) -> None:
        with mock.patch.dict(
            "os.environ",
            {"NAS_MANAGED_SERVICES_STATE_PATH": "/tmp/v2-services.yaml"},
            clear=False,
        ):
            registry = nas_state.default_authorities()
        managed = [authority for authority in registry if authority.name == "managed-services"]
        self.assertEqual(1, len(managed))
        self.assertEqual("/tmp/v2-services.yaml", managed[0].source)
        self.assertFalse(any(authority.name == "feature-control" for authority in registry))


if __name__ == "__main__":
    unittest.main()
