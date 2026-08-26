"""Tests for the explicit temporary setup Authentik application lifecycle."""

import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
BLUEPRINT = ROOT / "authentik/blueprints/nas-setup.yaml"


class ExplicitSetupApplicationTests(unittest.TestCase):
    def test_blueprint_exists_and_defines_setup_application(self) -> None:
        self.assertTrue(BLUEPRINT.exists(), "nas-setup.yaml blueprint must exist")
        content = BLUEPRINT.read_text(encoding="utf-8")
        self.assertIn("nas-setup", content)
        self.assertIn("NAS Setup", content)
        self.assertIn("authentik_core.application", content)
        self.assertIn("provider: null", content)

    def test_blueprint_is_installed_via_nas_authentik_blueprints(self) -> None:
        account_tools = (ROOT / "modules/nas/internal/account-tools.nix").read_text(encoding="utf-8")
        self.assertIn("nas-setup.yaml", account_tools)
        self.assertIn("nasAuthentikBlueprints", account_tools)

    def test_blueprint_has_policy_binding_for_nas_admin(self) -> None:
        content = BLUEPRINT.read_text(encoding="utf-8")
        self.assertIn("authentik_policies.policybinding", content)
        self.assertIn("nas_admin", content)


class SetupUtilityLifecycleTests(unittest.TestCase):
    def test_first_run_api_service_does_not_start_after_successful_setup(self) -> None:
        bootstrap = (ROOT / "modules/nas/config/caddy-bootstrap.nix").read_text(encoding="utf-8")
        declaration = "systemd.services.nas-first-run-api = lib.mkIf cfg.firstStart.enable {"
        start = bootstrap.index(declaration)
        end = bootstrap.index("\n  };", start)
        block = bootstrap[start:end]
        self.assertIn("ConditionPathExists", block)
        self.assertIn("!/var/lib/nas-setup/state.json", block)
        self.assertIn("nas-first-run-api", block)

    def test_caddy_bootstrap_hides_setup_after_ready(self) -> None:
        bootstrap = (ROOT / "modules/nas/config/caddy-bootstrap.nix").read_text(encoding="utf-8")
        self.assertIn("handle /setup", bootstrap)
        self.assertIn("firstRunWizardStatic", bootstrap)
        self.assertIn("if [[ -f ${secretRoot}/ready && -f /var/lib/nas-setup/state.json ]]", bootstrap)

    def test_secure_first_start_retires_setup_application_before_bootstrap_authority(self) -> None:
        first_start = (ROOT / "services/nas_first_start.py").read_text(encoding="utf-8")
        self.assertIn("def remove_setup_application", first_start)
        self.assertIn('"setup-application-retirement"', first_start)
        self.assertIn('"bootstrap-authority-retirement"', first_start)
        self.assertLess(
            first_start.index('"setup-application-retirement"'),
            first_start.index('"bootstrap-authority-retirement"'),
        )
        self.assertIn("core/applications/?slug=nas-setup", first_start)
        self.assertIn('method="DELETE"', first_start)
        self.assertIn("still exists after retirement", first_start)


if __name__ == "__main__":
    unittest.main()
