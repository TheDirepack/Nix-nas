"""Tests for the explicit setup Authentik application and its retirement."""

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
    def test_setup_api_service_does_not_start_after_successful_first_run(self) -> None:
        bootstrap = (ROOT / "modules/nas/config/caddy-bootstrap.nix").read_text(encoding="utf-8")
        start = bootstrap.index("systemd.services.nas-first-run-api = {")
        end = bootstrap.index("\n  };", start)
        block = bootstrap[start:end]
        self.assertIn("ConditionPathExists", block)
        self.assertIn("!/var/lib/nas-setup/state.json", block)
        self.assertIn("RestrictAddressFamilies = [ \"AF_UNIX\" ]", block)

    def test_caddy_bootstrap_hides_setup_after_ready(self) -> None:
        bootstrap = (ROOT / "modules/nas/config/caddy-bootstrap.nix").read_text(encoding="utf-8")
        self.assertIn("handle /setup", bootstrap)
        self.assertIn("firstRunWizardStatic", bootstrap)
        self.assertIn("if [[ -f ${secretRoot}/ready && -f /var/lib/nas-setup/state.json ]]", bootstrap)

    def test_hardened_first_start_retires_setup_application_before_completion(self) -> None:
        secure = (ROOT / "services/nas_first_start.py").read_text(encoding="utf-8")
        identity = (ROOT / "services/nas_identity_sync.py").read_text(encoding="utf-8")

        self.assertIn("def remove_setup_application", secure)
        self.assertIn('identity.authentik_request(token, "core/applications/nas-setup/", method="DELETE")', secure)
        self.assertIn("follow_redirects=False", identity)

        app_retirement = secure.index('"setup-application-retirement"')
        bootstrap_retirement = secure.index('"bootstrap-authority-retirement"')
        final_state = secure.index('"final-state"')
        complete = secure.index("journal.complete(report)")
        self.assertLess(app_retirement, bootstrap_retirement)
        self.assertLess(bootstrap_retirement, final_state)
        self.assertLess(final_state, complete)


if __name__ == "__main__":
    unittest.main()
