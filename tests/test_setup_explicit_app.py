"""Tests for explicit setup Authentik application and self-removal."""

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
        self.assertIn("metaDescription:", content)
        self.assertIn("nas_admin", content)

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
        app_services = (ROOT / "modules/nas/config/application-services.nix").read_text(encoding="utf-8")
        # The setup wizard API should not be available after the first run
        # has written its completion state. The persisted state makes the
        # wizard, its Caddy route, and its Authentik application unnecessary.
        start = app_services.index("systemd.services.nas-setup-api = {")
        end = app_services.index("};", start)
        block = app_services[start:end]
        self.assertIn("ConditionPathExists", block)
        self.assertIn("!/var/lib/nas-setup/state.json", block)

    def test_caddy_bootstrap_hides_setup_after_ready(self) -> None:
        bootstrap = (ROOT / "modules/nas/config/caddy-bootstrap.nix").read_text(encoding="utf-8")
        # Bootstrap serves /setup, but renderActive switches to the managed
        # Caddy config once secrets and state are ready.
        self.assertIn("handle /setup", bootstrap)
        self.assertIn("firstRunWizardStatic", bootstrap)
        self.assertIn("if [[ -f ${secretRoot}/ready && -f /var/lib/nas-setup/state.json ]]", bootstrap)
        # The managed Caddy config (generated from services.yaml) does not
        # contain the setup wizard – it self-removes at the Caddy layer.

    def test_setup_python_removes_application_after_complete(self) -> None:
        setup_py = (ROOT / "services/nas_setup.py").read_text(encoding="utf-8")
        self.assertIn("SETUP_APPLICATION_SLUG", setup_py)
        self.assertIn("def _remove_setup_application", setup_py)
        # Removal is best-effort after the journal is marked complete and
        # the first-start status is published, so a failed Authentik call
        # does not fail the overall setup.
        self.assertIn("journal.complete(report)", setup_py)
        # The removal call should be after complete, before return, with diagnostic handling.
        complete_idx = setup_py.index("journal.complete(report)")
        # Find the call site after complete, not the definition.
        remove_call_idx = setup_py.index("_remove_setup_application()", complete_idx)
        self.assertGreater(
            remove_call_idx, complete_idx, "_remove_setup_application() call should be after journal.complete"
        )
        self.assertIn("Unable to remove setup application", setup_py)


if __name__ == "__main__":
    unittest.main()
