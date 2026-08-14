from __future__ import annotations

import ast
import textwrap
import unittest

from repo_test_utils import ROOT, text


class ContractTests(unittest.TestCase):
    def test_authentik_replaces_retired_identity_stack(self) -> None:
        paths = [
            *sorted((ROOT / "modules").rglob("*.nix")),
            *sorted((ROOT / "services").glob("*.py")),
            *sorted((ROOT / "web").rglob("*.html")),
            ROOT / "local.nix",
            ROOT / "flake.nix",
        ]
        found_authentik = False
        for path in paths:
            source = path.read_text(encoding="utf-8", errors="replace").lower()
            found_authentik = found_authentik or "authentik" in source
            with self.subTest(path=path.relative_to(ROOT)):
                self.assertNotRegex(source, r"\b(?:lldap|authelia)\b")
        self.assertTrue(found_authentik, "no active source file references Authentik")

    def test_keepass_password_is_interactive_or_cockpit_stdin_and_never_persisted(self) -> None:
        secrets = text("modules/nas/internal/secret-tools.nix")
        unlock = text("cockpit/src/api.js")
        self.assertIn("keepassxc-cli", secrets)
        self.assertNotIn("--pw-stdin", secrets)
        self.assertIn("printf '%s\\n' \"$keepass_password\" | keepassxc-cli", secrets)
        self.assertRegex(secrets, r"read\s+-r\s+-s")
        self.assertIn("activate-stdin)", secrets)
        self.assertIn('superuser: "require"', unlock)
        self.assertIn("process.input", unlock)
        self.assertNotIn("DBUS_SESSION_BUS_ADDRESS", secrets)

    def test_authentik_token_authorities_are_separate(self) -> None:
        secrets = text("modules/nas/internal/secret-tools.nix")
        identity = text("services/nas_identity_sync.py") + text("services/nas_identity_model.py")
        self.assertIn("authentik-bootstrap-token", secrets)
        self.assertIn("authentik-api-token", secrets)
        self.assertIn("authentik_token(bootstrap=True)", identity)

    def test_copyparty_is_the_only_share_authority(self) -> None:
        identity = text("services/nas_identity_sync.py") + text("services/nas_identity_model.py")
        system = text("modules/nas/config/system.nix")
        services = text("modules/nas/config/application-services.nix")
        self.assertNotIn("render_copyparty", identity)
        self.assertNotIn("nasSharePath", identity)
        self.assertNotIn("GENERATED_CONFIG", identity)
        self.assertIn('copypartyUserSeed = pkgs.writeText "00-local-overrides.conf"', system)
        self.assertIn("[/shares/admin/copyparty-config]", system)
        self.assertIn("[/shares/users/''${u%+application.copyparty.files}]", system)
        self.assertIn("rwmd.: ''${u}", system)
        self.assertIn("shr-who: auth", system)
        self.assertIn('"shr-adm" = "@nas_admin";', services)
        self.assertIn('"idp-store" = 3;', services)

    def test_user_settings_are_authentik_owned(self) -> None:
        proxy = text("modules/nas/config/reverse-proxy.nix")
        blueprint = text("authentik/blueprints/nas-user-settings.yaml")
        account_tools = text("modules/nas/internal/account-tools.nix")
        self.assertIn("if/user/", proxy)
        self.assertIn("if/flow/nas-user-settings/", proxy)
        self.assertIn("attributes.nasSyncthingDevices", blueprint)
        self.assertIn("user_creation_mode: never_create", blueprint)
        self.assertIn("nas-user-settings-validate-syncthing-devices", blueprint)
        self.assertIn("validation_policies:", blueprint)
        self.assertNotIn("nasUserSettings", account_tools)
        self.assertFalse((ROOT / "services" / "nas_user_settings.py").exists())

    def test_authentik_blueprint_expressions_are_valid_python(self) -> None:
        blueprint = text("authentik/blueprints/nas-user-settings.yaml")

        def block_after(marker: str) -> str:
            lines = blueprint.splitlines()
            start = lines.index(marker) + 1
            block: list[str] = []
            for line in lines[start:]:
                if line and not line.startswith("        "):
                    break
                block.append(line[8:] if line.startswith("        ") else line)
            return textwrap.dedent("\n".join(block)).rstrip() + "\n"

        ast.parse(block_after("      initial_value: |"))
        ast.parse(block_after("      expression: |"))

    def test_portal_and_service_routes_are_v2_projected(self) -> None:
        proxy = text("modules/nas/config/reverse-proxy.nix")
        portal = text("web/portal/index.html")
        caddy = text("services/nas_v2_caddy.py")
        projection = text("services/nas_v2_caddy.py")
        self.assertIn("templates", proxy)
        self.assertIn("templates {\n            # The portal template", proxy)
        self.assertIn("root /", proxy)
        self.assertIn("file_server", proxy)
        self.assertIn("nasPortalStatic", proxy)
        self.assertIn('include "/run/nas-control/portal.json"', portal)
        self.assertIn('placeholder "http.request.header.Remote-Groups"', portal)
        self.assertIn('placeholder "http.request.header.Remote-User"', portal)
        self.assertIn('splitList ","', portal)
        self.assertIn('has "nas_admin" $groups', portal)
        self.assertNotIn('has $groups', portal)
        self.assertIn("generate_caddyfile", caddy)
        self.assertIn("project", projection)
        self.assertFalse((ROOT / "modules/nas/config/managed-services-migration.nix").exists())
        self.assertFalse((ROOT / "services" / "nas_portal.py").exists())

    def test_canonical_application_capabilities_replace_legacy_groups(self) -> None:
        common = text("services/nas_common.py")
        caddy = text("services/nas_v2_caddy.py")
        system = text("modules/nas/config/system.nix")
        coding = text("services/nas_coding_agent.py")
        self.assertIn("application_capability_group", common)
        self.assertIn("application_capability_allowed", common)
        self.assertIn("application.", caddy)
        self.assertIn("application.copyparty.files", system)
        self.assertIn('CODING_CAPABILITY_GROUP = "application.ai-coding.access"', coding)
        self.assertFalse((ROOT / "modules/nas/config/managed-services-identity-migration.nix").exists())
        self.assertFalse((ROOT / "services" / "nas_v2_identity_migrate.py").exists())

    def test_explicit_multi_superuser_group_and_admin_bypass_are_model_owned(self) -> None:
        identity = text("services/nas_identity_sync.py") + text("services/nas_identity_model.py")
        common = text("services/nas_common.py")
        self.assertIn("No enabled members of", identity)
        self.assertIn("multiple fully trusted administrators", identity)
        self.assertIn("desired_superuser = name == ADMIN_GROUP", identity)
        self.assertIn("administrator_bypass", common)

    def test_syncthing_reconciler_reads_authentik_attributes_and_v2_capability(self) -> None:
        model = text("services/nas_identity_model.py")
        devices = text("services/nas_syncthing_devices.py")
        self.assertIn("nasSyncthingDevices", model)
        self.assertIn("_resolve_syncthing_capability", model)
        self.assertIn("application_capability_allowed", model)
        self.assertIn("NAS_V2_SYNCTHING", model)
        self.assertIn("expand_attribute_values", devices)
        self.assertNotIn("atomic_write_device_state", devices)

    def test_no_request_time_legacy_capability_derivation_remains(self) -> None:
        sources = "\n".join(
            path.read_text(encoding="utf-8", errors="replace") for path in sorted((ROOT / "services").glob("*.py"))
        )
        for legacy in ("nas_allow_files", "nas_allow_ai", "nas_allow_vault", "legacyCapability"):
            self.assertNotIn(legacy, sources)


if __name__ == "__main__":
    unittest.main()
