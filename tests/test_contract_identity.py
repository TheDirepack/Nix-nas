from __future__ import annotations

import ast
import textwrap
import unittest

from repo_test_utils import ROOT, text


class ContractTests(unittest.TestCase):
    def test_authentik_replaces_retired_identity_stack(self):
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

    def test_keepass_password_is_interactive_or_cockpit_stdin_and_never_persisted(self):
        secrets = text("modules/nas/internal/secret-tools.nix")
        unlock = text("cockpit/src/api.js")
        self.assertIn("keepassxc-cli", secrets)
        self.assertNotIn("--pw-stdin", secrets)
        self.assertRegex(secrets, r"read\s+-r\s+-s")
        self.assertIn("activate-stdin)", secrets)
        self.assertIn('superuser: "require"', unlock)
        self.assertIn("process.input", unlock)
        self.assertNotIn("DBUS_SESSION_BUS_ADDRESS", secrets)

    def test_authentik_token_authorities_are_separate(self):
        secrets = text("modules/nas/internal/secret-tools.nix")
        identity = text("services/nas_identity_sync.py") + text("services/nas_identity_model.py")
        self.assertIn("authentik-bootstrap-token", secrets)
        self.assertIn("authentik-api-token", secrets)
        self.assertIn("authentik_token(bootstrap=True)", identity)

    def test_copyparty_is_the_only_share_authority(self):
        identity = text("services/nas_identity_sync.py") + text("services/nas_identity_model.py")
        system = text("modules/nas/config/system.nix")
        services = text("modules/nas/config/application-services.nix")
        portal = text("web/portal/index.html")
        self.assertNotIn("render_copyparty", identity)
        self.assertNotIn("nasSharePath", identity)
        self.assertNotIn("GENERATED_CONFIG", identity)
        self.assertIn('copypartyUserSeed = pkgs.writeText "00-local-overrides.conf"', system)
        self.assertIn("[/shares/admin/copyparty-config]", system)
        self.assertIn("r: @nas_allow_files", system)
        self.assertIn("[/shares/users/''${u%+nas_allow_files}]", system)
        self.assertIn("rwmd.: ''${u}", system)
        self.assertNotIn("A: ''${u}, @nas_admin", system)
        self.assertIn("shr-who: auth", system)
        # Portal is now a Caddy template that renders portal.json entries via
        # Remote-Groups, not hardcoded per-capability blocks. Check the template
        # reads the portal and gates on groups, and that the share ACL is still
        # copyparty-owned.
        self.assertIn('include "/run/nas-control/portal.json"', portal)
        self.assertIn('placeholder "http.request.header.Remote-Groups"', portal)
        self.assertIn('"shr-adm" = "@nas_admin";', services)
        self.assertIn('"idp-store" = 3;', services)

    def test_user_settings_are_authentik_owned(self):
        proxy = text("modules/nas/config/reverse-proxy.nix")
        blueprint = text("authentik/blueprints/nas-user-settings.yaml")
        account_tools = text("modules/nas/internal/account-tools.nix")
        self.assertIn("if/user/", proxy)
        self.assertIn("if/flow/nas-user-settings/", proxy)
        self.assertIn("attributes.nasSyncthingDevices", blueprint)
        self.assertIn("user_creation_mode: never_create", blueprint)
        self.assertIn("nas-user-settings-validate-syncthing-devices", blueprint)
        self.assertIn("validation_policies:", blueprint)
        self.assertNotIn("| to_json", blueprint)
        self.assertNotIn("nasUserSettings", account_tools)
        self.assertFalse((ROOT / "services" / "nas_user_settings.py").exists())

    def test_authentik_blueprint_expressions_are_valid_python(self):
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

    def test_portal_is_a_caddy_template_not_an_application_service(self):
        proxy = text("modules/nas/config/reverse-proxy.nix")
        base = text("modules/nas/internal/base.nix")
        systemd = text("modules/nas/config/systemd-services.nix")
        portal = text("web/portal/index.html")
        self.assertIn("templates", proxy)
        self.assertIn("templates {\n            # The portal template", proxy)
        self.assertIn("root /", proxy)
        self.assertIn("file_server", proxy)
        self.assertIn("nasPortalStatic", proxy)
        self.assertIn("handle /share/*", proxy)
        # Portal is a Caddy template that includes portal.json and renders
        # entries via placeholder Remote-Groups / Remote-User, not a
        # hard-coded /shares/users path.
        self.assertIn('include "/run/nas-control/portal.json"', portal)
        self.assertIn('placeholder "http.request.header.Remote-Groups"', portal)
        self.assertIn('splitList ","', portal)
        self.assertIn('has "nas_admin" $groups', portal)
        self.assertNotIn("has $groups", portal)
        self.assertIn('placeholder "http.request.header.Remote-User"', portal)
        share_route = proxy.split("handle /share/* {", 1)[1].split("@shares path", 1)[0]
        self.assertIn("${copypartySsoProxy}", share_route)
        self.assertNotIn("caddyForwardAuth", share_route)
        self.assertNotIn("caddyCapabilityAuth", share_route)
        self.assertNotIn("nas-portal.service", base + systemd)
        self.assertNotIn("portalPort", text("modules/nas/internal/maintenance-tools.nix"))
        self.assertFalse((ROOT / "services" / "nas_portal.py").exists())

    def test_explicit_multi_superuser_group_and_admin_only_global_syncthing(self):
        identity = text("services/nas_identity_sync.py") + text("services/nas_identity_model.py")
        proxy = text("modules/nas/config/reverse-proxy.nix")
        self.assertIn("No enabled members of", identity)
        self.assertIn("multiple fully trusted administrators", identity)
        self.assertIn("desired_superuser = name == ADMIN_GROUP", identity)
        self.assertIn("add_user/", identity)
        self.assertIn('caddyOnDemandAuth "syncthing" "admin"', proxy)

    def test_syncthing_reconciler_reads_authentik_attributes(self):
        identity = text("services/nas_identity_sync.py") + text("services/nas_identity_model.py")
        devices = text("services/nas_syncthing_devices.py")
        self.assertIn("nasSyncthingDevices", identity)
        self.assertNotIn("USER_DEVICE_STATE_PATH", identity)
        self.assertIn("expand_attribute_values", devices)
        self.assertNotIn("atomic_write_device_state", devices)

    def test_non_admin_capabilities_default_to_nothing(self):
        common = text("services/nas_common.py")
        system = text("modules/nas/config/system.nix")
        proxy = text("modules/nas/config/reverse-proxy.nix")
        self.assertIn("return allow_group in groups", common)
        self.assertIn("u%+nas_allow_files", system)
        self.assertIn('caddyCapabilityAuth "files"', proxy)
        self.assertIn('caddyCapabilityAuth "webdav"', proxy)
        self.assertIn('caddyCapabilityAuth "syncthing"', proxy)
        self.assertIn('caddyCapabilityAuth "vault"', proxy)

    def test_vault_fallback_is_authenticated_and_capability_gated(self):
        proxy = text("modules/nas/config/reverse-proxy.nix")
        vault = proxy.split("handle /vault/* {", 1)[1].split("# Native share links", 1)[0]
        fallback = vault.rsplit("handle {", 1)[1]
        self.assertIn("caddyForwardAuth", fallback)
        self.assertIn('caddyCapabilityAuth "vault"', fallback)


if __name__ == "__main__":
    unittest.main()
