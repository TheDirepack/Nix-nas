from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WIZARD = ROOT / "setup" / "first-run-wizard" / "src"


def test_first_run_schema_requires_independent_human_credentials() -> None:
    schema = json.loads((WIZARD / "forms" / "schema.json").read_text(encoding="utf-8"))
    properties = schema["properties"]
    required = set(schema["required"])

    assert properties["adminUsername"].get("default") is None
    assert "useSamePassword" not in properties
    assert "createOutpost" not in properties
    assert "createProviderApp" not in properties
    assert {
        "adminPassword",
        "adminPasswordConfirm",
        "keePassMasterPassword",
        "keePassMasterPasswordConfirm",
        "authentikAdministratorPassword",
        "authentikAdministratorPasswordConfirm",
    } <= required
    for field in (
        "adminPassword",
        "adminPasswordConfirm",
        "keePassMasterPassword",
        "keePassMasterPasswordConfirm",
        "authentikAdministratorPassword",
        "authentikAdministratorPasswordConfirm",
    ):
        assert properties[field]["minLength"] >= 15


def test_wizard_does_not_offer_fixed_admin_or_shared_keepass_password() -> None:
    admin_source = (WIZARD / "steps" / "AdminStep.jsx").read_text(encoding="utf-8")

    assert "useSamePassword" not in admin_source
    assert "Use the same password" not in admin_source
    assert "useState('admin')" not in admin_source
    assert "Choose a new local username" in admin_source
    assert "KeePassXC master password" in admin_source


def test_browser_api_never_generates_secret_bearing_nix_or_logs_credentials() -> None:
    api_source = (WIZARD / "api.js").read_text(encoding="utf-8")

    assert "writeTempNixConfig" not in api_source
    assert "users.users.admin" not in api_source
    assert "console.log" not in api_source
    assert "fs.write" not in api_source
    assert "redirect: 'error'" in api_source
    assert "credentials: 'same-origin'" in api_source
    assert "cache: 'no-store'" in api_source


def test_authentik_setup_uses_separate_human_password_and_managed_static_objects() -> None:
    source = (WIZARD / "steps" / "AuthentikStep.jsx").read_text(encoding="utf-8")

    assert "Authentik administrator password" in source
    assert "Confirm Authentik administrator password" in source
    assert "createOutpost" not in source
    assert "createProviderApp" not in source
    assert "embedded proxy outpost" in source
