from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
DISPATCH = ROOT / "services/nas_identity_dispatch.py"
PYPROJECT = ROOT / "pyproject.toml"
BOOTSTRAP = ROOT / "services/nas_identity_bootstrap.py"
RUNTIME = ROOT / "services/nas_identity_sync.py"


class IdentityAuthorityDispatchTests(unittest.TestCase):
    def test_public_identity_command_uses_authority_dispatcher(self) -> None:
        project = PYPROJECT.read_text(encoding="utf-8")
        self.assertIn('nas-identity-sync = "nas_identity_dispatch:main"', project)
        self.assertIn('"nas_identity_dispatch"', project)

    def test_only_setup_mutations_route_to_bootstrap_helper(self) -> None:
        source = DISPATCH.read_text(encoding="utf-8")
        self.assertIn('"apply-accounts": "apply-accounts"', source)
        self.assertIn('"bootstrap-runtime-token": "provision-runtime-token"', source)
        self.assertIn('"retire-bootstrap": "retire-bootstrap"', source)
        self.assertIn("return runtime.main()", source)
        for steady_state in ("status", "capabilities", "verify-token", "sync", "sync-syncthing"):
            self.assertNotIn(f'"{steady_state}":', source)

    def test_bootstrap_helper_uses_bootstrap_token_for_mutations(self) -> None:
        source = BOOTSTRAP.read_text(encoding="utf-8")
        self.assertIn("identity.apply_account_plan(\n        _bootstrap_token()", source)
        self.assertIn("identity.provision_runtime_token(_bootstrap_token())", source)
        self.assertIn("identity.retire_bootstrap_administrator(token, administrator)", source)

    def test_runtime_authentik_requests_never_follow_redirects(self) -> None:
        source = RUNTIME.read_text(encoding="utf-8")
        self.assertIn("follow_redirects=False", source)
        self.assertIn("_NoRedirectHandler", source)
        self.assertIn("Refusing Authentik request outside the configured API origin", source)

    def test_runtime_role_is_probed_for_denied_mutations(self) -> None:
        source = BOOTSTRAP.read_text(encoding="utf-8")
        self.assertIn('"user creation"', source)
        self.assertIn('"password reset"', source)
        self.assertIn("only 403 is accepted", source)
        self.assertIn("bootstrapTokenRejected", source)


if __name__ == "__main__":
    unittest.main()
