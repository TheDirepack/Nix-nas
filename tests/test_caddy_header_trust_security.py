from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class CaddyHeaderTrustSecurityTests(unittest.TestCase):
    def test_static_forward_auth_strips_full_spoofable_identity_corpus(self) -> None:
        helper = (ROOT / "modules/nas/internal/caddy-helpers.nix").read_text(encoding="utf-8")
        for header in (
            "Remote-User",
            "Remote-Groups",
            "Remote-UID",
            "Remote-Role",
            "X-Authentik-Username",
            "X-Authentik-Groups",
            "X-Authentik-Entitlements",
            "X-Authentik-Jwt",
            "X-Authentik-Meta-Jwks",
            "X-Authentik-Meta-Outpost",
            "X-Authentik-Meta-Provider",
            "X-Authentik-Meta-App",
            "X-Authentik-Meta-Version",
            "X-Authentik-Meta-User",
            "X-Authentik-Meta-Is-Superuser",
            "X-Authentik-Role",
        ):
            with self.subTest(header=header):
                self.assertIn(f"request_header -{header}", helper)
        self.assertIn(
            "copy_headers X-Authentik-Username X-Authentik-Groups X-Authentik-Name X-Authentik-Email X-Authentik-Uid",
            helper,
        )
        self.assertNotIn("copy_headers X-Authentik-Username X-Authentik-Groups X-Authentik-Entitlements", helper)

    def test_post_setup_caddy_exposes_only_capability_completion_bridge(self) -> None:
        full = (ROOT / "modules/nas/config/reverse-proxy.nix").read_text(encoding="utf-8")
        self.assertIn("handle /setup/api/first-start/job/*", full)
        self.assertIn("handle /setup/api/reboot", full)
        self.assertNotIn("handle /setup/api/first-run", full)
        self.assertNotIn("handle /setup/api/password-quality", full)
        self.assertNotIn("handle /setup/*", full)

    def test_bootstrap_caddy_authenticates_submission_but_not_capability_polling(self) -> None:
        bootstrap = (ROOT / "modules/nas/config/caddy-bootstrap.nix").read_text(encoding="utf-8")
        status = bootstrap.index("handle /setup/api/first-start/job/*")
        reboot = bootstrap.index("handle /setup/api/reboot")
        authenticated = bootstrap.index("handle /setup/api/*")
        self.assertLess(status, authenticated)
        self.assertLess(reboot, authenticated)
        authenticated_block = bootstrap[authenticated : bootstrap.index("handle /setup/*", authenticated)]
        self.assertIn("${caddyForwardAuth}", authenticated_block)


if __name__ == "__main__":
    unittest.main()
