from __future__ import annotations

import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
BLUEPRINT = ROOT / "authentik/experiments/nas-domain-forward-auth.yaml"
GUIDE = ROOT / "docs/development/authentik-domain-forward-auth-experiment.md"


class AuthentikDomainExperimentTests(unittest.TestCase):
    def test_blueprint_is_explicitly_nonproduction_and_domain_level(self) -> None:
        text = BLUEPRINT.read_text(encoding="utf-8")
        self.assertIn("Experimental only", text)
        self.assertIn("authentik_providers_proxy.proxyprovider", text)
        self.assertIn("mode: forward_domain", text)
        self.assertIn("cookie_domain: nas.example.invalid", text)
        self.assertNotIn("blueprints.goauthentik.io/instantiate", text)

    def test_launcher_apps_are_providerless_and_use_distinct_public_paths(self) -> None:
        text = BLUEPRINT.read_text(encoding="utf-8")
        self.assertEqual(text.count("provider: null"), 3)
        self.assertIn("meta_launch_url: https://nas.example.invalid/", text)
        self.assertIn("meta_launch_url: https://nas.example.invalid/console/", text)
        self.assertIn("meta_launch_url: https://nas.example.invalid/setup/", text)

    def test_experiment_requires_caddy_authorization_and_failure_probes(self) -> None:
        text = GUIDE.read_text(encoding="utf-8")
        for required in (
            "Caddy's existing generated capability checks",
            "authenticated users without the route capability",
            "locked boot -> unlock",
            "first-start setup retirement",
            "deliberately invalid blueprint update",
        ):
            self.assertIn(required, text)


if __name__ == "__main__":
    unittest.main()
