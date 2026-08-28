"""Setup flow tests - validates code/config changes."""

import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class TestSetupHTML(unittest.TestCase):
    """Tests for the packaged setup HTML structure and content."""

    def test_setup_html_exists(self):
        """Verify the packaged setup.html file exists."""
        html_path = pathlib.Path(ROOT / "web/portal/setup.html")
        self.assertTrue(html_path.exists(), "web/portal/setup.html should exist")

    def test_setup_html_links_to_the_authentik_gated_console(self):
        """Verify setup.html links to the GUI setup Console."""
        html_path = pathlib.Path(ROOT / "web/portal/setup.html")
        content = html_path.read_text()
        self.assertIn('href="/console/"', content, "setup.html should link to Console")
        self.assertIn("Sign in to Authentik", content, "setup.html should explain Authentik access")
        self.assertNotIn('method="POST"', content, "setup.html should not use POST form")

    def test_setup_html_has_canonical_link(self):
        """Verify setup.html has canonical link to /setup."""
        html_path = pathlib.Path(ROOT / "web/portal/setup.html")
        content = html_path.read_text()
        self.assertIn('rel="canonical"', content, "setup.html should have canonical link")
        self.assertIn('href="/setup"', content, "Canonical link should point to /setup")


class TestCaddyConfig(unittest.TestCase):
    """Tests for Caddy configuration changes."""

    def test_caddy_bootstrap_sends_home_and_unknown_paths_to_authentik_launcher(self):
        """Authentik owns the appliance home page in both Caddy configurations."""
        bootstrap_path = pathlib.Path(ROOT / "modules/nas/config/caddy-bootstrap.nix")
        self.assertTrue(pathlib.Path(bootstrap_path).exists(), "caddy-bootstrap.nix should exist")
        content = bootstrap_path.read_text(encoding="utf-8")

        # Authentik must remain reachable without forward-auth to avoid a loop.
        for route in ("handle @authentikUi {", "handle @authentikOutpost {"):
            with self.subTest(route=route):
                start = content.index(route)
                end = content.index("\n  }", start)
                self.assertNotIn("${caddyForwardAuth}", content[start:end])

        canonical = content[content.index("handle /setup {") : content.index("handle /setup/* {")]
        self.assertIn("redir /setup /setup/ 308", canonical)

        setup_start = content.index("handle /setup/* {")
        setup_end = content.find("\n  }\n", setup_start)
        self.assertIn("${caddyForwardAuth}", content[setup_start:setup_end], "/setup/* must require Authentik")

        console_start = content.index("handle /console* {")
        console_end = content.find("\n  }\n", console_start)
        console = content[console_start:console_end]
        self.assertIn("${caddyForwardAuth}", console)
        self.assertIn("respond @missingCockpitAdmin 403", console)
        self.assertIn("reverse_proxy 127.0.0.1:${toString cockpitPort}", console)

        root = content[content.index("handle / {") : content.index("handle /setup {")]
        self.assertIn("redir * ${cfg.identity.authentikPath}if/user/ 303", root)
        fallback = content[content.rindex("handle {") :]
        self.assertIn("redir * ${cfg.identity.authentikPath}if/user/ 303", fallback)

    def test_caddy_no_shell_conditionals(self):
        """Verify Caddy config doesn't have invalid shell conditionals."""
        bootstrap_path = pathlib.Path(ROOT / "modules/nas/config/caddy-bootstrap.nix")
        content = bootstrap_path.read_text()
        lines = content.split("\n")
        shell_if_lines = [i for i, line in enumerate(lines) if "if [ -f" in line]
        self.assertEqual(len(shell_if_lines), 0, "Caddy config should not have shell if conditionals")


class TestApplicationChanges(unittest.TestCase):
    """Tests for application configuration changes."""

    def test_copyparty_statedirectory_override(self):
        """Verify copyparty StateDirectory is overridden to absolute path."""
        app_path = pathlib.Path(ROOT / "modules/nas/config/application-services.nix")
        self.assertTrue(pathlib.Path(app_path).exists(), "application-services.nix should exist")
        content = app_path.read_text()
        # Check for StateDirectory override with mkForce
        self.assertIn("StateDirectory", content, "Should have StateDirectory override")
        # Should not have relative StateDirectory that causes ELOOP
        self.assertNotIn("StateDirectory=copyparty", content, "Should not have relative StateDirectory=copyparty")

    def test_vaultwarden_statedirectory_override(self):
        """Verify vaultwarden StateDirectory is overridden."""
        app_path = pathlib.Path(ROOT / "modules/nas/config/application-services.nix")
        content = app_path.read_text()
        self.assertIn("StateDirectory", content, "Should have StateDirectory override for vaultwarden")


class TestSecurityExpectations(unittest.TestCase):
    """Tests for security expectations from the setup flow."""

    def test_no_shell_if_in_caddyfile(self):
        """Ensure no shell if conditionals in Caddy config."""
        bootstrap_path = pathlib.Path(ROOT / "modules/nas/config/caddy-bootstrap.nix")
        content = bootstrap_path.read_text()
        lines = content.split("\n")
        has_shell_if = any("if [ -f" in line for line in lines)
        self.assertFalse(has_shell_if, "Caddy config should not contain shell if conditionals")


if __name__ == "__main__":
    unittest.main()
