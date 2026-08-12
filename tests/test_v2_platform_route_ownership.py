from __future__ import annotations

import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class ManagedServicesV2PlatformRouteOwnershipTests(unittest.TestCase):
    def test_cockpit_console_route_is_seeded_only_through_v2(self) -> None:
        seed = (ROOT / "modules" / "nas" / "config" / "managed-services-platform-routes.nix").read_text(encoding="utf-8")
        proxy = (ROOT / "modules" / "nas" / "config" / "reverse-proxy.nix").read_text(encoding="utf-8")

        self.assertIn("services.cockpit", seed)
        self.assertIn('paths = [ "/console" ];', seed)
        self.assertIn('type = "http";', seed)
        self.assertIn('host = "127.0.0.1";', seed)
        self.assertIn('capability = "admin";', seed)
        self.assertIn('title = "System Console";', seed)

        self.assertNotIn("@console", proxy)
        self.assertNotIn("tls_insecure_skip_verify", proxy)
        self.assertNotIn("cockpitPort", proxy)


if __name__ == "__main__":
    unittest.main()
