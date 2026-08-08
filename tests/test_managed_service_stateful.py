from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_managed_service as msvc
import nas_service_caddy as caddy


class ManagedServiceProjectionContractTests(unittest.TestCase):
    def test_enabled_endpoint_agrees_across_effective_portal_and_caddy(self) -> None:
        effective = {
            "schemaVersion": 2,
            "generation": 4,
            "services": {"app": {"label": "App", "enabled": True}},
            "endpoints": {
                "app:web": {
                    "serviceId": "app",
                    "endpointId": "web",
                    "label": "App:web",
                    "transport": "http",
                    "targetPort": 8080,
                    "exposure": {"type": "hostname", "value": "app.example.test"},
                    "auth": {"mode": "public"},
                    "portal": {"visible": True},
                    "available": True,
                }
            },
        }
        portal = msvc.portal_projection(effective)
        routes = caddy.generate_caddy_fragment(effective)["routes"]
        self.assertEqual(portal["generation"], 4)
        self.assertEqual(portal["entries"][0]["id"], "app:web")
        self.assertTrue(portal["entries"][0]["available"])
        self.assertEqual([route["id"] for route in routes], ["nas-managed-app-web"])

    def test_disabled_endpoint_stays_visible_as_unavailable_but_is_not_proxied(self) -> None:
        effective = {
            "schemaVersion": 2,
            "generation": 5,
            "services": {"app": {"label": "App", "enabled": False}},
            "endpoints": {
                "app:web": {
                    "serviceId": "app",
                    "endpointId": "web",
                    "label": "App:web",
                    "transport": "http",
                    "targetPort": 8080,
                    "exposure": {"type": "hostname", "value": "app.example.test"},
                    "auth": {"mode": "public"},
                    "portal": {"visible": True},
                    "available": False,
                }
            },
        }
        portal = msvc.portal_projection(effective)
        self.assertEqual(len(portal["entries"]), 1)
        self.assertFalse(portal["entries"][0]["available"])
        self.assertEqual(caddy.generate_caddy_fragment(effective), {"routes": []})
        self.assertNotIn("app.example.test", caddy.generate_caddyfile(effective))


if __name__ == "__main__":
    unittest.main()
