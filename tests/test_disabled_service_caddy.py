from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))

import nas_managed_service as msvc  # noqa: E402
import nas_service_caddy as caddy  # noqa: E402


class DisabledServiceCaddyRegressionTests(unittest.TestCase):
    def test_disabled_managed_service_remains_in_projection_but_has_no_proxy_route(self) -> None:
        service = {
            "label": "Disabled app",
            "enabled": False,
            "runtime": {
                "type": "compose",
                "source": "/var/lib/nas-control/apps/disabled-app/compose.yaml",
                "startPolicy": "boot",
            },
            "endpoints": {
                "web": {
                    "transport": "http",
                    "targetPort": 8080,
                    "exposure": {"type": "hostname", "value": "disabled.example.test"},
                    "auth": {"mode": "public"},
                }
            },
        }
        effective = {
            "schemaVersion": 2,
            "generation": 1,
            "services": {"disabled-app": service},
            "endpoints": {
                "disabled-app:web": {
                    "label": "Disabled app:web",
                    "serviceId": "disabled-app",
                    "endpointId": "web",
                    "transport": "http",
                    "targetPort": 8080,
                    "exposure": {"type": "hostname", "value": "disabled.example.test"},
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
        self.assertNotIn("disabled.example.test", caddy.generate_caddyfile(effective))


if __name__ == "__main__":
    unittest.main()
