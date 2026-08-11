from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

from nas_v2_portal import PortalProjectionError, compile_portal_projection  # noqa: E402


class PortalProjectionTests(unittest.TestCase):
    def test_projects_only_enabled_visible_routes_with_canonical_capability(self) -> None:
        effective = {
            "schemaVersion": 3,
            "services": {
                "files": {
                    "name": "Files",
                    "enabled": True,
                    "routes": {
                        "web": {
                            "exposure": {"type": "path", "paths": ["/shares/"]},
                            "auth": {"mode": "identity", "capability": "access"},
                            "portal": {"visible": True, "title": "My files", "category": "Storage", "order": 10},
                        },
                        "internal": {
                            "exposure": {"type": "path", "paths": ["/internal/"]},
                            "auth": {"mode": "identity", "capability": "admin"},
                            "portal": {"visible": False},
                        },
                    },
                },
                "disabled": {
                    "name": "Disabled",
                    "enabled": False,
                    "routes": {
                        "web": {
                            "exposure": {"type": "path", "paths": ["/disabled/"]},
                            "auth": {"mode": "public"},
                            "portal": {"visible": True},
                        }
                    },
                },
            },
        }
        projection = compile_portal_projection(effective)
        self.assertEqual(projection["schemaVersion"], 2)
        self.assertEqual(projection["source"], "managed-services-v2")
        self.assertEqual(len(projection["entries"]), 1)
        entry = projection["entries"][0]
        self.assertEqual(entry["id"], "files.web")
        self.assertEqual(entry["url"], "/shares/")
        self.assertEqual(entry["label"], "My files")
        self.assertEqual(entry["access"]["groups"], ["application.files.access", "nas_admin"])

    def test_public_and_upstream_routes_are_linkable_without_capability_group(self) -> None:
        effective = {
            "schemaVersion": 3,
            "services": {
                "docs": {
                    "name": "Docs",
                    "routes": {
                        "public": {
                            "exposure": {"type": "path", "paths": ["/docs/"]},
                            "auth": {"mode": "public"},
                            "portal": {"visible": True},
                        },
                        "native": {
                            "exposure": {"type": "path", "paths": ["/native/"]},
                            "auth": {"mode": "upstream"},
                            "portal": {"visible": True},
                        },
                    },
                }
            },
        }
        entries = compile_portal_projection(effective)["entries"]
        self.assertEqual([entry["access"]["allow"] for entry in entries], ["any", "any"])

    def test_visible_route_without_safe_url_fails_closed(self) -> None:
        effective = {
            "schemaVersion": 3,
            "services": {
                "bad": {
                    "routes": {
                        "web": {
                            "exposure": {"type": "unknown"},
                            "auth": {"mode": "public"},
                            "portal": {"visible": True, "url": "//evil.invalid/"},
                        }
                    }
                }
            },
        }
        with self.assertRaises(PortalProjectionError):
            compile_portal_projection(effective)

    def test_rejects_non_v3_effective_state(self) -> None:
        with self.assertRaisesRegex(PortalProjectionError, "schema version 3"):
            compile_portal_projection({"schemaVersion": 2, "services": {}})


if __name__ == "__main__":
    unittest.main()
