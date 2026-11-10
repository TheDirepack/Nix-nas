from __future__ import annotations

import hashlib
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
SCHEMA = ROOT / "schemas" / "managed-services-v3.schema.json"
SPEC_SCHEMA = ROOT / "spec" / "managed-services" / "managed-services-v3.schema.json"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_caddy as caddy  # noqa: E402
import nas_v2_spec as spec  # noqa: E402


class V2ReferenceTests(unittest.TestCase):
    def test_schema_copy_parity(self):
        self.assertTrue(SCHEMA.exists(), "schemas/managed-services-v3.schema.json missing")
        self.assertTrue(SPEC_SCHEMA.exists(), "spec/managed-services/managed-services-v3.schema.json missing")
        h1 = hashlib.sha256(SCHEMA.read_bytes()).hexdigest()
        h2 = hashlib.sha256(SPEC_SCHEMA.read_bytes()).hexdigest()
        self.assertEqual(
            h1,
            h2,
            "schemas/managed-services-v3.schema.json and spec/managed-services/managed-services-v3.schema.json must be identical",
        )

    def test_readme_example_compiles(self):
        # The minimal example in spec/managed-services/README.md must compile.
        # It defines a persistent runtime with parent/child paths (/metrics/admin/,
        # /metrics/api/) plus an on-demand workspace on /metrics/.
        # With longest-path-first ordering, this should succeed and render the
        # longer paths before the /metrics/ parent.
        example = {
            "schemaVersion": 3,
            "services": {
                "metrics-storage": {
                    "name": "Metrics storage",
                    "workload": {"kind": "job"},
                    "runtime": {"type": "systemd", "unit": "nas-metrics-storage.service"},
                },
                "metrics-runtime": {
                    "name": "Metrics database",
                    "workload": {"kind": "daemon", "activation": "persistent"},
                    "runtime": {"type": "systemd", "unit": "nas-metrics.service"},
                    "dependencies": [{"service": "metrics-storage", "condition": "completed"}],
                    "authorization": {"capabilities": [{"id": "retention", "title": "Manage retention"}]},
                    "readiness": {"probes": [{"type": "tcp", "port": 8080}]},
                    "routes": {
                        "ui": {
                            "target": {"type": "http", "host": "127.0.0.1", "port": 8080},
                            "exposure": {"type": "path", "paths": ["/metrics/admin/"]},
                            "auth": {"mode": "identity", "capability": "access"},
                            "portal": {"visible": True, "category": "Monitoring"},
                        },
                        "api": {
                            "target": {"type": "http", "host": "127.0.0.1", "port": 8080},
                            "exposure": {"type": "path", "paths": ["/metrics/api/"]},
                            "auth": {"mode": "upstream"},
                        },
                    },
                },
                "dashboards": {
                    "name": "Dashboards",
                    "workload": {"kind": "daemon", "activation": "on-demand", "idleSeconds": 600},
                    "runtime": {"type": "systemd", "unit": "dashboards.service"},
                    "dependencies": [{"service": "metrics-runtime", "condition": "ready"}],
                    "routes": {
                        "main": {
                            "target": {"type": "http", "host": "127.0.0.1", "port": 3000},
                            "exposure": {"type": "path", "paths": ["/metrics/"]},
                            "auth": {"mode": "identity", "capability": "access"},
                            "portal": {"visible": True, "category": "Monitoring"},
                        },
                    },
                },
            },
        }
        schema = spec.load_schema(SCHEMA)
        effective = spec.compile_document(example, schema)
        rendered = caddy.generate_caddyfile(effective)
        # Longest-path-first: /metrics/admin and /metrics/api must appear before /metrics/
        # Use specific path patterns to avoid substring matches
        parent = '"/metrics/" "/metrics" "/metrics/*"'
        self.assertLess(rendered.index('"/metrics/admin/"'), rendered.index(parent))
        self.assertLess(rendered.index('"/metrics/api/"'), rendered.index(parent))

    def test_nix_authority_path_consistency(self):
        nix_files = {
            "modules/nas/config/managed-services.nix": 'desiredPath = "/var/lib/nas-control/services.yaml"',
            "modules/nas/config/managed-services-seed-v2.nix": 'desiredPath = "/var/lib/nas-control/services.yaml"',
            "modules/nas/config/managed-services-lifecycle.nix": 'desiredPath = "/var/lib/nas-control/services.yaml"',
        }
        for path, expected in nix_files.items():
            text = (ROOT / path).read_text(encoding="utf-8")
            self.assertIn(expected, text, f"{path} must use {expected}")

        # Control defaults to file, not directory
        control = (ROOT / "services/nas_v2_control.py").read_text(encoding="utf-8")
        self.assertIn('"/var/lib/nas-control/services.yaml"', control)
        self.assertNotIn('"/var/lib/nas-control/services")', control)

        # Spec and README also use file
        readme = (ROOT / "spec/managed-services/README.md").read_text(encoding="utf-8")
        self.assertIn("/var/lib/nas-control/services.yaml", readme)

    def test_actual_seed_compiles(self):
        # The seed generated by managed-services-seed-v2.nix should compile
        # We can't run Nix here, but we can test that a document with the seed's
        # overlapping routes compiles when using longest-path-first
        # The seed has /shares, /shares/admin, /vault, /vault/admin
        doc = {
            "schemaVersion": 3,
            "services": {
                "copyparty": {
                    "name": "CopyParty",
                    "workload": {"kind": "daemon"},
                    "runtime": {"type": "systemd", "unit": "copyparty.service"},
                    "authorization": {
                        "capabilities": [{"id": "files", "title": "Files"}, {"id": "admin", "title": "Admin"}]
                    },
                    "routes": {
                        "files": {
                            "target": {"type": "http", "port": 8080},
                            "exposure": {"type": "path", "paths": ["/shares"]},
                            "auth": {"mode": "identity", "capability": "files"},
                        },
                        "admin": {
                            "target": {"type": "http", "port": 8080},
                            "exposure": {"type": "path", "paths": ["/shares/admin"]},
                            "auth": {"mode": "identity", "capability": "admin"},
                        },
                    },
                },
                "vaultwarden": {
                    "name": "Vaultwarden",
                    "workload": {"kind": "daemon"},
                    "runtime": {"type": "systemd", "unit": "vaultwarden.service"},
                    "authorization": {"capabilities": [{"id": "admin", "title": "Admin"}]},
                    "routes": {
                        "web": {
                            "target": {"type": "http", "port": 8080},
                            "exposure": {"type": "path", "paths": ["/vault"]},
                            "auth": {"mode": "public"},
                        },
                        "admin": {
                            "target": {"type": "http", "port": 8080},
                            "exposure": {"type": "path", "paths": ["/vault/admin"]},
                            "auth": {"mode": "identity", "capability": "admin"},
                        },
                    },
                },
            },
        }
        schema = spec.load_schema(SCHEMA)
        effective = spec.compile_document(doc, schema)
        self.assertIn("derived", effective)

    def test_cockpit_socket_consistency(self):
        # Caddy reaches Cockpit through a permissioned Unix socket on /console.
        # No TCP port may be reserved for it in the remote-admin firewall policy.
        network = (ROOT / "services/nas_v2_network.py").read_text(encoding="utf-8")
        self.assertIn("_remote_admin_ports", network)
        self.assertNotIn("NAS_V2_COCKPIT_PORT", network)
        self.assertNotIn('"9092"', network)
        self.assertNotIn('("9090", "tcp")', network)
        interfaces = (ROOT / "docs/src/reference/interfaces.md").read_text(encoding="utf-8")
        self.assertIn("`/console/`", interfaces)
        self.assertNotIn("9092", interfaces)
        interfaces = (ROOT / "docs/src/reference/interfaces.md").read_text(encoding="utf-8")
        self.assertIn("`/console/`", interfaces)
        self.assertNotIn("9092", interfaces)

    def test_group_headers_have_one_parser(self):
        # The Caddy portal template that re-parsed Remote-Groups was never
        # served and is removed; nas_common.split_groups (tests/test_common.py)
        # is the only group-header parser.
        self.assertFalse((ROOT / "web/portal").exists())
        for path in (ROOT / "web").rglob("*.html"):
            self.assertNotIn("Remote-Groups", path.read_text(encoding="utf-8"))

    def test_no_duplicate_route_catalogs(self):
        # The deleted native/platform split seed modules cannot be re-introduced.
        for stale in (
            "modules/nas/config/managed-services-native-services.nix",
            "modules/nas/config/managed-services-platform-routes.nix",
        ):
            self.assertFalse((ROOT / stale).exists(), f"split seed {stale} must stay deleted")
        # Route ownership is exclusive to managed-services-seed-v2.nix (and the
        # pathRoute helper); no other module may declare a path route.
        self.assertIn(
            "pathRoute", (ROOT / "modules/nas/config/managed-services-seed-v2.nix").read_text(encoding="utf-8")
        )
        self.assertIn(
            "pathRoute", (ROOT / "modules/nas/config/managed-services-helpers.nix").read_text(encoding="utf-8")
        )
        for module in (ROOT / "modules/nas/config").glob("*.nix"):
            source = module.read_text(encoding="utf-8")
            if module.name in {"managed-services-seed-v2.nix", "managed-services-helpers.nix"}:
                continue
            self.assertNotIn("pathRoute [", source, f"route catalog must stay in seed, not {module.name}")


if __name__ == "__main__":
    unittest.main()
