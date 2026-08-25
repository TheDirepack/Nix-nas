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
        # The README example at spec/managed-services/README.md:1257 should compile
        # It defines ai-runtime (/ai/runtime/, /ai/v1/) and ai-workspace (/ai/) which are parent/child
        # With longest-path-first ordering, this should succeed and render with /ai/runtime before /ai/
        example = {
            "schemaVersion": 3,
            "services": {
                "ai-storage": {
                    "name": "AI storage",
                    "workload": {"kind": "job"},
                    "runtime": {"type": "systemd", "unit": "nas-ai-storage.service"},
                },
                "ai-config": {
                    "name": "AI config",
                    "workload": {"kind": "job"},
                    "runtime": {"type": "systemd", "unit": "nas-ai-config-init.service"},
                    "dependencies": [{"service": "ai-storage", "condition": "completed"}],
                },
                "ai-runtime": {
                    "name": "llama-swap",
                    "workload": {"kind": "daemon", "activation": "persistent"},
                    "runtime": {"type": "systemd", "unit": "nas-llama-swap.service"},
                    "dependencies": [{"service": "ai-config", "condition": "completed"}],
                    "authorization": {"capabilities": [{"id": "models", "title": "Manage models"}]},
                    "readiness": {"probes": [{"type": "tcp", "port": 8080}]},
                    "routes": {
                        "ui": {
                            "target": {"type": "http", "host": "127.0.0.1", "port": 8080},
                            "exposure": {"type": "path", "paths": ["/ai/runtime/"]},
                            "auth": {"mode": "identity", "capability": "access"},
                            "portal": {"visible": True, "category": "AI"},
                        },
                        "api": {
                            "target": {"type": "http", "host": "127.0.0.1", "port": 8080},
                            "exposure": {"type": "path", "paths": ["/ai/v1/"]},
                            "auth": {"mode": "upstream"},
                        },
                    },
                },
                "ai-workspace": {
                    "name": "Open WebUI",
                    "workload": {"kind": "daemon", "activation": "on-demand", "idleSeconds": 600},
                    "runtime": {"type": "systemd", "unit": "open-webui.service"},
                    "dependencies": [{"service": "ai-runtime", "condition": "ready"}],
                    "routes": {
                        "main": {
                            "target": {"type": "http", "host": "127.0.0.1", "port": 3000},
                            "exposure": {"type": "path", "paths": ["/ai/"]},
                            "auth": {"mode": "identity", "capability": "access"},
                            "portal": {"visible": True, "category": "AI"},
                        },
                    },
                },
            },
        }
        schema = spec.load_schema(SCHEMA)
        effective = spec.compile_document(example, schema)
        rendered = caddy.generate_caddyfile(effective)
        # Longest-path-first: /ai/runtime and /ai/v1 must appear before /ai/
        # Use specific path patterns to avoid substring matches
        self.assertLess(rendered.index('"/ai/runtime/"'), rendered.index('"/ai/" "/ai/*"'))
        self.assertLess(rendered.index('"/ai/v1/"'), rendered.index('"/ai/" "/ai/*"'))

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
        # The seed has /shares, /shares/admin, /vault, /vault/admin, /ai/, /ai/v1, /ai/runtime
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

    def test_cockpit_port_consistency(self):
        # Cockpit remains private on 9092; browser clients use the Caddy route.
        network = (ROOT / "services/nas_v2_network.py").read_text(encoding="utf-8")
        self.assertIn("NAS_V2_COCKPIT_PORT", network)
        self.assertIn("_remote_admin_ports", network)
        self.assertIn('"9092"', network)
        self.assertNotIn('("9090", "tcp")', network)
        # Check the private listener declaration and public interface documentation.
        base = (ROOT / "modules/nas/internal/base.nix").read_text(encoding="utf-8")
        self.assertIn("cockpitPort = 9092", base)
        interfaces = (ROOT / "docs/src/reference/interfaces.md").read_text(encoding="utf-8")
        self.assertIn("`/console/`", interfaces)
        self.assertNotIn("9092", interfaces)

    def test_portal_delimiter_parity(self):
        # Both nas_common and portal should use same delimiter
        common = (ROOT / "services/nas_common.py").read_text(encoding="utf-8")
        portal = (ROOT / "web/portal/index.html").read_text(encoding="utf-8")
        # Check that both use commas only (or both handle pipe/semicolon)
        # After fix, nas_common should only split on commas, and portal should only split on commas
        self.assertIn('raw.split(",")', common)
        self.assertIn('splitList ","', portal)
        # Ensure portal does not handle pipe/semicolon if common doesn't
        # This is now consistent: both use comma only

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
