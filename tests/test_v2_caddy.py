from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
SCHEMA = ROOT / "schemas" / "managed-services-v3.schema.json"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_activation as activation  # noqa: E402
import nas_v2_caddy as caddy  # noqa: E402
import nas_v2_spec as v2  # noqa: E402


class ManagedServicesV2CaddyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = v2.load_schema(SCHEMA)

    def compile(self, service: dict) -> dict:
        return v2.compile_document({"schemaVersion": 3, "services": {"demo": service}}, self.schema)

    def base_service(self) -> dict:
        return {
            "name": "Demo",
            "workload": {"kind": "daemon", "activation": "persistent"},
            "runtime": {"type": "systemd", "unit": "demo.service"},
        }

    def test_identity_route_authorizes_in_caddy_before_proxy(self):
        service = self.base_service()
        service["authorization"] = {"capabilities": [{"id": "admin", "title": "Administration"}]}
        service["routes"] = {
            "web": {
                "target": {"type": "http", "port": 8080},
                "exposure": {"type": "path", "paths": ["/demo/"]},
                "auth": {"mode": "identity", "capability": "admin"},
            }
        }
        rendered = caddy.generate_caddyfile(self.compile(service))
        self.assertIn("request_header -X-Authentik-Username", rendered)
        self.assertIn("forward_auth 127.0.0.1:9010", rendered)
        self.assertIn('uri "/identity/outpost.goauthentik.io/auth/caddy"', rendered)
        self.assertIn("X-Original-URL {http.request.scheme}://{http.request.host}{http.request.orig_uri}", rendered)
        self.assertNotIn("X-Original-URL {http.request.scheme}://{http.request.host}{http.request.uri}", rendered)
        self.assertIn("header_up X-Forwarded-Uri {uri}", rendered)
        self.assertIn("not header_regexp X-Authentik-Groups", rendered)
        self.assertIn(r"application\\.demo\\.admin", rendered)
        self.assertIn("respond @v2_demo_web_missing_capability 403", rendered)
        self.assertLess(rendered.index("forward_auth 127.0.0.1:9010"), rendered.index("reverse_proxy 127.0.0.1:8080"))
        self.assertLess(rendered.index("missing_capability"), rendered.index("reverse_proxy 127.0.0.1:8080"))
        self.assertNotIn("nas-feature-control", rendered)
        self.assertNotIn("/authorize?", rendered)

    def test_authentik_listener_configuration_uses_scalar_addresses(self):
        config = (ROOT / "modules/nas/config/application-services.nix").read_text(encoding="utf-8")
        self.assertIn('http = "127.0.0.1:${toString authentikPort}";', config)
        self.assertIn('https = "";', config)
        self.assertNotIn('http = [ "127.0.0.1:${toString authentikPort}" ];', config)

    def test_embedded_authentik_outpost_replaces_custom_proxy_daemon(self):
        config = (ROOT / "modules/nas/config/application-services.nix").read_text(encoding="utf-8")
        self.assertNotIn("systemd.services.nas-authentik-proxy-outpost", config)
        self.assertNotIn("${pkgs.authentik-outposts.proxy}/bin/proxy", config)
        self.assertNotIn("AUTHENTIK_LISTEN__HTTP", config)
        self.assertNotIn("authentikOutpostPort", config)
        self.assertIn('http = "127.0.0.1:${toString authentikPort}";', config)

    def test_bootstrap_waits_for_authentik_default_flows_before_reconciling(self):
        services = (ROOT / "modules/nas/config/systemd-services.nix").read_text(encoding="utf-8")
        applications = (ROOT / "modules/nas/config/application-services.nix").read_text(encoding="utf-8")
        self.assertIn('ExecStartPost = pkgs.writeShellScript "authentik-ready"', applications)
        self.assertIn('after = [ "authentik.service" ];', services)

    def test_bootstrap_authentik_services_are_directly_enabled(self):
        services = (ROOT / "modules/nas/config/systemd-services.nix").read_text(encoding="utf-8")
        for unit in ("authentik-migrate", "authentik-worker", "authentik"):
            with self.subTest(unit=unit):
                stanza = services.split(f"    {unit} = {{", 1)[1].split("\n    };", 1)[0]
                self.assertIn('wantedBy = lib.mkOverride 90 [ "multi-user.target" ];', stanza)

    def test_runtime_selector_starts_identity_stack_after_creating_runtime_files(self):
        applications = (ROOT / "modules/nas/config/application-services.nix").read_text(encoding="utf-8")
        selector = applications.split("config.systemd.services.nas-bootstrap-runtime-select = {", 1)[1].split(
            "config.systemd.services.nas-bootstrap-authentik-secrets = {", 1
        )[0]
        for unit in ("authentik-migrate.service", "authentik-worker.service", "authentik.service"):
            self.assertIn(f'"{unit}"', selector)

    def test_v2_blueprint_root_preserves_native_nested_blueprints(self):
        blueprint = (ROOT / "modules/nas/config/managed-services-authentik-blueprint.nix").read_text(encoding="utf-8")
        self.assertIn("cp -a --no-preserve=ownership,mode", blueprint)
        self.assertIn("nas-authentik-blueprints.service", blueprint)
        self.assertIn(
            'before = [ "authentik-migrate.service" "authentik-worker.service" "authentik.service" ];',
            blueprint,
        )

    def test_authentik_login_flow_routes_rewrite_to_the_prefixed_ui(self):
        for relative_path in (
            "modules/nas/config/caddy-bootstrap.nix",
            "modules/nas/config/reverse-proxy.nix",
        ):
            with self.subTest(path=relative_path):
                config = (ROOT / relative_path).read_text(encoding="utf-8")
                self.assertIn("@authentikFlows path /flows/*", config)
                flow_start = config.index("handle @authentikFlows {")
                flow_end = (
                    config.index("\n      }", flow_start)
                    if "reverse-proxy" in relative_path
                    else config.index("\n  }", flow_start)
                )
                flow_handler = config[flow_start:flow_end]
                self.assertIn("uri replace /flows ${cfg.identity.authentikPath}flows", flow_handler)
                self.assertIn("reverse_proxy 127.0.0.1:${toString authentikPort}", flow_handler)
                self.assertNotIn("${caddyForwardAuth}", flow_handler)

    def test_managed_routes_forward_authenticate_through_embedded_outpost(self):
        config = (ROOT / "modules/nas/config/managed-services.nix").read_text(encoding="utf-8")
        self.assertIn(
            'NAS_V2_AUTHENTIK_UPSTREAM = "127.0.0.1:${toString authentikPort}";',
            config,
        )
        self.assertNotIn("authentikOutpostPort", config)
        self.assertNotIn("NAS_V2_AUTHENTIK_PUBLIC_HOST", config)

    def test_forward_auth_sends_forwarded_trio_and_does_not_rewrite_locations(self):
        helpers = (ROOT / "modules/nas/internal/caddy-helpers.nix").read_text(encoding="utf-8")
        self.assertIn("header_up X-Forwarded-Proto {scheme}", helpers)
        self.assertIn("header_up X-Forwarded-Host {http.request.hostport}", helpers)
        self.assertIn("header_up X-Forwarded-Uri {uri}", helpers)
        self.assertIn("X-Original-URL", helpers)
        self.assertNotIn("header_down Location", helpers)

        service = self.base_service()
        service["authorization"] = {"capabilities": [{"id": "admin", "title": "Administration"}]}
        service["routes"] = {
            "web": {
                "target": {"type": "http", "port": 8080},
                "exposure": {"type": "path", "paths": ["/demo/"]},
                "auth": {"mode": "identity", "capability": "admin"},
            }
        }
        rendered = caddy.generate_caddyfile(self.compile(service))
        self.assertIn("forward_auth 127.0.0.1:9010", rendered)
        self.assertIn("header_up X-Forwarded-Uri {uri}", rendered)
        self.assertNotIn("header_down Location", rendered)

    def test_bootstrap_reconciles_portal_for_embedded_outpost(self):
        options = (ROOT / "modules/nas/options/core.nix").read_text(encoding="utf-8")
        services = (ROOT / "modules/nas/config/systemd-services.nix").read_text(encoding="utf-8")
        applications = (ROOT / "modules/nas/config/application-services.nix").read_text(encoding="utf-8")
        account_tools = (ROOT / "modules/nas/internal/account-tools.nix").read_text(encoding="utf-8")
        vm = (ROOT / "tests/nixos/qemu-installed.nix").read_text(encoding="utf-8")

        self.assertIn("publicHost = lib.mkOption", options)
        self.assertIn('default = "${config.networking.hostName}.local";', options)
        self.assertIn('nas.identity.publicHost = lib.mkForce "nas-test.local:8443";', vm)
        self.assertIn("nas-identity-bootstrap = {", services)
        self.assertIn('requires = [ "authentik.service" ];', services)
        self.assertIn('wantedBy = [ "authentik.service" ];', services)
        self.assertNotIn(
            'wantedBy = [ "multi-user.target" ];', services[services.index("nas-identity-bootstrap = {") :]
        )
        self.assertIn("NAS_AUTHENTIK_BOOTSTRAP_TOKEN_FILE = authentikRuntimeApiTokenFile;", services)
        self.assertIn("NAS_PUBLIC_HOST = cfg.identity.publicHost;", services)
        self.assertNotIn("nas-authentik-proxy-outpost.service", services)
        self.assertIn("\"''${NAS_AUTHENTIK_BOOTSTRAP_TOKEN_FILE:-", account_tools)
        self.assertNotIn("nas-authentik-proxy-outpost", applications)
        self.assertIn('http = "127.0.0.1:${toString authentikPort}";', applications)

    def test_public_and_upstream_routes_do_not_call_authentik(self):
        for mode in ("public", "upstream"):
            with self.subTest(mode=mode):
                service = self.base_service()
                service["routes"] = {
                    "web": {
                        "target": {"type": "http", "port": 8080},
                        "exposure": {"type": "path", "paths": ["/demo/"]},
                        "auth": {"mode": mode},
                    }
                }
                rendered = caddy.generate_caddyfile(self.compile(service))
                self.assertNotIn("forward_auth 127.0.0.1:9000", rendered)
                self.assertNotIn("copy_headers", rendered)
                self.assertIn("reverse_proxy 127.0.0.1:8080", rendered)

    def test_public_routes_strip_all_identity_headers(self):
        service = self.base_service()
        service["routes"] = {
            "web": {
                "target": {"type": "http", "port": 8080},
                "exposure": {"type": "path", "paths": ["/demo/"]},
                "auth": {"mode": "public"},
            }
        }
        rendered = caddy.generate_caddyfile(self.compile(service))
        for header in caddy.IDENTITY_HEADERS:
            with self.subTest(header=header):
                self.assertIn(f"request_header -{header}", rendered)
        self.assertLess(rendered.index("request_header -Remote-User"), rendered.index("reverse_proxy"))
        self.assertNotIn("Remote-User {http.request.header", rendered)

    def test_upstream_routes_strip_all_identity_headers(self):
        service = self.base_service()
        service["routes"] = {
            "web": {
                "target": {"type": "http", "port": 8080},
                "exposure": {"type": "path", "paths": ["/demo/"]},
                "auth": {"mode": "upstream"},
            }
        }
        rendered = caddy.generate_caddyfile(self.compile(service))
        for header in caddy.IDENTITY_HEADERS:
            with self.subTest(header=header):
                self.assertIn(f"request_header -{header}", rendered)
        self.assertNotIn("forward_auth", rendered)

    def test_identity_route_strips_full_corpus(self):
        service = self.base_service()
        service["authorization"] = {"capabilities": [{"id": "admin", "title": "Administration"}]}
        service["routes"] = {
            "web": {
                "target": {"type": "http", "port": 8080},
                "exposure": {"type": "path", "paths": ["/demo/"]},
                "auth": {"mode": "identity", "capability": "admin"},
            }
        }
        rendered = caddy.generate_caddyfile(self.compile(service))
        expected_headers = (
            "Remote-User",
            "Remote-Groups",
            "Remote-Name",
            "Remote-Email",
            "Remote-UID",
            "Remote-Role",
            "X-Authentik-Username",
            "X-Authentik-Groups",
            "X-Authentik-Name",
            "X-Authentik-Email",
            "X-Authentik-Uid",
            "X-Authentik-Jwt",
            "X-Authentik-Entitlements",
            "X-Authentik-Meta-Outpost",
            "X-Authentik-Meta-App",
            "X-Authentik-Meta-Provider",
            "X-Authentik-Meta-User",
            "X-Authentik-Meta-Is-Superuser",
            "X-Authentik-Role",
        )
        for header in expected_headers:
            with self.subTest(header=header):
                self.assertIn(f"request_header -{header}", rendered)
        self.assertEqual(set(caddy.IDENTITY_HEADERS), set(expected_headers))
        self.assertEqual(caddy.TRUSTED_IDENTITY_HEADERS, frozenset(expected_headers))
        self.assertLess(rendered.index("request_header -Remote-User"), rendered.index("forward_auth"))

    def test_activation_socket_path_is_derived_from_validated_ids(self):
        self.assertEqual(str(activation.socket_path("demo", "web")), "/run/nas-control/activate/demo-web.sock")
        for service_id, route_id in (("../demo", "web"), ("demo", "web\nroute"), ("demo", "web/route")):
            with self.subTest(service_id=service_id, route_id=route_id):
                with self.assertRaises(activation.ActivationProjectionError):
                    activation.socket_path(service_id, route_id)

    def test_on_demand_route_authorizes_before_native_socket_activation(self):
        service = self.base_service()
        service["workload"] = {"kind": "daemon", "activation": "on-demand", "idleSeconds": 60}
        service["routes"] = {
            "web": {
                "target": {"type": "http", "port": 8080},
                "exposure": {"type": "path", "paths": ["/demo/"]},
                "auth": {"mode": "identity"},
            }
        }
        rendered = caddy.generate_caddyfile(self.compile(service))
        capability_position = rendered.index("missing_capability")
        proxy = "reverse_proxy unix//run/nas-control/activate/demo-web.sock"
        proxy_position = rendered.index(proxy)
        self.assertLess(capability_position, proxy_position)
        self.assertNotIn("/wake?", rendered)
        self.assertNotIn("reverse_proxy 127.0.0.1:8080", rendered)
        self.assertNotIn("Remote-User {http.request.header.Remote-User}", rendered)

    def test_on_demand_upstream_auth_fails_closed(self):
        service = self.base_service()
        service["workload"] = {"kind": "daemon", "activation": "on-demand", "idleSeconds": 60}
        service["routes"] = {
            "api": {
                "target": {"type": "http", "port": 8080},
                "exposure": {"type": "path", "paths": ["/api/"]},
                "auth": {"mode": "upstream"},
            }
        }
        with self.assertRaisesRegex(caddy.CaddyProjectionError, "native socket activation"):
            caddy.generate_caddyfile(self.compile(service))

    def test_disabled_service_has_no_route(self):
        service = self.base_service()
        service["enabled"] = False
        service["routes"] = {
            "web": {
                "target": {"type": "http", "port": 8080},
                "exposure": {"type": "path", "paths": ["/demo/"]},
                "auth": {"mode": "public"},
            }
        }
        rendered = caddy.generate_caddyfile(self.compile(service))
        self.assertNotIn("/demo/", rendered)
        self.assertNotIn("reverse_proxy", rendered)

    def test_hostname_route_cannot_duplicate_appliance_site(self):
        service = self.base_service()
        service["routes"] = {
            "web": {
                "target": {"type": "http", "port": 8080},
                "exposure": {"type": "hostname", "hostnames": ["nas.local"]},
                "auth": {"mode": "public"},
            }
        }
        with self.assertRaisesRegex(caddy.CaddyProjectionError, "collides"):
            caddy.generate_caddyfile(self.compile(service), lan_host="nas.local")

    def test_unix_target_and_proxy_headers(self):
        service = self.base_service()
        service["routes"] = {
            "web": {
                "target": {"type": "unix-http", "socket": "/run/demo/http.sock"},
                "exposure": {"type": "path", "paths": ["/demo"]},
                "auth": {"mode": "public"},
                "proxy": {
                    "stripPrefix": "/demo",
                    "requestHeaders": {"X-Forwarded-Prefix": "/demo"},
                    "removeRequestHeaders": ["X-Untrusted"],
                    "responseHeaders": {"X-Frame-Options": "SAMEORIGIN"},
                    "requireHeaders": {"Origin": "https://nas.local"},
                },
            }
        }
        rendered = caddy.generate_caddyfile(self.compile(service))
        self.assertIn('not header Origin "https://nas.local"', rendered)
        self.assertIn("request_header -X-Untrusted", rendered)
        self.assertIn('request_header X-Forwarded-Prefix "/demo"', rendered)
        self.assertIn('uri strip_prefix "/demo"', rendered)
        self.assertIn("reverse_proxy unix//run/demo/http.sock", rendered)
        self.assertIn('header_down X-Frame-Options "SAMEORIGIN"', rendered)

    def test_static_request_headers_cannot_forge_trusted_identity(self):
        service = self.base_service()
        service["routes"] = {
            "web": {
                "target": {"type": "http", "port": 8080},
                "exposure": {"type": "path", "paths": ["/demo/"]},
                "auth": {"mode": "identity"},
                "proxy": {"requestHeaders": {"Remote-User": "admin"}},
            }
        }
        with self.assertRaisesRegex(caddy.CaddyProjectionError, "trusted identity"):
            caddy.generate_caddyfile(self.compile(service))

    def test_trusted_identity_header_projection_requires_identity_auth(self):
        service = self.base_service()
        service["routes"] = {
            "web": {
                "target": {"type": "http", "port": 8080},
                "exposure": {"type": "path", "paths": ["/demo/"]},
                "auth": {"mode": "public"},
                "proxy": {"trustedIdentityHeaders": ["Remote-User"]},
            }
        }
        with self.assertRaisesRegex(caddy.CaddyProjectionError, "requires identity"):
            caddy.generate_caddyfile(self.compile(service))

    def test_parent_child_routes_render_longest_first(self):
        def svc(sid: str, path: str) -> dict:
            return {
                "name": sid,
                "workload": {"kind": "daemon"},
                "runtime": {"type": "systemd", "unit": f"{sid}.service"},
                "routes": {
                    "web": {
                        "target": {"type": "http", "port": 8080},
                        "exposure": {"type": "path", "paths": [path]},
                        "auth": {"mode": "public"},
                    }
                },
            }

        doc = v2.compile_document(
            {
                "schemaVersion": 3,
                "services": {
                    "a": svc("a", "/shares"),
                    "b": svc("b", "/shares/admin"),
                    "c": svc("c", "/vault"),
                    "d": svc("d", "/vault/admin"),
                    "e": svc("e", "/ai/"),
                    "f": svc("f", "/ai/v1"),
                    "g": svc("g", "/ai/runtime"),
                },
            },
            self.schema,
        )
        rendered = caddy.generate_caddyfile(doc)
        self.assertLess(rendered.index("/shares/admin"), rendered.index('"/shares"'))
        self.assertLess(rendered.index("/vault/admin"), rendered.index('"/vault"'))
        pos_runtime = rendered.index("/ai/runtime")
        pos_v1 = rendered.index("/ai/v1")
        pos_ai = rendered.index('path "/ai/"')
        if pos_ai == -1:
            pos_ai = rendered.index('"/ai/*"')
        self.assertLess(pos_runtime, pos_ai)
        self.assertLess(pos_v1, pos_ai)

    def test_real_seed_overlapping_routes_compile_and_render(self):
        copyparty_files = {
            "name": "CopyParty",
            "workload": {"kind": "daemon"},
            "runtime": {"type": "systemd", "unit": "copyparty.service"},
            "authorization": {"capabilities": [{"id": "files", "title": "Files"}, {"id": "admin", "title": "Admin"}]},
            "routes": {
                "files": {
                    "target": {"type": "http", "port": 8000},
                    "exposure": {"type": "path", "paths": ["/shares"]},
                    "auth": {"mode": "identity", "capability": "files"},
                },
                "admin": {
                    "target": {"type": "http", "port": 8000},
                    "exposure": {"type": "path", "paths": ["/shares/admin"]},
                    "auth": {"mode": "identity", "capability": "admin"},
                },
            },
        }
        vault = {
            "name": "Vaultwarden",
            "workload": {"kind": "daemon"},
            "runtime": {"type": "systemd", "unit": "vaultwarden.service"},
            "authorization": {"capabilities": [{"id": "admin", "title": "Admin"}]},
            "routes": {
                "web": {
                    "target": {"type": "http", "port": 8001},
                    "exposure": {"type": "path", "paths": ["/vault"]},
                    "auth": {"mode": "public"},
                },
                "admin": {
                    "target": {"type": "http", "port": 8001},
                    "exposure": {"type": "path", "paths": ["/vault/admin"]},
                    "auth": {"mode": "identity", "capability": "admin"},
                },
            },
        }
        ai_runtime = {
            "name": "AI Runtime",
            "workload": {"kind": "daemon"},
            "runtime": {"type": "systemd", "unit": "ai-runtime.service"},
            "routes": {
                "admin": {
                    "target": {"type": "http", "port": 8002},
                    "exposure": {"type": "path", "paths": ["/ai/runtime"]},
                    "auth": {"mode": "public"},
                },
                "api": {
                    "target": {"type": "http", "port": 8002},
                    "exposure": {"type": "path", "paths": ["/ai/v1"]},
                    "auth": {"mode": "public"},
                },
            },
        }
        ai_workspace = {
            "name": "Open WebUI",
            "workload": {"kind": "daemon"},
            "runtime": {"type": "systemd", "unit": "ai-workspace.service"},
            "routes": {
                "main": {
                    "target": {"type": "http", "port": 8003},
                    "exposure": {"type": "path", "paths": ["/ai/"]},
                    "auth": {"mode": "public"},
                }
            },
        }
        effective = v2.compile_document(
            {
                "schemaVersion": 3,
                "services": {
                    "copyparty": copyparty_files,
                    "vaultwarden": vault,
                    "ai-runtime": ai_runtime,
                    "ai-workspace": ai_workspace,
                },
            },
            self.schema,
        )
        rendered = caddy.generate_caddyfile(effective)
        for p in ("/shares", "/shares/admin", "/vault", "/vault/admin", "/ai/", "/ai/v1", "/ai/runtime"):
            self.assertIn(p.rstrip("/") if p != "/ai/" else "/ai", rendered)

    def test_exact_duplicate_path_still_fails_closed(self):
        one = self.base_service()
        one["routes"] = {
            "web": {
                "target": {"type": "http", "port": 8080},
                "exposure": {"type": "path", "paths": ["/shared/"]},
                "auth": {"mode": "public"},
            }
        }
        two = self.base_service()
        two["routes"] = {
            "web": {
                "target": {"type": "http", "port": 8081},
                "exposure": {"type": "path", "paths": ["/shared/"]},
                "auth": {"mode": "public"},
            }
        }
        with self.assertRaisesRegex(v2.ManagedServicesV2Error, "Duplicate"):
            v2.compile_document({"schemaVersion": 3, "services": {"one": one, "two": two}}, self.schema)
        one["routes"] = {
            "web": {
                "target": {"type": "http", "port": 8080},
                "exposure": {"type": "path", "paths": ["/api"]},
                "auth": {"mode": "public"},
            }
        }
        two["routes"] = {
            "web": {
                "target": {"type": "http", "port": 8081},
                "exposure": {"type": "path", "paths": ["/api/"]},
                "auth": {"mode": "public"},
            }
        }
        with self.assertRaisesRegex(v2.ManagedServicesV2Error, "Duplicate"):
            v2.compile_document({"schemaVersion": 3, "services": {"one": one, "two": two}}, self.schema)


if __name__ == "__main__":
    unittest.main()
