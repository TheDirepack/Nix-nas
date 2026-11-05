from __future__ import annotations

import copy
import pathlib
import re
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT / "services") not in sys.path:
    sys.path.insert(0, str(ROOT / "services"))

import nas_v2_caddy as caddy  # noqa: E402
import nas_v2_network as network  # noqa: E402
import nas_v2_quadlet as quadlet  # noqa: E402
import nas_v2_spec as spec  # noqa: E402


def isolated_app(name: str, host_port: int, *, container_port: int | None = None) -> dict:
    service = {
        "name": name,
        "workload": {"kind": "daemon", "activation": "persistent"},
        "runtime": {"type": "oci", "image": "example.invalid/web:1"},
        "network": {"mode": "isolated", "outboundDefault": "deny"},
        "routes": {
            "web": {
                "target": {"type": "http", "host": "127.0.0.1", "port": host_port},
                "exposure": {"type": "hostname", "hostnames": [f"{name}.example.test"]},
                "auth": {"mode": "identity"},
            }
        },
    }
    if container_port is not None:
        service["listeners"] = {
            "web": {
                "protocol": "tcp",
                "exposure": {"port": host_port},
                "targetPort": container_port,
                "firewall": False,
            }
        }
    return service


class RoutePublicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = spec.load_schema(ROOT / "schemas/managed-services-v3.schema.json")

    def compile(self, **services):
        return spec.compile_document({"schemaVersion": 3, "services": services}, self.schema)

    def assert_conflict(self, services, owner):
        with self.assertRaisesRegex(spec.ManagedServicesV2Error, owner) as raised:
            self.compile(**services)
        self.assertEqual(raised.exception.code, "route-port-conflict")
        self.assertIn(".routes.web.target.port", raised.exception.path)

    def test_two_apps_share_container_port_with_distinct_loopback_publications(self):
        effective = self.compile(
            alpha=isolated_app("alpha", 18080, container_port=8080),
            beta=isolated_app("beta", 18081, container_port=8080),
        )
        firewall, _ = network.compile_projection(effective, lan_zone="trusted")
        rendered_caddy = caddy.generate_caddyfile(effective)
        for name, port in (("alpha", 18080), ("beta", 18081)):
            with self.subTest(name=name):
                rendered = quadlet.render_quadlet(
                    effective, name, effective["services"][name], unit_lines=[], service_lines=[]
                ).decode()
                publications = [line for line in rendered.splitlines() if line.startswith("PublishPort=")]
                self.assertEqual(publications, [f'PublishPort="127.0.0.1:{port}:8080/tcp"'])
                self.assertIn(f"reverse_proxy 127.0.0.1:{port} {{", rendered_caddy)
                route_policy = firewall[f"policies/{network.route_policy_name(name)}"]
                self.assertEqual(route_policy["ports"], [["8080", "tcp"]])
                self.assertEqual((route_policy["ingress"], route_policy["egress"]), ("HOST", network.zone_name(name)))
                self.assertNotIn(f"policies/{network.listener_policy_name(name)}", firewall)
        self.assertIn("application[.]alpha[.]access", rendered_caddy)
        self.assertIn("application[.]beta[.]access", rendered_caddy)

    def test_two_implicit_routes_cannot_reserve_the_same_host_port(self):
        self.assert_conflict({"alpha": isolated_app("alpha", 8080), "beta": isolated_app("beta", 8080)}, "alpha:web")

    def test_route_conflicts_with_other_services_listener_even_without_firewall(self):
        for reverse in (False, True):
            alpha = isolated_app("alpha", 18080)
            alpha.pop("routes")
            alpha["listeners"] = {"api": {"protocol": "tcp", "exposure": {"port": 8080}, "firewall": False}}
            services = {"alpha": alpha, "beta": isolated_app("beta", 8080)}
            if reverse:
                services = dict(reversed(list(services.items())))
            with self.subTest(reverse=reverse):
                self.assert_conflict(services, "alpha:api")

    def test_route_conflicts_with_listener_range(self):
        alpha = isolated_app("alpha", 18080)
        alpha.pop("routes")
        alpha["listeners"] = {"range": {"protocol": "tcp", "exposure": {"start": 8079, "end": 8081}}}
        self.assert_conflict({"alpha": alpha, "beta": isolated_app("beta", 8080)}, "alpha:range")

    def test_isolated_publication_cannot_take_native_loopback_upstream(self):
        native = isolated_app("native", 8080)
        native.pop("network")
        native["runtime"] = {"type": "systemd", "unit": "native.service"}
        self.assert_conflict({"native": native, "beta": isolated_app("beta", 8080)}, "native:web")

    def test_native_listener_target_port_is_also_reserved(self):
        native = {
            "name": "Native",
            "workload": {"kind": "daemon"},
            "runtime": {"type": "systemd", "unit": "native.service"},
            "listeners": {"api": {"protocol": "tcp", "exposure": {"port": 80}, "targetPort": 8080}},
        }
        self.assert_conflict({"native": native, "beta": isolated_app("beta", 8080)}, "native:api")

    def test_matching_listener_and_multiple_routes_share_one_publication(self):
        alpha = isolated_app("alpha", 18080, container_port=8080)
        alpha["routes"]["web"]["exposure"]["path"] = "/web"
        alpha["routes"]["api"] = copy.deepcopy(alpha["routes"]["web"])
        alpha["routes"]["api"]["exposure"]["path"] = "/api"
        effective = self.compile(alpha=alpha)
        firewall, _ = network.compile_projection(effective, lan_zone="trusted")
        self.assertEqual(firewall[f"policies/{network.route_policy_name('alpha')}"]["ports"], [["8080", "tcp"]])

    def test_udp_on_same_host_number_does_not_remap_http(self):
        alpha = isolated_app("alpha", 18080, container_port=8080)
        alpha["listeners"]["web"]["protocol"] = "udp"
        effective = self.compile(alpha=alpha)
        firewall, _ = network.compile_projection(effective, lan_zone="trusted")
        self.assertEqual(firewall[f"policies/{network.route_policy_name('alpha')}"]["ports"], [["18080", "tcp"]])

    def test_unchanged_document_retains_mapping_and_input_is_not_modified(self):
        services = {"alpha": isolated_app("alpha", 18080, container_port=8080)}
        before = copy.deepcopy(services)
        self.assertEqual(self.compile(**services), self.compile(**services))
        self.assertEqual(services, before)

    def test_nonisolated_routes_may_share_an_existing_upstream(self):
        alpha = isolated_app("alpha", 8080)
        beta = isolated_app("beta", 8080)
        for candidate in (alpha, beta):
            candidate.pop("network")
            candidate["runtime"] = {"type": "systemd", "unit": "shared.service"}
        self.compile(alpha=alpha, beta=beta)

    def test_network_profile_cannot_bypass_route_port_conflicts(self):
        alpha = isolated_app("alpha", 8080)
        alpha.pop("network")
        alpha["networkProfile"] = "private"
        with self.assertRaises(spec.ManagedServicesV2Error) as raised:
            spec.compile_document(
                {
                    "schemaVersion": 3,
                    "networkProfiles": {"private": {"mode": "isolated"}},
                    "services": {"alpha": alpha, "beta": isolated_app("beta", 8080)},
                },
                self.schema,
            )
        self.assertEqual(raised.exception.code, "route-port-conflict")

    def test_disabled_declarations_keep_their_reservations(self):
        alpha = isolated_app("alpha", 8080)
        alpha["enabled"] = False
        self.assert_conflict({"alpha": alpha, "beta": isolated_app("beta", 8080)}, "alpha:web")

    def test_operator_mapping_example_compiles_and_projects(self):
        text = (ROOT / "docs/src/admin/networking.md").read_text()
        example = re.search(r"```yaml\n(.*?)\n```", text, re.DOTALL)
        if example is None:
            self.fail("operator networking example is missing")
        effective = spec.compile_document(spec.parse_yaml_text(example[1]), self.schema)
        service = effective["services"]["alpha"]
        rendered = quadlet.render_quadlet(effective, "alpha", service, unit_lines=[], service_lines=[]).decode()
        self.assertIn('PublishPort="127.0.0.1:18080:8080/tcp"', rendered)


if __name__ == "__main__":
    unittest.main()
