from __future__ import annotations

import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


class CockpitSecurityTests(unittest.TestCase):
    def test_local_session_tcp_listener_is_network_namespace_isolated(self) -> None:
        default = read("modules/nas/default.nix")
        application = read("modules/nas/config/application-services.nix")
        hardening = read("modules/nas/config/cockpit-security.nix")

        self.assertIn("./config/cockpit-security.nix", default)
        self.assertIn("--local-session", application)
        self.assertIn("--address 127.0.0.1", application)
        self.assertIn("systemd.services.nas-cockpit-sso.serviceConfig.PrivateNetwork = true;", hardening)

    def test_only_caddy_group_can_enter_cockpit_through_host_namespace(self) -> None:
        hardening = read("modules/nas/config/cockpit-security.nix")
        self.assertIn("ListenStream = proxySocket;", hardening)
        self.assertIn('SocketUser = "root";', hardening)
        self.assertIn('SocketGroup = "caddy";', hardening)
        self.assertIn('SocketMode = "0660";', hardening)
        self.assertIn('DirectoryMode = "0750";', hardening)
        self.assertIn('unitConfig.JoinsNamespaceOf = [ "nas-cockpit-sso.service" ];', hardening)
        self.assertIn("systemd-socket-proxyd 127.0.0.1:${toString cockpitPort}", hardening)
        self.assertIn("PrivateNetwork = true;", hardening)

    def test_bootstrap_and_v2_routes_use_only_the_unix_proxy(self) -> None:
        bootstrap = read("modules/nas/config/caddy-bootstrap.nix")
        seed = read("modules/nas/config/managed-services-seed-v2.nix")

        console = bootstrap.split("handle /console* {", 1)[1].split("handle {", 1)[0]
        self.assertIn("${caddyForwardAuth}", console)
        self.assertIn("respond @missingCockpitAdmin 403", console)
        self.assertIn("reverse_proxy unix/${cockpitProxySocket}", console)
        self.assertNotIn("reverse_proxy 127.0.0.1", console)

        cockpit = seed.split("cockpit = {", 1)[1].split("    };\n  };", 1)[0]
        self.assertIn('type = "unix-http";', cockpit)
        self.assertIn('socket = "/run/nas-cockpit-proxy/http.sock";', cockpit)
        self.assertNotIn('host = "127.0.0.1";', cockpit)


if __name__ == "__main__":
    unittest.main()
