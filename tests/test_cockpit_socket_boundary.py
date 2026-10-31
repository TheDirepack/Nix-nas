from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
APPLICATION = ROOT / "modules/nas/config/application-services.nix"
CADDY = ROOT / "modules/nas/config/caddy-bootstrap.nix"
UPDATE = ROOT / "scripts/update-nas.sh"


class CockpitSocketBoundaryTests(unittest.TestCase):
    def test_privileged_bridge_uses_permissioned_unix_socket_without_tcp_listener(self) -> None:
        source = APPLICATION.read_text(encoding="utf-8")
        web = source.split('cockpitWebService = pkgs.writeShellScript', 1)[1].split(
            'authentikProxyOutpost = pkgs.writeShellScript', 1
        )[0]
        self.assertIn("--local-session", web)
        self.assertIn('export LISTEN_PID="$BASHPID"', web)
        self.assertIn("exec ${cockpitPatched}/libexec/cockpit-ws", web)
        self.assertNotIn("--address 127.0.0.1", web)
        self.assertNotIn("--port ${toString cockpitPort}", web)

        socket = source.split("systemd.sockets.nas-cockpit-sso = {", 1)[1].split(
            "systemd.services.nas-cockpit-sso = {", 1
        )[0]
        self.assertIn('ListenStream = "/run/nas-cockpit-sso/ws.sock";', socket)
        self.assertIn('SocketGroup = config.services.caddy.group;', socket)
        self.assertIn('SocketMode = "0660";', socket)
        self.assertIn('SocketUser = "root";', socket)
        service = source.split("systemd.services.nas-cockpit-sso = {", 1)[1].split(
            "systemd.services.nas-setup-api = {", 1
        )[0]
        self.assertIn('Sockets = [ "nas-cockpit-sso.socket" ];', service)

    def test_caddy_is_only_proxy_to_socket_and_updater_uses_unix_probe(self) -> None:
        config = CADDY.read_text(encoding="utf-8")
        self.assertIn("reverse_proxy unix//run/nas-cockpit-sso/ws.sock", config)
        self.assertNotIn("reverse_proxy 127.0.0.1:${toString cockpitPort}", config)
        updater = UPDATE.read_text(encoding="utf-8")
        self.assertIn("[[ -S /run/nas-cockpit-sso/ws.sock ]]", updater)
        self.assertNotIn('listener_present "$cockpit_port"', updater)


if __name__ == "__main__":
    unittest.main()
