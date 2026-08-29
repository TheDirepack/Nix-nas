{ lib, pkgs, nasInternal, ... }:

let
  inherit (nasInternal) cockpitPort;
  proxySocket = "/run/nas-cockpit-proxy/http.sock";
in
{
  # cockpit-ws --local-session intentionally skips Cockpit authentication.
  # Keep its TCP listener in a private network namespace so no host-local
  # process can bypass the Caddy + Authentik authorization boundary.
  systemd.services.nas-cockpit-sso.serviceConfig.PrivateNetwork = true;

  # `services.cockpit.enable` is retained for Cockpit's package, plugins, PAM,
  # and generated configuration, but the upstream NixOS module also enables a
  # host-network cockpit.socket on services.cockpit.port. That would become an
  # alternate authentication ingress whenever the NAS firewall is disabled.
  # The appliance has exactly one Cockpit ingress: the Caddy-only Unix proxy
  # below. Keep the upstream socket installed but neither boot-enabled nor
  # manually startable.
  systemd.sockets.cockpit = {
    wantedBy = lib.mkOverride 90 [ ];
    unitConfig.RefuseManualStart = true;
  };

  # Caddy reaches Cockpit only through this host-visible Unix socket. The
  # socket-proxy process joins the Cockpit network namespace for its outbound
  # loopback connection, while the listening fd remains the systemd-created
  # AF_UNIX socket in the host namespace.
  systemd.sockets.nas-cockpit-proxy = {
    description = "Caddy-only socket for isolated Cockpit SSO";
    wantedBy = [ "sockets.target" ];
    socketConfig = {
      ListenStream = proxySocket;
      SocketUser = "root";
      SocketGroup = "caddy";
      SocketMode = "0660";
      DirectoryMode = "0750";
      RemoveOnStop = true;
    };
  };

  systemd.services.nas-cockpit-proxy = {
    description = "Proxy Caddy Unix socket into isolated Cockpit namespace";
    requires = [ "nas-cockpit-sso.service" ];
    after = [ "nas-cockpit-sso.service" ];
    unitConfig.JoinsNamespaceOf = [ "nas-cockpit-sso.service" ];
    serviceConfig = {
      ExecStart = "${pkgs.systemd}/lib/systemd/systemd-socket-proxyd 127.0.0.1:${toString cockpitPort}";
      PrivateNetwork = true;
      DynamicUser = true;
      NoNewPrivileges = true;
      PrivateTmp = true;
      PrivateDevices = true;
      ProtectHome = true;
      ProtectSystem = "strict";
      ProtectKernelTunables = true;
      ProtectKernelModules = true;
      ProtectKernelLogs = true;
      ProtectControlGroups = true;
      RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" ];
      RestrictRealtime = true;
      RestrictSUIDSGID = true;
      LockPersonality = true;
    };
  };
}
