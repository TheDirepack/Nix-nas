{ lib, ... }:

{
  config = {
    systemd.tmpfiles.rules = [
      "d /run/nas-control/generations 0755 root root -"
    ];

    # Effective state is now an immutable file reached through the atomically
    # switched /run/nas-control/current generation pointer. Watch that pointer
    # rather than relying on inotify behavior through a stable symlink.
    systemd.paths.nas-managed-services-authentik-reconcile.pathConfig = lib.mkForce {
      PathChanged = "/run/nas-control/current";
      Unit = "nas-managed-services-authentik-reconcile.service";
    };

    # Native per-route systemd sockets replaced the authorization-free Python
    # wake HTTP service. Caddy authenticates first and then connects directly to
    # the generated activation socket. Keep the existing After= ordering: an
    # ordering edge to a disabled socket is harmless and preserves all backend
    # ordering contributed by systemd-services.nix.
    systemd.sockets.nas-managed-services-wake.enable = lib.mkForce false;
    systemd.services."nas-managed-services-wake@".enable = lib.mkForce false;
    systemd.services.caddy.requires = lib.mkOverride 900 [ "nas-caddy-bootstrap.service" ];
  };
}
