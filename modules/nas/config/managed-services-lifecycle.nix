{ lib, ... }:

{
  config.systemd.services.nas-managed-services-authentik-reconcile = {
    # This finite projection needs the identity provider and compiled effective
    # state, not a direct lifecycle edge to the V2-managed identity-sync job.
    # Applications that need base identity state declare `completed` on that
    # job in services.yaml instead.
    requires = lib.mkForce [ "authentik.service" ];
    after = lib.mkForce [
      "authentik.service"
      "nas-managed-services-reconcile.service"
    ];
  };
}
