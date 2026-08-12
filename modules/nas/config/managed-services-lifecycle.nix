{ config, lib, ... }:

{
  config.systemd.services = lib.mkMerge [
    {
      nas-managed-services-authentik-reconcile = {
        # This finite projection needs the identity provider and compiled effective
        # state, not a direct lifecycle edge to the V2-managed identity-sync job.
        # Applications that need base identity state declare `completed` on that
        # job in services.yaml instead.
        requires = lib.mkOverride 90 [ "authentik.service" ];
        after = lib.mkOverride 90 [
          "authentik.service"
          "nas-managed-services-reconcile.service"
        ];
      };
    }

    (lib.mkIf config.nas.syncthing.enable {
      nas-syncthing-sync = {
        # Authentik is platform substrate. Syncthing itself is V2-managed, so its
        # lifecycle edge is generated from the service dependency in services.yaml.
        requires = lib.mkOverride 90 [ "authentik.service" ];
        after = lib.mkOverride 90 [ "authentik.service" ];
      };
    })

    (lib.mkIf (config.nas.observability.enable && config.nas.alerting.enable) {
      vmalert-nas = {
        # VictoriaMetrics and the alert router are V2-managed applications. Their
        # dependency edges belong to the finite V2 systemd projection, not static
        # NixOS configuration that could bypass a desired `off` state.
        requires = lib.mkOverride 90 [ ];
        after = lib.mkOverride 90 [ ];
      };
    })
  ];
}
