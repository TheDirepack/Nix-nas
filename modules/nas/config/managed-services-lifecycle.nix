{ config, lib, pkgs, ... }:

let
  desiredPath = "/var/lib/nas-control/services.yaml";
  initialSeedMarker = "/var/lib/nas-control/.managed-services-native-seed-v2";
in
{
  config.systemd.services = lib.mkMerge [
    {
      nas-managed-services-seed = {
        # The canonical V2 spec permits Nix-provided application defaults to seed
        # services.yaml only when no V2 authority existed before this oneshot ran.
        # The base seed ExecStart creates a minimal stub when absent; this marker
        # carries the pre-ExecStart fact into the native-services postStart helper.
        preStart = lib.mkBefore ''
          if [ ! -e ${lib.escapeShellArg desiredPath} ]; then
            ${pkgs.coreutils}/bin/install -d -m 0750 -o root -g nas-operations /var/lib/nas-control
            : > ${lib.escapeShellArg initialSeedMarker}
          else
            ${pkgs.coreutils}/bin/rm -f ${lib.escapeShellArg initialSeedMarker}
          fi
        '';
      };

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

    (lib.mkIf config.nas.observability.ntfy.enable {
      "nas-health-alert@" = {
        # ntfy is a V2-managed application. A host health failure must not bypass
        # an explicit notifications=off desired state by pulling ntfy into service.
        wants = lib.mkOverride 90 [ ];
        after = lib.mkOverride 90 [ ];
      };
    })
  ];
}
