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
        # carries the pre-ExecStart fact into the seed bootstrap postStart helper.
        # Once created it must survive a failed initial seed attempt so the next
        # oneshot invocation can retry. The bootstrap helper clears it after a
        # successful seed or after detecting a concurrent real authority writer.
        preStart = lib.mkBefore ''
          if [ ! -e ${lib.escapeShellArg desiredPath} ]; then
            ${pkgs.coreutils}/bin/install -d -m 0750 -o root -g nas-operations /var/lib/nas-control
            : > ${lib.escapeShellArg initialSeedMarker}
          fi
        '';
      };

      nas-managed-services-authentik-reconcile = {
        # First-boot identity uses Authentik's bootstrap token. Apply the V2
        # capability projection only after that one-time bootstrap has completed.
        # Applications that need base identity state declare `completed` on the
        # identity job in services.yaml instead.
        requires = lib.mkOverride 90 [ "authentik.service" "nas-identity-bootstrap.service" ];
        after = lib.mkOverride 90 [
          "authentik.service"
          "nas-identity-bootstrap.service"
          "nas-managed-services-reconcile.service"
        ];
      };
    }
  ];
}
