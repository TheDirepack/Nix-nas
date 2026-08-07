{ config, lib, pkgs, nasInternal, ... }:

let
  cfg = config.nas;
  storePath = "/var/lib/nas-control/services.json";
  effectivePath = "/run/nas-control/effective-endpoints.json";
  portalPath = "/run/nas-control/portal.json";
in
{
  config = lib.mkIf true {
    systemd.tmpfiles.rules = [
      "d /var/lib/nas-control 0750 nas-feature-gate nas-feature-control -"
      "d /run/nas-control 0755 root root -"
      "f ${storePath} 0600 nas-feature-gate nas-feature-control - {\"schemaVersion\":2,\"services\":{}}"
    ];

    systemd.services.nas-managed-services-reconcile = {
      description = "Rebuild effective service registry and portal projection";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${nasInternal.nasPythonApplication}/bin/nas-managed-service reconcile";
        RemainAfterExit = true;
      };
    };

    systemd.paths.nas-managed-services-reconcile = {
      description = "Watch for managed service store changes";
      wantedBy = [ "multi-user.target" ];
      pathConfig = {
        PathChanged = storePath;
      };
    };

    environment.etc."nas-control/effective-endpoints.json".source = effectivePath;
  };
}
