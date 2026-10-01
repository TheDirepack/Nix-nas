{ config, lib, pkgs, ... }:

let
  cfg = config.nas;
  obs = cfg.observability;
  credentialPath = "/run/nas-alertmanager-ntfy/config.yml";
  renderConfig = ../../../scripts/lib/render-alertmanager-ntfy-config.py;
in
{
  config = lib.mkIf (obs.enable && cfg.alerting.enable) {
    # Existing mutable services.yaml files refer to nas-alert-router.service.
    # Keep that service name as an alias so upgrades do not require rewriting
    # the runtime service authority just to replace its implementation.
    systemd.services.alertmanager.aliases = [ "nas-alert-router.service" ];
    systemd.services.nas-alert-router.enable = lib.mkForce false;

    systemd.services.vmalert-nas = {
      after = lib.mkForce [ "victoriametrics.service" "alertmanager.service" ];
      requires = lib.mkForce [ "victoriametrics.service" "alertmanager.service" ];
    };

    services.prometheus.alertmanager-ntfy.extraConfigFiles = lib.mkIf obs.ntfy.enable (lib.mkForce [ credentialPath ]);

    systemd.services.nas-alertmanager-ntfy-config = lib.mkIf obs.ntfy.enable {
      description = "Render alertmanager-ntfy runtime credentials";
      wantedBy = lib.mkOverride 90 [ ];
      partOf = [ "nas-protected-services.target" ];
      before = [ "alertmanager-ntfy.service" ];
      unitConfig.ConditionPathExists = [
        "/run/nas-secrets/observability/ntfy-topic"
        "/run/nas-secrets/observability/ntfy-admin-password"
      ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        RuntimeDirectory = "nas-alertmanager-ntfy";
        RuntimeDirectoryMode = "0700";
        ExecStart = "${pkgs.python3}/bin/python3 ${renderConfig}";
        NoNewPrivileges = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictAddressFamilies = [ "AF_UNIX" ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        CapabilityBoundingSet = [ ];
        ReadOnlyPaths = [ "/run/nas-secrets/observability" ];
        ReadWritePaths = [ "/run/nas-alertmanager-ntfy" ];
        UMask = "0077";
      };
    };

    systemd.services.alertmanager-ntfy = lib.mkIf obs.ntfy.enable {
      after = lib.mkAfter [ "nas-alertmanager-ntfy-config.service" ];
      requires = lib.mkAfter [ "nas-alertmanager-ntfy-config.service" ];
      unitConfig.ConditionPathExists = lib.mkForce [ credentialPath ];
    };
  };
}
