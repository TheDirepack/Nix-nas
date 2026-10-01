{ config, lib, pkgs, nasInternal, ... }:

let
  cfg = config.nas;
  obs = cfg.observability;
  inherit (nasInternal) failureAlert;
  credentialPath = "/run/nas-alertmanager-ntfy/config.yml";
  renderConfig = ../../../scripts/lib/render-alertmanager-ntfy-config.py;
in
{
  config = lib.mkIf (obs.enable && cfg.alerting.enable) {
    # The custom router implementation is deleted. This lower-priority override
    # suppresses the old split declaration until that block is removed outright.
    systemd.services.nas-alert-router.enable = lib.mkOverride 80 false;

    systemd.services.alertmanager = {
      onFailure = failureAlert;
      wantedBy = lib.mkOverride 90 [ ];
      partOf = [ "nas-protected-services.target" ];
      wants = lib.optional obs.ntfy.enable "alertmanager-ntfy.service";
      after = lib.optional obs.ntfy.enable "alertmanager-ntfy.service";
    };

    systemd.services.vmalert-nas = {
      after = lib.mkOverride 80 [ "victoriametrics.service" "alertmanager.service" ];
      requires = lib.mkOverride 80 [ "victoriametrics.service" "alertmanager.service" ];
    };

    services.prometheus.alertmanager-ntfy.extraConfigFiles =
      lib.mkIf obs.ntfy.enable (lib.mkOverride 80 [ credentialPath ]);

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
      onFailure = failureAlert;
      wantedBy = lib.mkOverride 90 [ ];
      partOf = [ "nas-protected-services.target" ];
      after = lib.mkAfter [ "nas-alertmanager-ntfy-config.service" "ntfy-sh.service" ];
      requires = lib.mkAfter [ "nas-alertmanager-ntfy-config.service" ];
      wants = lib.mkAfter [ "ntfy-sh.service" ];
      unitConfig.ConditionPathExists = lib.mkOverride 80 [ credentialPath ];
    };
  };
}
