{ config, lib, pkgs, nasInternal, ... }:

let
  inherit (nasInternal)
    authentikApiTokenFile
    authentikPort
    cfg
    nasPythonApplication
    secretRoot
  ;
  storePath = "/var/lib/nas-control/services.json";
  effectivePath = "/run/nas-control/effective-endpoints.json";
  authentikUrl = "http://127.0.0.1:${toString authentikPort}${lib.removeSuffix "/" cfg.identity.authentikPath}";
in
{
  config = {
    # Authorization objects are reconciled only while the protected identity
    # plane is active. Editing V2 policy while the NAS is locked must never
    # force Authentik or its database to start.
    systemd.services.nas-authentik-v2-groups = {
      description = "Reconcile Managed Services V2 capability groups into Authentik";
      wantedBy = [ "nas-protected-services.target" ];
      partOf = [ "nas-protected-services.target" ];
      requires = [
        "authentik.service"
        "nas-managed-services-reconcile.service"
      ];
      after = [
        "authentik.service"
        "nas-managed-services-reconcile.service"
      ];
      environment = {
        NAS_AUTHENTIK_URL = authentikUrl;
        NAS_AUTHENTIK_TOKEN_FILE = authentikApiTokenFile;
      };
      unitConfig.ConditionPathExists = [
        "${secretRoot}/ready"
        authentikApiTokenFile
        effectivePath
      ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${nasPythonApplication}/bin/nas-authentik-v2-groups --effective ${effectivePath}";
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectHome = true;
        ProtectSystem = "strict";
        ReadOnlyPaths = [
          effectivePath
          authentikApiTokenFile
        ];
        RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" ];
        UMask = "0077";
      };
    };

    systemd.paths.nas-authentik-v2-groups = {
      description = "Watch V2 application policy for Authentik capability changes";
      wantedBy = [ "nas-protected-services.target" ];
      partOf = [ "nas-protected-services.target" ];
      pathConfig = {
        PathChanged = storePath;
        Unit = "nas-authentik-v2-groups.service";
      };
    };
  };
}
