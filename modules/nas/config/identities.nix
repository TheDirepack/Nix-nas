{ config, lib, pkgs, nasInternal, ... }:

let
  inherit (nasInternal) cfg featureCatalog;
  featureUnits = lib.unique (
    lib.concatMap
      (entry: entry.startUnits ++ (entry.stopUnits or [ ]))
      (lib.attrValues featureCatalog.features)
  );
  featureUnitsJson = builtins.toJSON featureUnits;
in
{
  config = {
    users.mutableUsers = lib.mkDefault cfg.hostPolicy.mutableLocalPasswords;
    users.groups.authentik = { };
    users.groups.nas-feature-control = { };
    users.groups.nas-operations = { };
    users.users.nas-feature-gate = {
      isSystemUser = true;
      group = "nas-feature-control";
      extraGroups = [ "caddy" ] ++ lib.optional cfg.ai.enable "nas-ai-models";
    };
    users.users.authentik = {
      isSystemUser = true;
      group = "authentik";
      home = "/var/lib/authentik";
      createHome = true;
      homeMode = "0750";
    };
    users.users.caddy.extraGroups = [ "copyparty" ];
    security.polkit.enable = true;
    security.polkit.extraConfig = ''
      polkit.addRule(function(action, subject) {
        const allowedUnits = ${featureUnitsJson};
        const allowedVerbs = ["start", "stop", "restart"];
        if (subject.user === "nas-feature-gate"
            && action.id === "org.freedesktop.systemd1.manage-units"
            && allowedUnits.indexOf(action.lookup("unit")) >= 0
            && allowedVerbs.indexOf(action.lookup("verb")) >= 0) {
          return polkit.Result.YES;
        }
      });
    '';
    users.users.${cfg.adminUser} = {
      hashedPasswordFile = lib.mkIf (cfg.adminPasswordHashFile != null) cfg.adminPasswordHashFile;
      autoSubUidGidRange = true;
      linger = true;
      extraGroups = lib.mkAfter ([ "nas-operations" ] ++ lib.optionals cfg.virtualization.enable [ "libvirtd" "kvm" ]);
    };
  };
}
