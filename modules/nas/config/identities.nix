{ config, lib, nasInternal, ... }:

let
  inherit (nasInternal) cfg authentikDataDir;
in
{
  config = {
    users.mutableUsers = lib.mkDefault cfg.hostPolicy.mutableLocalPasswords;
    users.groups.authentik = { };
    users.groups.nas-operations = { };
    users.users.authentik = {
      isSystemUser = true;
      group = "authentik";
      home = authentikDataDir;
      createHome = true;
      homeMode = "0750";
    };
    users.users.caddy.extraGroups = [ "copyparty" ];
    users.users.${cfg.adminUser} = {
      hashedPasswordFile = lib.mkIf (cfg.adminPasswordHashFile != null) cfg.adminPasswordHashFile;
      autoSubUidGidRange = true;
      linger = true;
      extraGroups = lib.mkAfter ([ "nas-operations" ] ++ lib.optionals cfg.virtualization.enable [ "libvirtd" "kvm" ]);
    };
  };
}
