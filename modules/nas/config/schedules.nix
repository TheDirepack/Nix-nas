{ nasInternal, ... }:

let
  inherit (nasInternal) protectedServiceUnits;
in
{
  config.systemd.targets.nas-protected-services = {
    description = "NAS core services enabled after KeePassXC secret activation";
    requires = protectedServiceUnits;
    wants = [ "network-online.target" ];
    after = [ "network-online.target" ] ++ protectedServiceUnits;
  };
}
