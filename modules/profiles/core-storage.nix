{ lib, ... }:

{
  nas = {
    networking.enable = lib.mkDefault true;
    networking.firewall.enable = lib.mkDefault true;
    networking.firewall.seedDefaults = lib.mkDefault true;
    scheduler.backend = lib.mkDefault "systemd";
  };
}
