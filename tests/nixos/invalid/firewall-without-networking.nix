{ lib, ... }:
{
  nas.networking.enable = lib.mkForce false;
  nas.networking.firewall.enable = lib.mkForce true;
}
