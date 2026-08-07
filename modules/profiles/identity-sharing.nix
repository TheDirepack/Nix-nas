{ lib, ... }:

{
  nas = {
    syncthing.enable = lib.mkDefault true;
    vaultwarden.enable = lib.mkDefault true;
  };
}
