{ lib, ... }:

{
  system.stateVersion = "26.05";
  networking.hostId = "c0ffee22";
  networking.interfaces.eth0.useDHCP = true;

  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = false;

  users.users.admin = {
    isNormalUser = true;
    extraGroups = [ "wheel" ];
    openssh.authorizedKeys.keys = [ ];
  };

  nas = {
    installationReady = false;
    trustedInterfaces = [ ];
    autoUpdate.enable = lib.mkForce false;
    backup.enable = lib.mkForce false;
    zfsImportAtBoot = lib.mkForce false;
  };
}
