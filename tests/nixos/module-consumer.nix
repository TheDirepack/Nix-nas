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
    openssh.authorizedKeys.keys = [
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICITestFixtureOnlyKeyMaterial000000000000000 nas-ci"
    ];
  };

  nas = {
    installationReady = false;
    trustedInterfaces = [ ];
    autoUpdate.enable = lib.mkForce false;
    backup.enable = lib.mkForce false;
    zfsImportAtBoot = lib.mkForce false;
  };
}
