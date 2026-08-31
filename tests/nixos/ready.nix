{ lib, pkgs, ... }:

{
  networking.hostId = lib.mkForce "c1a05eed";
  networking.interfaces.eth0.useDHCP = true;
  boot.loader.systemd-boot.enable = lib.mkForce true;
  boot.loader.efi.canTouchEfiVariables = lib.mkForce false;

  nas = {
    installationReady = lib.mkForce true;
    testing.installationReadyFixture = true;
    hostPolicy.consoleRecoveryVerified = true;
    trustedInterfaces = lib.mkForce [ "eth0" ];
    zfsImportAtBoot = lib.mkForce true;
    zfsEncryption.acknowledgeUnencrypted = lib.mkForce true;
    autoUpdate.enable = lib.mkForce false;
    backup.enable = lib.mkForce false;
  };
}
