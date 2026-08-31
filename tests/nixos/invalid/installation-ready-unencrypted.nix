{ lib, pkgs, ... }:

{
  nas = {
    installationReady = lib.mkForce true;
    testing.installationReadyFixture = true;
    trustedInterfaces = lib.mkForce [ "eth0" ];
    zfsEncryption.enable = lib.mkForce false;
    zfsEncryption.acknowledgeUnencrypted = lib.mkForce false;
  };
}
