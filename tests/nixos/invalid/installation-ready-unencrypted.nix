{ lib, pkgs, ... }:

{
  nas = {
    installationReady = lib.mkForce true;
    testing.installationReadyFixture = true;
    trustedInterfaces = lib.mkForce [ "eth0" ];
    zfsEncryption.acknowledgeUnencrypted = lib.mkForce false;
  };
}
