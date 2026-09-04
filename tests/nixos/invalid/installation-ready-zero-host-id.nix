{ lib, pkgs, ... }:

{
  networking.hostId = lib.mkForce "00000000";

  nas = {
    installationReady = lib.mkForce true;
    testing.installationReadyFixture = true;
    trustedInterfaces = lib.mkForce [ "eth0" ];
    zfsEncryption.acknowledgeUnencrypted = lib.mkForce true;
  };
}
