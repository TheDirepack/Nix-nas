{ lib, pkgs, ... }:

{
  nas = {
    installationReady = lib.mkForce true;
    testing.installationReadyFixture = true;
    trustedInterfaces = lib.mkForce [ ];
    zfsEncryption.acknowledgeUnencrypted = lib.mkForce true;
  };
}
