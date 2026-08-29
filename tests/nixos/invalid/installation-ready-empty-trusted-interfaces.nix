{ lib, pkgs, ... }:

{
  nas = {
    installationReady = lib.mkForce true;
    testing.installationReadyFixture = true;
    trustedInterfaces = lib.mkForce [ ];
    adminPasswordHashFile = lib.mkForce (toString (pkgs.writeText "negative-admin-password-hash" "!"));
    zfsEncryption.acknowledgeUnencrypted = lib.mkForce true;
  };
}
