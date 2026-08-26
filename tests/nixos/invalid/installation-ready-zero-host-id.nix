{ lib, pkgs, ... }:

{
  networking.hostId = lib.mkForce "00000000";

  nas = {
    installationReady = lib.mkForce true;
    testing.installationReadyFixture = true;
    trustedInterfaces = lib.mkForce [ "eth0" ];
    adminPasswordHashFile = lib.mkForce (toString (pkgs.writeText "negative-admin-password-hash" "!"));
    zfsEncryption.acknowledgeUnencrypted = lib.mkForce true;
  };
}
