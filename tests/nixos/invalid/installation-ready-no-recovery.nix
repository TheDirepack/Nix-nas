{ lib, pkgs, ... }:

{
  users.users.admin.openssh.authorizedKeys.keys = lib.mkForce [ ];

  nas = {
    installationReady = lib.mkForce true;
    testing.installationReadyFixture = true;
    trustedInterfaces = lib.mkForce [ "eth0" ];
    zfsEncryption.acknowledgeUnencrypted = lib.mkForce true;
  };
}
