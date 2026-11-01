{ lib, ... }:

{
  users.users.admin.extraGroups = [ "nas-administrators" ];
  services.openssh.settings.AllowGroups = lib.mkForce [ "operators" ];

  nas = {
    installationReady = lib.mkForce true;
    testing.installationReadyFixture = true;
    trustedInterfaces = lib.mkForce [ "eth0" ];
    zfsEncryption.acknowledgeUnencrypted = lib.mkForce true;
  };
}
