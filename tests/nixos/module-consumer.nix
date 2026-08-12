{ config, lib, pkgs, ... }:

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
    networking.applicationVlanParent = "eth0";
  };

  assertions = [
    {
      assertion =
        config.systemd.services.nas-managed-services-reconcile.environment.NAS_V2_VLAN_PARENT == "eth0";
      message = "Managed Services V2 must project the configured application VLAN trunk into its finite reconcile environment.";
    }
    {
      assertion =
        config.systemd.services.nas-managed-services-reconcile.environment.NAS_V2_NMCLI_BIN
        == "${pkgs.networkmanager}/bin/nmcli";
      message = "Managed Services V2 must use the pinned NetworkManager nmcli binary for VLAN projection.";
    }
    {
      assertion =
        config.systemd.services.nas-managed-services-reconcile.environment.NAS_V2_INSTALL_BIN
        == "${pkgs.coreutils}/bin/install";
      message = "Managed Services V2 must use the pinned coreutils install binary for VLAN projection.";
    }
  ];
}
