{ config, lib, pkgs, ... }:

let
  reconcileEnvironment = config.systemd.services.nas-managed-services-reconcile.environment;
in
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
        !config.nas.networking.enable
        || lib.attrByPath [ "NAS_V2_VLAN_PARENT" ] null reconcileEnvironment == "eth0";
      message = "Managed Services V2 must project the configured application VLAN trunk into its finite reconcile environment.";
    }
    {
      assertion =
        !config.nas.networking.enable
        || lib.attrByPath [ "NAS_V2_NMSTATECTL_BIN" ] null reconcileEnvironment == "${pkgs.nmstate}/bin/nmstatectl";
      message = "Managed Services V2 must use the pinned nmstatectl binary for VLAN projection.";
    }
    {
      assertion = config.systemd.services.copyparty.wantedBy == [ ];
      message = "CopyParty must not retain a static NixOS boot target while Managed Services V2 owns its lifecycle.";
    }
    {
      assertion = !lib.elem "copyparty.service" config.systemd.services.caddy.wants;
      message = "Caddy must not bypass Managed Services V2 by statically starting the CopyParty application backend.";
    }
    {
      assertion = !lib.elem "copyparty.service" config.systemd.targets.nas-protected-services.requires;
      message = "Secret activation must not bypass Managed Services V2 by statically starting CopyParty.";
    }
    {
      assertion = !lib.elem "nas-identity-sync.service" config.systemd.targets.nas-protected-services.requires;
      message = "Secret activation must not bypass the Managed Services V2 identity-sync job lifecycle.";
    }
    {
      assertion = config.systemd.services.nas-managed-services-authentik-reconcile.requires == [ "authentik.service" "nas-identity-bootstrap.service" ];
      message = "The Authentik capability projection must wait for the first-boot identity bootstrap without starting the V2-managed identity-sync job.";
    }
    {
      assertion =
        !lib.elem "nas-identity-sync.service" config.systemd.services.nas-managed-services-authentik-reconcile.after;
        message = "The Authentik capability projection must not retain a hidden ordering dependency on identity-sync.";
    }
    {
      assertion = lib.elem "nas-identity-bootstrap.service" config.systemd.services.nas-managed-services-authentik-reconcile.after;
      message = "The Authentik capability projection must run after the first-boot identity bootstrap.";
    }
  ];
}
