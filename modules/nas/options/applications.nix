{ lib, ... }:

{
  options.nas = {
    syncthing = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Enable Syncthing with an admin-only MFA-protected web interface and LAN-scoped transfer/discovery ports.";
      };
      internetDiscovery = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Allow Syncthing global discovery, relays, and NAT traversal. Keep false for LAN-only synchronization.";
      };
    };
    vaultwarden = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Enable the native NixOS Vaultwarden service at /vault with per-account Authentik OIDC and an MFA-protected admin route.";
      };
      ssoOnly = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Require Vaultwarden user logins to use Authentik OIDC. Disable only for temporary compatibility with clients that cannot complete the SSO flow.";
      };
    };
    tftp = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Enable CopyParty's anonymous LAN-restricted TFTP endpoint. Disabled by default.";
      };
      writable = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Permit unauthenticated TFTP uploads through the dedicated CopyParty volume. The underlying directory remains owned by the CopyParty service.";
      };
      port = lib.mkOption {
        type = lib.types.port;
        default = 69;
        description = "External UDP port presented to TFTP clients.";
      };
      internalPort = lib.mkOption {
        type = lib.types.port;
        default = 3969;
        description = "Unprivileged UDP port on which the CopyParty process listens for TFTP.";
      };
      responsePortStart = lib.mkOption {
        type = lib.types.port;
        default = 40000;
        description = "First CopyParty TFTP response port allowed through the firewall.";
      };
      responsePortEnd = lib.mkOption {
        type = lib.types.port;
        default = 40099;
        description = "Last CopyParty TFTP response port allowed through the firewall.";
      };
    };
  };
}
