{ config, lib, pkgs, ... }:

{
  imports = [
    ./options/core.nix
    ./options/hardware.nix
    ./options/storage.nix
    ./options/applications.nix
    ./options/power.nix
    ./options/virtualization.nix
    ./options/operations.nix
    ./options/management.nix
    ./config/validation.nix
    ./config/network-firewall.nix
    ./config/host-platform.nix
    ./config/virtualization.nix
    ./config/identities.nix
    ./config/application-services.nix
    ./config/bootstrap-security.nix
    ./config/password-security.nix
    ./config/reverse-proxy.nix
    ./config/caddy-bootstrap.nix
    ./config/observability.nix
    ./config/storage-monitoring.nix
    ./config/backup-domains.nix
    ./config/systemd-services.nix
    ./config/schedules.nix
    ./config/system.nix
    ./config/managed-services.nix
    ./config/managed-services-transactions.nix
    ./config/managed-services-lifecycle.nix
    ./config/managed-services-generations.nix
    ./config/managed-services-backup-profile.nix
    ./config/managed-services-network-platform.nix
    ./config/managed-services-authentik-blueprint.nix
    ./config/managed-services-compose-import.nix
    ./config/managed-services-seed-v2.nix
  ];

  _module.args.nasInternal = import ./internal { inherit config lib pkgs; };
}
