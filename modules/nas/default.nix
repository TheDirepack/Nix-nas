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
    ./config/reverse-proxy.nix
    ./config/observability.nix
    ./config/storage-monitoring.nix
    ./config/systemd-services.nix
    ./config/schedules.nix
    ./config/system.nix
  ];

  _module.args.nasInternal = import ./internal { inherit config lib pkgs; };
}
