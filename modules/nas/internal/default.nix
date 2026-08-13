{ config, lib, pkgs }:

let
  common = { inherit config lib pkgs; };

  mergeChecked = label: left: right:
    let
      duplicates = lib.intersectLists (lib.attrNames left) (lib.attrNames right);
    in
      if duplicates != [ ] then
        throw "NAS internal export collision while merging ${label}: ${lib.concatStringsSep ", " duplicates}"
      else
        left // right;

  base = import ./base.nix common;
  caddy_helpers = import ./caddy-helpers.nix (common // base);
  core = mergeChecked "base and Caddy helpers" base caddy_helpers;

  secret_tools = import ./secret-tools.nix (common // core);
  with_secrets = mergeChecked "core and secret tools" core secret_tools;
  zfs_tools = import ./zfs-tools.nix (common // with_secrets);
  with_zfs = mergeChecked "secret and ZFS tools" with_secrets zfs_tools;
  power_tools = import ./power-tools.nix (common // with_zfs);
  with_power = mergeChecked "ZFS and power tools" with_zfs power_tools;
  maintenance_tools = import ./maintenance-tools.nix (common // with_power);
  with_maintenance = mergeChecked "power and maintenance tools" with_power maintenance_tools;
  account_tools = import ./account-tools.nix (common // with_maintenance);
  with_accounts = mergeChecked "maintenance and account tools" with_maintenance account_tools;
  documentation_tools = import ./documentation-tools.nix (common // with_accounts);
  with_documentation = mergeChecked "account and documentation tools" with_accounts documentation_tools;
  share_firewall = import ./share-firewall.nix (common // with_documentation);
in
  mergeChecked "documentation and share/firewall tools" with_documentation share_firewall
