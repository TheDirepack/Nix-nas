{ config, lib, nasInternal, ... }:

let
  inherit (nasInternal) cfg authentikDataDir;
in
{
  config = {
    # First-run creates the operator-selected local administrator. Nix must not
    # recreate or overwrite that mutable identity on later activations.
    users.mutableUsers = true;
    users.groups.authentik = { };
    users.groups.nas-administrators = { };
    users.groups.nas-operations = { };
    users.users.authentik = {
      isSystemUser = true;
      group = "authentik";
      home = authentikDataDir;
      createHome = true;
      homeMode = "0750";
    };
  };
}
