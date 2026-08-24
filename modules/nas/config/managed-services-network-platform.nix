{ config, lib, pkgs, ... }:

let
  cfg = config.nas;
  vlanParent = cfg.networking.applicationVlanParent;
in
{
  config = {
    assertions = [
      {
        assertion = vlanParent == null || cfg.networking.enable;
        message = "nas.networking.applicationVlanParent requires nas.networking.enable so NetworkManager can own the 802.1Q trunk.";
      }
    ];

    # nmstate is now the sole V2 adapter for host VLAN/VRF topology. It talks
    # to NetworkManager through its native provider and performs its own
    # verify/rollback transaction. Podman bridge networks remain Quadlet-owned.
    systemd.services.nas-managed-services-reconcile.environment = lib.mkIf cfg.networking.enable (
      {
        NAS_V2_NMSTATECTL_BIN = "${pkgs.nmstate}/bin/nmstatectl";
      }
      // lib.optionalAttrs (vlanParent != null) {
        NAS_V2_VLAN_PARENT = vlanParent;
      }
    );
  };
}
