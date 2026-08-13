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

    systemd.services.nas-managed-services-reconcile.environment = lib.mkIf cfg.networking.enable (
      {
        NAS_V2_NMCLI_BIN = "${pkgs.networkmanager}/bin/nmcli";
        NAS_V2_INSTALL_BIN = "${pkgs.coreutils}/bin/install";
        NAS_V2_RM_BIN = "${pkgs.coreutils}/bin/rm";
      }
      // lib.optionalAttrs (vlanParent != null) {
        NAS_V2_VLAN_PARENT = vlanParent;
      }
    );
  };
}
