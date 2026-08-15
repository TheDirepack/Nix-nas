{ lib, config }:
let
  cfg = config.nas;
in
{
  syncthingGuiPort = 8384;
  syncthingSyncPort = 22000;
  syncthingDiscoveryPort = 21027;
  vaultwardenPort = 8222;
  nutUpsdPort = cfg.power.ups.web.upsdPort;
}
