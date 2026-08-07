{ config, lib, pkgs, aiInternal, ... }:

let
  inherit (aiInternal)
    cfg
    llamaCppPackage
  ;
in
{
  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ pkgs.llama-swap llamaCppPackage ];
  };
}
