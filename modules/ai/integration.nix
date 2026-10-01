{ config, lib, pkgs, aiInternal, ... }:

let
  inherit (aiInternal)
    cfg
    llamaCppPackage
    nasAiConfig
  ;
in
{
  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ pkgs.llama-swap llamaCppPackage nasAiConfig ];
  };
}
