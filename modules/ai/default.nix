{ config, lib, pkgs, ... }:

{
  imports = [
    ./options.nix
    ./validation-identities.nix
    ./open-webui.nix
    ./downloader.nix
    ./services.nix
    ./coding-agent.nix
    ./coding-agent-network-security.nix
    ./integration.nix
  ];

  _module.args.aiInternal = import ./internal.nix { inherit config lib pkgs; };
}
