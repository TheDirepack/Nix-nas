{ config, lib, pkgs }:

let
  cfg = config.nas.ai;
  nas = config.nas;
  lanHost = "${config.networking.hostName}.local";
  secretRoot = "/run/nas-secret-runtime/live";
  aiSecretDir = "${secretRoot}/ai";
  imagePin = import ../../hfdownloader-image.nix;
  hostSystem = pkgs.stdenv.hostPlatform.system;
  digestKey = builtins.replaceStrings [ "-" ] [ "_" ] hostSystem;
  downloaderDigest = imagePin.digests.${digestKey} or "";
  missingDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
  downloaderImage = "${imagePin.repository}@${if downloaderDigest != "" then downloaderDigest else missingDigest}";
  aiRoot = if cfg.storageRoot != "" then cfg.storageRoot else "${nas.zfsRoot}/ai";
  hfRoot = "${aiRoot}/huggingface";
  backendCache = "${aiRoot}/backend-cache";
  stateDir = "/var/lib/nas-llama-swap";
  legacyStateDir = "/var/lib/nas-ai-manager";
  legacyDefaultConfig = pkgs.writeText "nas-llama-swap-alpha4-default.yaml" ''
    healthCheckTimeout: 300
    logLevel: info
    apiKeys:
      - "''${env.LLAMA_SWAP_API_KEY}"
    models: {}
  '';
  defaultConfig = pkgs.writeText "nas-llama-swap-default.yaml" ''
    healthCheckTimeout: 300
    globalTTL: ${toString cfg.llamaSwap.globalTtl}
    unloadTimeout: 10
    logLevel: info
    apiKeys:
      - "''${env.LLAMA_SWAP_API_KEY}"
    ${lib.optionalString cfg.codingAgent.enable ''  - "''${env.LLAMA_SWAP_CODING_API_KEY}"''}
    models: {}
  '';
  llamaBackend = nas.hardware.llamaCpp.backend;
  llamaCppPackage =
    if llamaBackend == "cuda" then
      pkgs.llama-cpp.override { cudaSupport = true; }
    else if llamaBackend == "rocm" then
      pkgs.llama-cpp.override { rocmSupport = true; }
    else if llamaBackend == "vulkan" then
      pkgs.llama-cpp.override { vulkanSupport = true; }
    else
      pkgs.llama-cpp;
  protectedUnits = [
    "nas-ai-storage.service"
    "nas-ai-config-init.service"
    "nas-llama-swap.service"
    "open-webui.service"
  ]
  ++ lib.optional cfg.modelDownloader.enable "podman-hfdownloader.service"
  ++ lib.optional cfg.codingAgent.enable "nas-ai-coding-prepare.service";
  uidCollisions = lib.attrNames (lib.filterAttrs
    (name: user:
      !(lib.elem name [ "nas-ai" "hfdownloader" "nas-code-agent" ])
      && lib.elem (user.uid or null) [ cfg.serviceUid cfg.downloaderUid cfg.codingAgent.serviceUid ])
    config.users.users);
  gidCollisions = lib.attrNames (lib.filterAttrs
    (name: group:
      !(lib.elem name [ "nas-ai" "hfdownloader" "nas-ai-models" "nas-code-agent" ])
      && lib.elem (group.gid or null) [ cfg.serviceUid cfg.downloaderUid cfg.modelGroupGid cfg.codingAgent.serviceUid ])
    config.users.groups);
in
{
  inherit
    cfg
    nas
    lanHost
    secretRoot
    aiSecretDir
    imagePin
    hostSystem
    digestKey
    downloaderDigest
    missingDigest
    downloaderImage
    aiRoot
    hfRoot
    backendCache
    stateDir
    legacyStateDir
    legacyDefaultConfig
    defaultConfig
    llamaBackend
    llamaCppPackage
    protectedUnits
    uidCollisions
    gidCollisions
  ;
}
