{ config, lib, pkgs, aiInternal, ... }:

let
  inherit (aiInternal)
    cfg
    downloaderDigest
    gidCollisions
    hostSystem
    nas
    stateDir
    uidCollisions
  ;
in
{
  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = hostSystem == "x86_64-linux";
        message = "nas.ai is supported on x86_64-linux in this release.";
      }
      {
        assertion = uidCollisions == [ ];
        message = "nas.ai static UID collision(s): ${lib.concatStringsSep ", " uidCollisions}";
      }
      {
        assertion = gidCollisions == [ ];
        message = "nas.ai static GID collision(s): ${lib.concatStringsSep ", " gidCollisions}";
      }
      {
        assertion = !cfg.modelDownloader.enable || downloaderDigest != "";
        message = "nas.ai.modelDownloader requires an immutable ${hostSystem} digest in hfdownloader-image.nix. Renovate should maintain this pin through reviewed pull requests.";
      }
      {
        assertion = lib.length (lib.unique [ cfg.llamaSwap.port cfg.openWebuiPort cfg.modelDownloader.port ]) == 3;
        message = "All nas.ai loopback ports must be unique.";
      }
      {
        assertion = nas.hardware.llamaCpp.enable;
        message = "nas.ai requires nas.hardware.llamaCpp.enable so local GGUF models have a llama-server backend.";
      }
      {
        assertion = !cfg.codingAgent.enable || cfg.codingAgent.workspaceRoots != [ ];
        message = "nas.ai.codingAgent.workspaceRoots must contain at least one approved absolute directory.";
      }
      {
        assertion = !cfg.codingAgent.enable || lib.all (root: lib.hasPrefix "/" root && root != "/") cfg.codingAgent.workspaceRoots;
        message = "nas.ai.codingAgent.workspaceRoots must be absolute and may not include the filesystem root.";
      }
      {
        assertion = !cfg.codingAgent.enable || cfg.codingAgent.heartbeatSeconds < cfg.codingAgent.idleSeconds;
        message = "nas.ai.codingAgent.heartbeatSeconds must be shorter than idleSeconds.";
      }
      {
        assertion = !(cfg.codingAgent.tools.web.enable || cfg.codingAgent.tools.context7.enable || cfg.codingAgent.tools.lsp.enable || cfg.codingAgent.tools.browser.enable);
        message = "Alpha.5 exposes Pi extension policy but does not enable extension packages until their Nix dependency closures are pinned and qualified.";
      }
    ];

    users.groups = {
      nas-ai.gid = cfg.serviceUid;
      hfdownloader.gid = cfg.downloaderUid;
      nas-ai-models.gid = cfg.modelGroupGid;
      nas-code-agent = lib.mkIf cfg.codingAgent.enable { gid = cfg.codingAgent.serviceUid; };
    };

    users.users = {
      nas-ai = {
        isSystemUser = true;
        uid = cfg.serviceUid;
        group = "nas-ai";
        extraGroups = [ "nas-ai-models" "render" "video" ];
        home = stateDir;
        createHome = false;
      };
      nas-code-agent = lib.mkIf cfg.codingAgent.enable {
        isSystemUser = true;
        uid = cfg.codingAgent.serviceUid;
        group = "nas-code-agent";
        home = "/var/lib/nas-code-agent";
        createHome = false;
      };
      hfdownloader = {
        isSystemUser = true;
        uid = cfg.downloaderUid;
        group = "hfdownloader";
        extraGroups = [ "nas-ai-models" ];
        home = "/var/lib/hfdownloader";
        createHome = true;
        linger = true;
        subUidRanges = [ { startUid = 310000; count = 65536; } ];
        subGidRanges = [ { startGid = 310000; count = 65536; } ];
      };
    };

  };
}
