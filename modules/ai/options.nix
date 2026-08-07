{ lib, ... }:

{
  options.nas.ai = {
    enable = lib.mkEnableOption "authenticated local-AI control plane";

    storageRoot = lib.mkOption {
      type = lib.types.str;
      default = "";
      description = "AI storage root. Empty selects <nas.zfsRoot>/ai.";
    };

    serviceUid = lib.mkOption {
      type = lib.types.int;
      default = 952;
      description = "Static UID for llama-swap.";
    };

    downloaderUid = lib.mkOption {
      type = lib.types.int;
      default = 951;
      description = "Static UID/GID for the rootless Hugging Face downloader container.";
    };

    modelGroupGid = lib.mkOption {
      type = lib.types.int;
      default = 953;
      description = "Shared group ID granting inference services read access to downloaded models.";
    };

    llamaSwap = {
      port = lib.mkOption {
        type = lib.types.port;
        default = 9292;
        description = "Loopback port for the llama-swap API and runtime interface.";
      };
      globalTtl = lib.mkOption {
        type = lib.types.ints.between 0 604800;
        default = 300;
        description = "Default number of idle seconds before llama-swap unloads a backend; zero disables unloading.";
      };
    };

    openWebuiPort = lib.mkOption {
      type = lib.types.port;
      default = 9380;
      description = "Loopback port for Open WebUI.";
    };

    codingAgent = {
      enable = lib.mkEnableOption "sandboxed Pi coding-agent sessions routed through llama-swap";

      serviceUid = lib.mkOption {
        type = lib.types.int;
        default = 954;
        description = "Static UID/GID for the isolated nas-code-agent service identity.";
      };

      workspaceRoots = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ "/srv/code" ];
        description = "Absolute directory roots within which Pi coding sessions may operate.";
      };

      modelRoles = {
        default = lib.mkOption { type = lib.types.str; default = "coding/default"; };
        cheap = lib.mkOption { type = lib.types.str; default = "coding/cheap"; };
        planner = lib.mkOption { type = lib.types.str; default = "coding/planner"; };
        reviewer = lib.mkOption { type = lib.types.str; default = "coding/reviewer"; };
        research = lib.mkOption { type = lib.types.str; default = "coding/research"; };
        localWorker = lib.mkOption { type = lib.types.str; default = "coding/local-worker"; };
      };

      contextWindow = lib.mkOption {
        type = lib.types.ints.between 4096 1048576;
        default = 131072;
        description = "Context-window metadata advertised to Pi for llama-swap coding role aliases.";
      };

      maxTokens = lib.mkOption {
        type = lib.types.ints.between 1024 131072;
        default = 16384;
        description = "Maximum output-token metadata advertised to Pi for coding role aliases.";
      };

      idleSeconds = lib.mkOption {
        type = lib.types.ints.between 60 86400;
        default = 600;
        description = "Idle time before the aiCoding feature may be reaped after sessions stop heartbeating.";
      };

      heartbeatSeconds = lib.mkOption {
        type = lib.types.ints.between 30 3600;
        default = 120;
        description = "Interval at which an active transient coding session refreshes aiCoding runtime activity.";
      };

      tools = {
        web.enable = lib.mkEnableOption "the pinned pi-web-access extension once packaged";
        context7.enable = lib.mkEnableOption "the pinned Context7 Pi extension once packaged";
        lsp.enable = lib.mkEnableOption "the pinned pi-lsp extension once packaged";
        browser.enable = lib.mkEnableOption "lazy browser automation for coding sessions";
      };
    };

    modelDownloader = {
      enable = lib.mkEnableOption "administrator-only Hugging Face Model Downloader web service";
      port = lib.mkOption {
        type = lib.types.port;
        default = 9381;
        description = "Loopback port for HuggingFaceModelDownloader.";
      };
    };
  };
}
