{ config, ... }:

let
  cfg = config.nas;
  mkService = {
    serviceId,
    label,
    description ? null,
    enabled,
    units,
    port ? null,
    publicPath ? null,
    access ? "admin",
    linkKey ? null,
    category ? "Other",
    icon ? null,
    lifecycleMode ? "persistent",
    idleSeconds ? null,
    ownership ? "v2",
    expose ? true,
    dependsOn ? [ ],
  }:
    let
      authMode = if access == "public" then "public" else "forward-auth";
      authAllow = if access == "admin" then "groups" else if access == "ai" then "groups" else if access == "vault" then "groups" else "any";
      authGroups = if access == "admin" then [ "nas_admin" ] else if access == "ai" then [ "nas_allow_ai" "nas_admin" ] else if access == "vault" then [ "nas_allow_vault" "nas_admin" ] else [ ];
      authCapability = if access == "admin" || access == "ai" || access == "vault" then "application.${serviceId}.access" else null;
      portalCategory = if linkKey == "identity" then "Administration" else if linkKey == "console" then "Administration" else if linkKey == "aiWorkspace" then "AI" else if linkKey == "syncthing" then "Files" else category;
      portalIcon = if icon != null then icon else if linkKey != null then linkKey else "box";
      lifecycle = { mode = lifecycleMode; } // (if lifecycleMode == "on-demand" then { inherit idleSeconds; } else { });
      startPolicy = if !enabled then "disabled" else if lifecycleMode == "persistent" then "boot" else if lifecycleMode == "on-demand" then "on-demand" else "manual";
      endpoint = {
        main = {
          transport = "http";
          targetPort = port;
          exposure = {
            type = "path";
            value = publicPath;
            prefix = true;
          };
          auth = {
            mode = authMode;
          }
          // (if authCapability != null then { capability = authCapability; } else { })
          // (if authGroups != [ ] then { allow = authAllow; groups = authGroups; } else if authMode == "public" then { } else { allow = "any"; });
          portal = {
            visible = linkKey != null;
            category = portalCategory;
            icon = portalIcon;
          };
        };
      };
    in
    {
      inherit label enabled ownership lifecycle dependsOn;
      runtime = {
        type = "systemd";
        source = "systemd/${builtins.head units}";
        inherit startPolicy units;
      };
      endpoints = if expose then endpoint else { };
    } // (if description != null then { inherit description; } else { });

  aiRuntimeBase = mkService {
    serviceId = "aiRuntime";
    label = "llama-swap runtime";
    enabled = cfg.ai.enable;
    units = [ "nas-llama-swap.service" ];
    port = cfg.ai.llamaSwap.port;
    publicPath = "/ai/runtime/";
    access = "admin";
    linkKey = "aiRuntime";
    category = "AI";
    lifecycleMode = "on-demand";
    idleSeconds = 600;
  };

  registry = {
    # Recovery/control-plane substrates are visible to the dependency graph but
    # V2 never owns their shutdown lifecycle.
    identity = mkService {
      serviceId = "identity";
      label = "Authentik identity";
      enabled = true;
      units = [ "authentik.service" "authentik-worker.service" ];
      port = 9000;
      publicPath = cfg.identity.authentikPath;
      access = "public";
      linkKey = "identity";
      category = "Administration";
      lifecycleMode = "persistent";
      ownership = "system";
    };
    cockpit = mkService {
      serviceId = "cockpit";
      label = "Cockpit management";
      enabled = true;
      units = [ "cockpit.socket" ];
      port = 9092;
      publicPath = "/console/";
      access = "admin";
      linkKey = "console";
      category = "Administration";
      lifecycleMode = "persistent";
      ownership = "system";
    };
    caddy = mkService {
      serviceId = "caddy";
      label = "Caddy ingress";
      enabled = true;
      units = [ "caddy.service" ];
      lifecycleMode = "persistent";
      ownership = "system";
      expose = false;
    };

    copyparty = mkService {
      serviceId = "copyparty";
      label = "CopyParty files";
      enabled = true;
      units = [ "copyparty.service" ];
      lifecycleMode = "persistent";
      expose = false;
    };

    aiRuntime = aiRuntimeBase // {
      endpoints = aiRuntimeBase.endpoints // {
        api = {
          transport = "http";
          targetPort = cfg.ai.llamaSwap.port;
          exposure = {
            type = "path";
            value = "/ai/v1/";
            prefix = true;
          };
          auth = {
            mode = "forward-auth";
            capability = "application.aiRuntime.access";
            allow = "groups";
            groups = [ "nas_allow_ai" "nas_admin" ];
          };
          portal = {
            visible = false;
            category = "AI";
            icon = "api";
          };
        };
      };
    };
    aiWorkspace = mkService {
      serviceId = "aiWorkspace";
      label = "Open WebUI";
      enabled = cfg.ai.enable;
      units = [ "open-webui.service" ];
      port = cfg.ai.openWebuiPort;
      publicPath = "/ai/";
      access = "ai";
      linkKey = "aiWorkspace";
      category = "AI";
      lifecycleMode = "on-demand";
      idleSeconds = 600;
      dependsOn = [ "aiRuntime" ];
    };
    aiDownloader = mkService {
      serviceId = "aiDownloader";
      label = "Hugging Face model downloader";
      enabled = cfg.ai.enable && cfg.ai.modelDownloader.enable;
      units = [ "podman-hfdownloader.service" ];
      port = cfg.ai.modelDownloader.port;
      publicPath = "/ai/models/";
      access = "admin";
      linkKey = "aiModels";
      category = "AI";
      lifecycleMode = "on-demand";
      idleSeconds = 600;
    };
    syncthing = mkService {
      serviceId = "syncthing";
      label = "Syncthing";
      enabled = cfg.syncthing.enable;
      units = [ "syncthing.service" "nas-syncthing-sync.timer" ];
      port = 8384;
      publicPath = "/syncthing/";
      access = "admin";
      linkKey = "syncthing";
      category = "Files";
      lifecycleMode = "persistent";
      dependsOn = [ "identity" ];
    };
    vaultwardenCa = mkService {
      serviceId = "vaultwardenCa";
      label = "Vaultwarden CA preparation";
      enabled = cfg.vaultwarden.enable;
      units = [ "nas-caddy-ca-export.service" ];
      lifecycleMode = "persistent";
      expose = false;
      dependsOn = [ "caddy" ];
    };
    vaultwarden = mkService {
      serviceId = "vaultwarden";
      label = "Vaultwarden";
      enabled = cfg.vaultwarden.enable;
      units = [ "vaultwarden.service" ];
      port = 8222;
      publicPath = "/vault/";
      access = "vault";
      linkKey = "vaultwarden";
      category = "Home";
      lifecycleMode = "persistent";
      dependsOn = [ "identity" "vaultwardenCa" ];
    };
    victoriametrics = mkService {
      serviceId = "victoriametrics";
      label = "VictoriaMetrics";
      enabled = cfg.observability.enable;
      units = [ "victoriametrics.service" ];
      port = cfg.observability.victoriaMetricsPort;
      publicPath = "/victoriametrics/";
      access = "admin";
      linkKey = "victoriaMetrics";
      category = "Monitoring";
      lifecycleMode = "persistent";
    };
    telegraf = mkService {
      serviceId = "telegraf";
      label = "Telegraf metrics collector";
      enabled = cfg.observability.enable;
      units = [ "telegraf.service" ];
      lifecycleMode = "persistent";
      expose = false;
      dependsOn = [ "victoriametrics" ];
    };
    grafana = mkService {
      serviceId = "grafana";
      label = "Grafana";
      enabled = cfg.observability.enable && cfg.observability.grafana.enable;
      units = [ "grafana.service" ];
      port = cfg.observability.grafana.port;
      publicPath = "/metrics/";
      access = "admin";
      linkKey = "metrics";
      category = "Monitoring";
      lifecycleMode = "on-demand";
      idleSeconds = 600;
      dependsOn = [ "victoriametrics" ];
    };
    alerts = mkService {
      serviceId = "alerts";
      label = "Alert status";
      enabled = cfg.observability.enable && cfg.alerting.enable;
      units = [ "nas-alert-router.service" "vmalert-nas.service" ];
      port = cfg.observability.alertRouterPort;
      publicPath = "/alerts/";
      access = "admin";
      linkKey = "alerts";
      category = "Monitoring";
      lifecycleMode = "persistent";
      dependsOn = [ "victoriametrics" ];
    };
    notifications = mkService {
      serviceId = "notifications";
      label = "ntfy notifications";
      enabled = cfg.observability.ntfy.enable;
      units = [ "ntfy-sh.service" ];
      port = cfg.observability.ntfy.port;
      publicPath = "/notifications/";
      access = "native";
      linkKey = "notifications";
      category = "Monitoring";
      lifecycleMode = "persistent";
    };
    ups = mkService {
      serviceId = "ups";
      label = "NUT web interface";
      enabled = cfg.power.ups.enable && cfg.power.ups.web.enable;
      units = [ "podman-nut-webgui.service" ];
      port = cfg.power.ups.web.port;
      publicPath = "/ups/";
      access = "admin";
      linkKey = "ups";
      category = "Monitoring";
      lifecycleMode = "on-demand";
      idleSeconds = 600;
    };
  };

  storageResources = {
    nas-shares = {
      path = "${cfg.zfsRoot}/shares";
      dataset = cfg.zfsDataset;
      scope = "system";
      stateClass = "authoritative";
      capabilities = [ "read" "write" "move" "delete" "admin" ];
      backup = {
        enabled = cfg.backup.includeShares;
        consistency = "zfs-snapshot";
      };
      fileBrowser.visible = false;
      description = "Managed NAS share tree";
    };
    nas-control-state = {
      path = "/var/lib/nas-control";
      scope = "system";
      stateClass = "authoritative";
      capabilities = [ "admin" ];
      backup = {
        enabled = cfg.backup.enable;
        consistency = "filesystem";
      };
      fileBrowser.visible = false;
      description = "Managed Services V2 definitions and appliance control state";
    };
    copyparty-config = {
      path = "/var/lib/copyparty/user.d";
      scope = "system";
      stateClass = "authoritative";
      capabilities = [ "admin" ];
      backup = {
        enabled = cfg.backup.enable;
        consistency = "filesystem";
      };
      fileBrowser.visible = false;
      description = "CopyParty native administrator configuration";
    };
    authentik-files = {
      path = "/var/lib/authentik";
      scope = "system";
      stateClass = "authoritative";
      capabilities = [ "admin" ];
      backup = {
        enabled = cfg.backup.enable;
        consistency = "filesystem";
      };
      fileBrowser.visible = false;
      description = "Authentik file-backed state; PostgreSQL remains native-dump managed";
    };
    setup-state = {
      path = "/var/lib/nas-setup";
      scope = "system";
      stateClass = "authoritative";
      capabilities = [ "admin" ];
      backup = {
        enabled = cfg.backup.enable;
        consistency = "filesystem";
      };
      fileBrowser.visible = false;
      description = "First-start completion and recovery state";
    };
    identity-projection-state = {
      path = "/var/lib/nas-identity-sync";
      scope = "system";
      stateClass = "derived";
      capabilities = [ "admin" ];
      backup = {
        enabled = false;
        consistency = "filesystem";
      };
      fileBrowser.visible = false;
      description = "Reconstructable identity projection state derived from Authentik";
    };
  };
in
{
  serviceRegistry = registry;
  serviceRegistryV2 = {
    schemaVersion = 2;
    generation = 3;
    inherit storageResources;
    services = registry;
  };
}
