{ config, ... }:

let
  cfg = config.nas;
  mkService = { label, description ? null, enabled, units, port, publicPath, access, linkKey, category ? "Other", icon ? null }:
    let
      authMode = if access == "public" then "public" else "forward-auth";
      authAllow = if access == "admin" then "groups" else if access == "ai" then "groups" else if access == "vault" then "groups" else "any";
      authGroups = if access == "admin" then ["nas_admin"] else if access == "ai" then ["nas_allow_ai" "nas_admin"] else if access == "vault" then ["nas_allow_vault" "nas_admin"] else if access == "api-key" then [] else [];
      portalCategory = if linkKey == "identity" then "Administration" else if linkKey == "console" then "Administration" else if linkKey == "aiWorkspace" then "AI" else if linkKey == "syncthing" then "Files" else category;
      portalIcon = if icon != null then icon else if linkKey != null then linkKey else "box";
    in {
      label = label;
      enabled = enabled;
      ownership = "system";
      runtime = {
        type = "systemd";
        source = "systemd/${builtins.head units}";
        startPolicy = "boot";
        units = units;
      };
      endpoints = {
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
          } // (if authGroups != [] then { allow = authAllow; groups = authGroups; } else if authMode == "public" then {} else { allow = "any"; });
          portal = {
            visible = linkKey != null;
            category = portalCategory;
            icon = portalIcon;
          } // (if linkKey != null then { inherit linkKey; } else {});
          inherit linkKey;
          available = enabled;
        };
      };
    } // (if description != null then { description = description; } else {});
  registry = {
    identity = mkService {
      label = "Authentik identity";
      enabled = true;
      units = [ "authentik.service" "authentik-worker.service" ];
      port = 9000;
      publicPath = cfg.identity.authentikPath;
      access = "public";
      linkKey = "identity";
      category = "Administration";
    };
    cockpit = mkService {
      label = "Cockpit management";
      enabled = true;
      units = [ "cockpit.socket" ];
      port = 9092;
      publicPath = "/console/";
      access = "admin";
      linkKey = "console";
      category = "Administration";
    };
    aiApi = mkService {
      label = "llama-swap API";
      enabled = cfg.ai.enable;
      units = [ "nas-llama-swap.service" ];
      port = cfg.ai.llamaSwap.port;
      publicPath = "/ai/v1/";
      access = "api-key";
      linkKey = null;
      category = "AI";
    };
    aiRuntime = mkService {
      label = "llama-swap runtime UI";
      enabled = cfg.ai.enable;
      units = [ "nas-llama-swap.service" ];
      port = cfg.ai.llamaSwap.port;
      publicPath = "/ai/runtime/";
      access = "admin";
      linkKey = "aiRuntime";
      category = "AI";
    };
    aiWorkspace = mkService {
      label = "Open WebUI";
      enabled = cfg.ai.enable;
      units = [ "open-webui.service" ];
      port = cfg.ai.openWebuiPort;
      publicPath = "/ai/";
      access = "ai";
      linkKey = "aiWorkspace";
      category = "AI";
    };
    aiDownloader = mkService {
      label = "Hugging Face model downloader";
      enabled = cfg.ai.enable && cfg.ai.modelDownloader.enable;
      units = [ "podman-hfdownloader.service" ];
      port = cfg.ai.modelDownloader.port;
      publicPath = "/ai/models/";
      access = "admin";
      linkKey = "aiModels";
      category = "AI";
    };
    syncthing = mkService {
      label = "Syncthing administration";
      enabled = cfg.syncthing.enable;
      units = [ "syncthing.service" ];
      port = 8384;
      publicPath = "/syncthing/";
      access = "admin";
      linkKey = "syncthing";
      category = "Files";
    };
    vaultwarden = mkService {
      label = "Vaultwarden";
      enabled = cfg.vaultwarden.enable;
      units = [ "vaultwarden.service" ];
      port = 8222;
      publicPath = "/vault/";
      access = "vault";
      linkKey = "vaultwarden";
      category = "Home";
    };
    victoriametrics = mkService {
      label = "VictoriaMetrics";
      enabled = cfg.observability.enable;
      units = [ "victoriametrics.service" ];
      port = cfg.observability.victoriaMetricsPort;
      publicPath = "/victoriametrics/";
      access = "admin";
      linkKey = "victoriaMetrics";
      category = "Monitoring";
    };
    grafana = mkService {
      label = "Grafana";
      enabled = cfg.observability.enable && cfg.observability.grafana.enable;
      units = [ "grafana.service" ];
      port = cfg.observability.grafana.port;
      publicPath = "/metrics/";
      access = "admin";
      linkKey = "metrics";
      category = "Monitoring";
    };
    alerts = mkService {
      label = "Alert status";
      enabled = cfg.observability.enable && cfg.alerting.enable;
      units = [ "nas-alert-router.service" "vmalert-nas.service" ];
      port = cfg.observability.alertRouterPort;
      publicPath = "/alerts/";
      access = "admin";
      linkKey = "alerts";
      category = "Monitoring";
    };
    notifications = mkService {
      label = "ntfy notifications";
      enabled = cfg.observability.ntfy.enable;
      units = [ "ntfy-sh.service" ];
      port = cfg.observability.ntfy.port;
      publicPath = "/notifications/";
      access = "native";
      linkKey = "notifications";
      category = "Monitoring";
    };
    ups = mkService {
      label = "NUT web interface";
      enabled = cfg.power.ups.enable && cfg.power.ups.web.enable;
      units = [ "podman-nut-webgui.service" ];
      port = cfg.power.ups.web.port;
      publicPath = "/ups/";
      access = "admin";
      linkKey = "ups";
      category = "Monitoring";
    };
  };
in
{
  serviceRegistry = registry;
  serviceRegistryV2 = {
    schemaVersion = 2;
    generation = 1;
    services = registry;
  };
}
