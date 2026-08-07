{ config, ... }:

let
  cfg = config.nas;
  registry = {
    identity = {
      label = "Authentik identity";
      publicPath = cfg.identity.authentikPath;
      port = 9000;
      units = [ "authentik.service" "authentik-worker.service" ];
      access = "public";
      available = true;
      linkKey = "identity";
    };
    cockpit = {
      label = "Cockpit management";
      publicPath = "/console/";
      port = 9092;
      units = [ "cockpit.socket" ];
      access = "admin";
      available = true;
      linkKey = "console";
    };
    aiApi = {
      label = "llama-swap API";
      publicPath = "/ai/v1/";
      port = cfg.ai.llamaSwap.port;
      units = [ "nas-llama-swap.service" ];
      access = "api-key";
      available = cfg.ai.enable;
      linkKey = null;
    };
    aiRuntime = {
      label = "llama-swap runtime UI";
      publicPath = "/ai/runtime/";
      port = cfg.ai.llamaSwap.port;
      units = [ "nas-llama-swap.service" ];
      access = "admin";
      available = cfg.ai.enable;
      linkKey = "aiRuntime";
    };
    aiWorkspace = {
      label = "Open WebUI";
      publicPath = "/ai/";
      port = cfg.ai.openWebuiPort;
      units = [ "open-webui.service" ];
      access = "ai";
      available = cfg.ai.enable;
      linkKey = "aiWorkspace";
    };
    aiDownloader = {
      label = "Hugging Face model downloader";
      publicPath = "/ai/models/";
      port = cfg.ai.modelDownloader.port;
      units = [ "podman-hfdownloader.service" ];
      access = "admin";
      available = cfg.ai.enable && cfg.ai.modelDownloader.enable;
      linkKey = "aiModels";
    };
    syncthing = {
      label = "Syncthing administration";
      publicPath = "/syncthing/";
      port = 8384;
      units = [ "syncthing.service" ];
      access = "admin";
      available = cfg.syncthing.enable;
      linkKey = "syncthing";
    };
    vaultwarden = {
      label = "Vaultwarden";
      publicPath = "/vault/";
      port = 8222;
      units = [ "vaultwarden.service" ];
      access = "vault";
      available = cfg.vaultwarden.enable;
      linkKey = "vaultwarden";
    };
    victoriametrics = {
      label = "VictoriaMetrics";
      publicPath = "/victoriametrics/";
      port = cfg.observability.victoriaMetricsPort;
      units = [ "victoriametrics.service" ];
      access = "admin";
      available = cfg.observability.enable;
      linkKey = "victoriaMetrics";
    };
    grafana = {
      label = "Grafana";
      publicPath = "/metrics/";
      port = cfg.observability.grafana.port;
      units = [ "grafana.service" ];
      access = "admin";
      available = cfg.observability.enable && cfg.observability.grafana.enable;
      linkKey = "metrics";
    };
    alerts = {
      label = "Alert status";
      publicPath = "/alerts/";
      port = cfg.observability.alertRouterPort;
      units = [ "nas-alert-router.service" "vmalert-nas.service" ];
      access = "admin";
      available = cfg.observability.enable && cfg.alerting.enable;
      linkKey = "alerts";
    };
    notifications = {
      label = "ntfy notifications";
      publicPath = "/notifications/";
      port = cfg.observability.ntfy.port;
      units = [ "ntfy-sh.service" ];
      access = "native";
      available = cfg.observability.ntfy.enable;
      linkKey = "notifications";
    };
    ups = {
      label = "NUT web interface";
      publicPath = "/ups/";
      port = cfg.power.ups.web.port;
      units = [ "podman-nut-webgui.service" ];
      access = "admin";
      available = cfg.power.ups.enable && cfg.power.ups.web.enable;
      linkKey = "ups";
    };
  };
in
{
  serviceRegistry = registry;
}
