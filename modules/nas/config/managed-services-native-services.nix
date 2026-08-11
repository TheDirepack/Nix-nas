{ config, lib, pkgs, nasInternal, ... }:

let
  cfg = config.nas;
  inherit (nasInternal) syncthingGuiPort vaultwardenPort;
  desiredPath = "/var/lib/nas-control/services.yaml";
  markerPath = "/var/lib/nas-control/.managed-services-native-seed-v2";
  schemaPath = "/etc/nas-control/managed-services-v3.schema.json";
  platformPath = "/etc/nas-control/platform-capabilities.json";
  v2Source = ../../../services;
  v2Python = pkgs.python3.withPackages (pythonPackages: with pythonPackages; [
    defusedxml
    jsonschema
    ruamel-yaml
  ]);
  yamlFormat = pkgs.formats.yaml { };

  durationSeconds = value:
    let
      matched = builtins.match "^([0-9]+)(s|sec|min|m|h|d|w)$" value;
      amount = if matched == null then null else lib.toInt (builtins.elemAt matched 0);
      unit = if matched == null then null else builtins.elemAt matched 1;
      multiplier = {
        s = 1;
        sec = 1;
        min = 60;
        m = 60;
        h = 3600;
        d = 86400;
        w = 604800;
      }.${if unit == null then "s" else unit};
      seconds = if amount == null then 0 else amount * multiplier;
    in
      if matched == null || seconds < 60 then
        throw "nas.identity.syncInterval must be a whole-unit duration of at least 60 seconds for Managed Services V2 (for example 5min, 1h, or 1d)"
      else
        seconds;

  syncSchedules = lib.optionals (cfg.scheduler.backend == "systemd") [
    {
      intervalSeconds = durationSeconds cfg.identity.syncInterval;
      randomizedDelaySeconds = 0;
      persistent = false;
    }
  ];

  daemon = unit: name: {
    inherit name;
    managed = true;
    workload = { kind = "daemon"; activation = "persistent"; };
    runtime = { type = "systemd"; inherit unit; };
  };
  onDemand = unit: name: idleSeconds: (daemon unit name) // {
    workload = { kind = "daemon"; activation = "on-demand"; inherit idleSeconds; };
  };
  job = unit: name: {
    inherit name;
    managed = true;
    workload.kind = "job";
    runtime = { type = "systemd"; inherit unit; };
  };
  scheduledJob = unit: name: schedules: (job unit name) // {
    workload = { kind = "job"; inherit schedules; };
  };
  platformService = service: service // { managed = false; };
  depends = service: condition: { inherit service condition; };
  pathRoute = paths: target: auth: {
    inherit target auth;
    exposure = { type = "path"; inherit paths; };
  };
  httpTarget = port: { type = "http"; host = "127.0.0.1"; inherit port; };
  copypartyTarget = { type = "unix-http"; socket = "/run/copyparty/http.sock"; };
  identity = capability: { mode = "identity"; inherit capability; };
  capability = id: title: { inherit id title; };
  adminCapability = title: [ (capability "admin" title) ];
  portal = title: category: icon: order: {
    visible = true;
    inherit title category icon order;
  };

  baselineServices = {
    zfs-mount-guard = platformService (job "nas-zfs-mount-guard.service" "NAS storage mount guard");
    authentik = platformService (daemon "authentik.service" "Authentik identity provider");
    identity-sync = (scheduledJob "nas-identity-sync.service" "Reconcile Authentik NAS identity policy" syncSchedules) // {
      dependencies = [ (depends "authentik" "started") ];
    };
    copyparty = (daemon "copyparty.service" "CopyParty file service") // {
      dependencies = [ (depends "zfs-mount-guard" "completed") ];
      authorization.capabilities = [
        (capability "files" "Browse and manage files")
        (capability "webdav" "Use WebDAV")
        (capability "admin" "Administer CopyParty")
      ];
      routes = {
        admin = (pathRoute [ "/shares/admin" ] copypartyTarget (identity "admin")) // { portal.visible = false; };
        dav = (pathRoute [ "/dav" ] copypartyTarget (identity "webdav")) // {
          proxy.stripPrefix = "/dav";
          portal.visible = false;
        };
        files = (pathRoute [ "/shares" ] copypartyTarget (identity "files")) // {
          portal = portal "Files" "Files" "folder" 10;
        };
        share = (pathRoute [ "/share" ] copypartyTarget { mode = "upstream"; }) // { portal.visible = false; };
      };
    };
  }
  // lib.optionalAttrs cfg.syncthing.enable {
    syncthing = (daemon "syncthing.service" "Syncthing synchronization service") // {
      dependencies = [ (depends "zfs-mount-guard" "completed") ];
      authorization.capabilities = [
        (capability "access" "Use personal Syncthing synchronization")
        (capability "admin" "Administer Syncthing")
      ];
      routes.web = (pathRoute [ "/syncthing" ] (httpTarget syncthingGuiPort) (identity "admin")) // {
        proxy.stripPrefix = "/syncthing";
        portal = portal "Syncthing" "Files" "sync" 20;
      };
    };
    syncthing-sync = (scheduledJob "nas-syncthing-sync.service" "Reconcile Syncthing identity-backed configuration" syncSchedules) // {
      dependencies = [ (depends "authentik" "started") (depends "syncthing" "started") ];
    };
  }
  // lib.optionalAttrs cfg.vaultwarden.enable {
    vaultwarden = (daemon "vaultwarden.service" "Vaultwarden password manager") // {
      dependencies = [ (depends "authentik" "started") ];
      authorization.capabilities = [
        (capability "access" "Use Vaultwarden")
        (capability "admin" "Access Vaultwarden administration")
      ];
      routes = {
        admin = (pathRoute [ "/vault/admin" ] (httpTarget vaultwardenPort) (identity "admin")) // { portal.visible = false; };
        oidc = (pathRoute [ "/vault/identity/connect/oidc" "/vault/identity/connect/oidc-signin" ] (httpTarget vaultwardenPort) (identity "access")) // { portal.visible = false; };
        web = (pathRoute [ "/vault" ] (httpTarget vaultwardenPort) { mode = "upstream"; }) // {
          portal = portal "Vaultwarden" "Home" "lock" 30;
        };
      };
    };
  }
  // lib.optionalAttrs cfg.ai.enable {
    ai-storage = (job "nas-ai-storage.service" "Prepare local AI storage") // {
      dependencies = [ (depends "zfs-mount-guard" "completed") ];
    };
    ai-config = (job "nas-ai-config-init.service" "Prepare llama-swap configuration") // {
      dependencies = [ (depends "ai-storage" "completed") ];
    };
    ai-runtime = (daemon "nas-llama-swap.service" "AI model router") // {
      dependencies = [ (depends "ai-config" "completed") ];
      authorization.capabilities = adminCapability "Administer the AI runtime";
      resources.accelerators = [ { kind = "gpu"; vendor = "any"; quantity = 1; required = false; mode = "shared"; } ];
      readiness.probes = [ { type = "tcp"; port = cfg.ai.llamaSwap.port; } ];
      routes = {
        api = (pathRoute [ "/ai/v1" ] (httpTarget cfg.ai.llamaSwap.port) { mode = "upstream"; }) // {
          proxy.stripPrefix = "/ai";
          portal.visible = false;
        };
        admin = (pathRoute [ "/ai/runtime" ] (httpTarget cfg.ai.llamaSwap.port) (identity "admin")) // {
          proxy = {
            stripPrefix = "/ai/runtime";
            requestHeaders."X-Forwarded-Prefix" = "/ai/runtime";
          };
          portal = portal "AI Runtime" "AI" "cpu" 45;
        };
      };
    };
    ai-workspace = (onDemand "open-webui.service" "Open WebUI AI workspace" 600) // {
      dependencies = [ (depends "ai-runtime" "ready") ];
      authorization.capabilities = [
        (capability "access" "Use Open WebUI")
        (capability "admin" "Administer Open WebUI")
      ];
      readiness.probes = [ { type = "http"; url = "http://127.0.0.1:${toString cfg.ai.openWebuiPort}/health"; } ];
    };
  }
  // lib.optionalAttrs (cfg.ai.enable && cfg.ai.codingAgent.enable) {
    ai-coding = (onDemand "nas-ai-coding-sessions.target" "Pi coding-agent sessions" cfg.ai.codingAgent.idleSeconds) // {
      dependencies = [ (depends "ai-runtime" "ready") ];
      authorization.capabilities = [ (capability "access" "Run coding-agent sessions") ];
    };
  }
  // lib.optionalAttrs (cfg.ai.enable && cfg.ai.modelDownloader.enable) {
    ai-downloader = (onDemand "podman-hfdownloader.service" "Hugging Face model downloader" 600) // {
      dependencies = [ (depends "ai-storage" "completed") ];
      authorization.capabilities = adminCapability "Download and manage AI models";
      readiness.probes = [ { type = "tcp"; port = cfg.ai.modelDownloader.port; } ];
      routes.web = (pathRoute [ "/ai/models" ] (httpTarget cfg.ai.modelDownloader.port) (identity "admin")) // {
        proxy = {
          stripPrefix = "/ai/models";
          requestHeaders."X-Forwarded-Prefix" = "/ai/models";
        };
        portal = portal "AI Models" "AI" "download" 50;
      };
    };
  }
  // lib.optionalAttrs cfg.virtualization.enable {
    vm-storage = (job "nas-vm-storage.service" "Prepare VM storage") // {
      dependencies = [ (depends "zfs-mount-guard" "completed") ];
    };
    virtualization = (daemon "libvirtd.service" "libvirt virtual-machine runtime") // {
      dependencies = [ (depends "vm-storage" "completed") ];
      requiresCapabilities = [ "libvirt" "kvm" ];
    };
    vm-storage-pool = (daemon "nas-vm-storage-pool.service" "Activate the ZFS-backed libvirt storage pool") // {
      dependencies = [ (depends "vm-storage" "completed") (depends "virtualization" "started") ];
      requiresCapabilities = [ "libvirt" ];
    };
  }
  // lib.optionalAttrs cfg.observability.enable {
    victoriametrics = (daemon "victoriametrics.service" "VictoriaMetrics metrics database") // {
      authorization.capabilities = adminCapability "View VictoriaMetrics";
      readiness.probes = [ { type = "tcp"; port = cfg.observability.victoriaMetricsPort; } ];
      routes.web = (pathRoute [ "/victoriametrics/" ] (httpTarget cfg.observability.victoriaMetricsPort) (identity "admin")) // {
        portal = portal "VictoriaMetrics" "Monitoring" "chart" 60;
      };
    };
    telegraf = (daemon "telegraf.service" "Telegraf metric collector") // {
      dependencies = [ (depends "victoriametrics" "started") ];
    };
  }
  // lib.optionalAttrs (cfg.observability.enable && cfg.alerting.enable) {
    alert-router = (daemon "nas-alert-router.service" "NAS alert router") // {
      authorization.capabilities = adminCapability "View alert routing";
      routes.web = (pathRoute [ "/alerts/" ] (httpTarget cfg.observability.alertRouterPort) (identity "admin")) // {
        portal = portal "Alerts" "Monitoring" "bell" 70;
      };
    };
    vmalert = (daemon "vmalert-nas.service" "VictoriaMetrics alert evaluator") // {
      dependencies = [ (depends "victoriametrics" "started") (depends "alert-router" "started") ];
    };
  }
  // lib.optionalAttrs (cfg.observability.enable && cfg.observability.grafana.enable) {
    grafana = (onDemand "grafana.service" "Grafana dashboards" 600) // {
      dependencies = [ (depends "victoriametrics" "started") ];
      authorization.capabilities = adminCapability "Administer Grafana";
      readiness.probes = [ { type = "http"; url = "http://127.0.0.1:${toString cfg.observability.grafana.port}/api/health"; } ];
      routes.web = (pathRoute [ "/metrics/" ] (httpTarget cfg.observability.grafana.port) (identity "admin")) // {
        proxy = {
          requestHeaders = {
            "X-WEBAUTH-USER" = "{http.request.header.Remote-User}";
            "X-WEBAUTH-NAME" = "{http.request.header.Remote-Name}";
            "X-WEBAUTH-EMAIL" = "{http.request.header.Remote-Email}";
            "X-WEBAUTH-ROLE" = "Admin";
            "X-Forwarded-Proto" = "https";
            "X-Forwarded-Prefix" = "/metrics";
          };
          responseHeaders."X-Frame-Options" = "SAMEORIGIN";
        };
        portal = portal "Grafana" "Monitoring" "dashboard" 65;
      };
    };
  }
  // lib.optionalAttrs cfg.observability.ntfy.enable {
    notifications = (daemon "ntfy-sh.service" "ntfy notification server") // {
      routes.web = (pathRoute [ "/notifications/" ] (httpTarget cfg.observability.ntfy.port) { mode = "upstream"; }) // {
        proxy.responseHeaders."X-Frame-Options" = "SAMEORIGIN";
        portal = portal "Notifications" "Monitoring" "bell" 80;
      };
    };
  }
  // lib.optionalAttrs (cfg.power.ups.enable && cfg.power.ups.web.enable) {
    ups-web = (onDemand "podman-nut-webgui.service" "NUT web interface" 600) // {
      authorization.capabilities = adminCapability "Administer UPS monitoring";
      readiness.probes = [ { type = "tcp"; port = cfg.power.ups.web.port; } ];
      routes.web = (pathRoute [ "/ups/" ] (httpTarget cfg.power.ups.web.port) (identity "admin")) // {
        proxy.responseHeaders."X-Frame-Options" = "SAMEORIGIN";
        portal = portal "UPS" "Monitoring" "battery" 90;
      };
    };
  };

  seedFile = yamlFormat.generate "managed-services-native-seed-v2.yaml" {
    schemaVersion = 3;
    services = baselineServices;
  };
in
{
  config.systemd.services.nas-managed-services-seed = {
    environment.PYTHONPATH = "${v2Source}";
    postStart = lib.mkAfter ''
      ${v2Python}/bin/python ${v2Source}/nas_v2_bootstrap.py \
        --desired ${lib.escapeShellArg desiredPath} \
        --seed ${lib.escapeShellArg seedFile} \
        --marker ${lib.escapeShellArg markerPath} \
        --schema ${lib.escapeShellArg schemaPath} \
        --platform ${lib.escapeShellArg platformPath}
    '';
    serviceConfig.ReadWritePaths = lib.mkAfter [ "/var/lib/nas-control" ];
  };
}
