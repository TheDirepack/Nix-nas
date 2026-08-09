args:
let
  inherit (args) cfg lib llamaCppPackage serviceRegistry;
  featureCatalog = {
    schemaVersion = 2;
    features = {
      ai = {
        label = "Local AI";
        description = "Master availability switch for local AI. It prepares storage/configuration once; child runtime processes can remain asleep until used.";
        available = cfg.ai.enable;
        allowedModes = [ "off" "always" ];
        defaultMode = if cfg.ai.enable then "always" else "off";
        startUnits = [ "nas-ai-storage.service" "nas-ai-config-init.service" ];
        stopUnits = [ "nas-ai-config-init.service" "nas-ai-storage.service" ];
      };
      aiRuntime = {
        label = "AI runtime";
        description = "llama-swap starts on the first API or administrator request and unloads after inactivity. Models retain their own shorter unload timeout.";
        available = cfg.ai.enable;
        allowedModes = [ "off" "on-demand" "always" ];
        defaultMode = if cfg.ai.enable then "on-demand" else "off";
        legacyTrueMode = "on-demand";
        parent = "ai";
        access = "admin";
        idleSeconds = 600;
        startupTimeoutSeconds = 60;
        startupEstimateSeconds = { warm = "1-4"; first = "2-10"; };
        availabilityProbe = {
          type = "executable";
          path = "${llamaCppPackage}/bin/llama-server";
          description = "The configured llama.cpp server executable is unavailable in this generation.";
        };
        healthPort = serviceRegistry.aiRuntime.endpoints.main.targetPort;
        activePorts = [ serviceRegistry.aiRuntime.endpoints.main.targetPort ];
        startUnits = serviceRegistry.aiRuntime.runtime.units;
        stopUnits = [ "nas-llama-swap.service" ];
      };
      aiCoding = {
        label = "Coding agent";
        description = "Pi coding-agent sessions run transiently as nas-code-agent and use llama-swap as their only model/provider endpoint. Network egress is limited to the local llama-swap endpoint; loopback remains reachable only for that service and filesystem writes are confined to the approved workspace.";
        available = cfg.ai.enable && cfg.ai.codingAgent.enable;
        allowedModes = [ "off" "on-demand" "always" ];
        defaultMode = if cfg.ai.enable && cfg.ai.codingAgent.enable then "on-demand" else "off";
        legacyTrueMode = "on-demand";
        parent = "aiRuntime";
        access = "coding";
        idleSeconds = cfg.ai.codingAgent.idleSeconds;
        startupTimeoutSeconds = 60;
        startupEstimateSeconds = { warm = "1-3"; first = "2-10"; };
        startUnits = [ "nas-ai-coding-prepare.service" "nas-ai-coding-sessions.target" ];
        stopUnits = [ "nas-ai-coding-sessions.target" "nas-ai-coding-prepare.service" ];
      };
      aiWorkspace = {
        label = "AI workspace";
        description = "Open WebUI is the advanced AI workspace; it starts on authorized access and stops after 10 idle minutes.";
        available = cfg.ai.enable;
        allowedModes = [ "off" "on-demand" "always" ];
        defaultMode = if cfg.ai.enable then "on-demand" else "off";
        legacyTrueMode = "on-demand";
        parent = "aiRuntime";
        access = "ai";
        idleSeconds = 600;
        startupTimeoutSeconds = 120;
        startupEstimateSeconds = { warm = "5-20"; first = "15-60"; };
        healthUrl = "http://127.0.0.1:${toString serviceRegistry.aiWorkspace.endpoints.main.targetPort}/health";
        activePorts = [ serviceRegistry.aiWorkspace.endpoints.main.targetPort ];
        startUnits = serviceRegistry.aiWorkspace.runtime.units;
      };
      aiDownloader = {
        label = "AI model downloader";
        description = "Administrator-only model downloader, started on access and stopped after 10 idle minutes.";
        available = cfg.ai.enable && cfg.ai.modelDownloader.enable;
        allowedModes = [ "off" "on-demand" "always" ];
        defaultMode = if cfg.ai.enable && cfg.ai.modelDownloader.enable then "on-demand" else "off";
        legacyTrueMode = "on-demand";
        parent = "ai";
        access = "admin";
        idleSeconds = 600;
        startupTimeoutSeconds = 90;
        startupEstimateSeconds = { warm = "2-10"; first = "5-30"; };
        healthPort = serviceRegistry.aiDownloader.endpoints.main.targetPort;
        activePorts = [ serviceRegistry.aiDownloader.endpoints.main.targetPort ];
        startUnits = serviceRegistry.aiDownloader.runtime.units;
      };
      syncthing = {
        label = "Syncthing";
        description = "Continuous per-user device and folder synchronization.";
        available = cfg.syncthing.enable;
        allowedModes = [ "off" "always" ];
        defaultMode = if cfg.syncthing.enable then "always" else "off";
        startUnits = [ "syncthing.service" "nas-syncthing-sync.timer" ];
        stopUnits = [ "nas-syncthing-sync.timer" "nas-syncthing-sync.service" "syncthing.service" ];
      };
      vaultwarden = {
        label = "Vaultwarden";
        description = "Personal password vaults; kept resident when enabled so browser and mobile clients remain reliable.";
        available = cfg.vaultwarden.enable;
        allowedModes = [ "off" "always" ];
        defaultMode = if cfg.vaultwarden.enable then "always" else "off";
        startUnits = [ "nas-caddy-ca-export.service" "vaultwarden.service" ];
        stopUnits = [ "vaultwarden.service" ];
      };
      observability = {
        label = "VictoriaMetrics metrics";
        description = "Always-on single-node VictoriaMetrics with one Telegraf collector for continuous low-overhead history.";
        available = cfg.observability.enable;
        allowedModes = [ "off" "always" ];
        defaultMode = if cfg.observability.enable then "always" else "off";
        legacyTrueMode = "always";
        access = "admin";
        startupTimeoutSeconds = 90;
        startupEstimateSeconds = { warm = "1-5"; first = "3-20"; };
        healthUrl = "http://127.0.0.1:${toString cfg.observability.victoriaMetricsPort}/victoriametrics/ping";
        activePorts = [ cfg.observability.victoriaMetricsPort ];
        startUnits = [ "victoriametrics.service" "telegraf.service" ];
        stopUnits = [ "telegraf.service" "victoriametrics.service" ];
      };
      alerts = {
        label = "Alert evaluation and delivery";
        description = "vmalert evaluates rules continuously and sends deduplicated alerts through the hardened NAS router directly to ntfy when notifications are enabled.";
        available = cfg.observability.enable && cfg.alerting.enable;
        allowedModes = [ "off" "on-demand" "always" ];
        defaultMode = if cfg.observability.enable && cfg.alerting.enable then "always" else "off";
        legacyTrueMode = "always";
        parent = "observability";
        access = "admin";
        idleSeconds = 1800;
        startupTimeoutSeconds = 60;
        startupEstimateSeconds = { warm = "1-5"; first = "2-15"; };
        healthUrls = [
          "http://127.0.0.1:${toString cfg.observability.vmalertPort}/-/ready"
          "http://127.0.0.1:${toString cfg.observability.alertRouterPort}/-/ready"
        ];
        activePorts = [ cfg.observability.vmalertPort cfg.observability.alertRouterPort ];
        startUnits = lib.optional cfg.observability.ntfy.enable "ntfy-sh.service"
          ++ [ "nas-alert-router.service" "vmalert-nas.service" ];
        stopUnits = [ "vmalert-nas.service" "nas-alert-router.service" ];
      };
      grafana = {
        label = "Grafana dashboards";
        description = "Grafana starts on first administrator access and queries the always-on VictoriaMetrics backend.";
        available = cfg.observability.enable && cfg.observability.grafana.enable;
        allowedModes = [ "off" "on-demand" "always" ];
        defaultMode = if cfg.observability.enable && cfg.observability.grafana.enable then "on-demand" else "off";
        legacyTrueMode = "on-demand";
        parent = "observability";
        access = "admin";
        idleSeconds = 600;
        startupTimeoutSeconds = 60;
        startupEstimateSeconds = { warm = "1-5"; first = "3-15"; };
        healthUrl = "http://127.0.0.1:${toString cfg.observability.grafana.port}/api/health";
        activePorts = [ cfg.observability.grafana.port ];
        startUnits = [ "grafana.service" ];
      };
      notifications = {
        label = "ntfy notifications";
        description = "Native push-notification server. It remains resident when enabled so mobile subscriptions and system alerts are reliable.";
        available = cfg.observability.ntfy.enable;
        allowedModes = [ "off" "always" ];
        defaultMode = if cfg.observability.ntfy.enable then "always" else "off";
        access = "admin";
        startUnits = [ "ntfy-sh.service" ];
        stopUnits = [ "ntfy-sh.service" ];
      };
      virtualization = {
        label = "Virtual machines";
        description = "libvirt/QEMU and Cockpit Machines.";
        available = cfg.virtualization.enable;
        allowedModes = [ "off" "always" ];
        defaultMode = if cfg.virtualization.enable then "always" else "off";
        availabilityProbe = {
          type = "device-any";
          paths = [ "/dev/kvm" ];
          description = "Hardware virtualization is unavailable because /dev/kvm is missing.";
        };
        startUnits = [ "nas-vm-storage.service" "libvirtd.service" "nas-vm-storage-pool.service" ];
        stopUnits = [ "nas-vm-storage-pool.service" "libvirtd.service" "nas-vm-storage.service" ];
      };
      upsWeb = {
        label = "UPS web interface";
        description = "The optional NUT web UI starts on administrator access. Core UPS monitoring remains resident and unaffected.";
        available = cfg.power.ups.enable && cfg.power.ups.web.enable;
        allowedModes = [ "off" "on-demand" "always" ];
        defaultMode = if cfg.power.ups.enable && cfg.power.ups.web.enable then "on-demand" else "off";
        legacyTrueMode = "on-demand";
        access = "admin";
        idleSeconds = 600;
        startupTimeoutSeconds = 60;
        startupEstimateSeconds = { warm = "1-5"; first = "3-15"; };
        healthPort = serviceRegistry.ups.endpoints.main.targetPort;
        activePorts = [ serviceRegistry.ups.endpoints.main.targetPort ];
        startUnits = serviceRegistry.ups.runtime.units;
      };
      automaticUpdates = {
        label = "Scheduled update checks";
        description = "Run the reviewed-checkout update timer. Dependency changes remain CI/Renovate-owned.";
        available = cfg.autoUpdate.enable && cfg.installationReady && cfg.scheduler.backend == "systemd";
        allowedModes = [ "off" "always" ];
        defaultMode = if cfg.autoUpdate.enable && cfg.installationReady && cfg.scheduler.backend == "systemd" then "always" else "off";
        startUnits = [ "nas-auto-update.timer" ];
        stopUnits = [ "nas-auto-update.timer" ];
      };
      backups = {
        label = "Scheduled critical-state backups";
        description = "Restic timer for appliance configuration and mutable service state.";
        available = cfg.backup.enable && cfg.scheduler.backend == "systemd";
        allowedModes = [ "off" "always" ];
        defaultMode = if cfg.backup.enable && cfg.scheduler.backend == "systemd" then "always" else "off";
        startUnits = [ "restic-backups-nas-boot-system.timer" ];
        stopUnits = [ "restic-backups-nas-boot-system.timer" ];
      };
    };
    memoryComponents = [
      { id = "system"; label = "NixOS and systemd base"; minMiB = 350; typicalMiB = 500; maxMiB = 700; notes = "Kernel userspace and ordinary base daemons; ZFS ARC is excluded."; units = [ ]; }
      { id = "network"; label = "NetworkManager, firewalld, SSH, mDNS"; minMiB = 80; typicalMiB = 120; maxMiB = 180; units = [ "NetworkManager.service" "firewalld.service" "sshd.service" "avahi-daemon.service" ]; }
      { id = "desktop"; label = "Optional XFCE, LightDM, Xorg, and KeePassXC"; installed = cfg.desktop.enable; minMiB = 300; typicalMiB = 550; maxMiB = 900; notes = "Optional maintenance desktop; secret activation is CLI-based and does not require a logged-in session."; units = [ "display-manager.service" ]; }
      { id = "zfs"; label = "ZFS helpers"; minMiB = 30; typicalMiB = 60; maxMiB = 100; notes = "Excludes the adaptive ZFS ARC cache; SMART polling is performed by Telegraf without waking standby disks."; units = [ "sanoid.service" ]; }
      { id = "caddy"; label = "Caddy"; minMiB = 30; typicalMiB = 45; maxMiB = 70; units = [ "caddy.service" ]; }
      { id = "feature-gate"; label = "On-demand feature gate"; minMiB = 12; typicalMiB = 22; maxMiB = 35; notes = "Lightweight Unix-socket authorization, readiness, and idle-reaping service."; units = [ "nas-on-demand-gate.service" ]; }
      { id = "cockpit"; label = "Cockpit idle socket"; minMiB = 5; typicalMiB = 10; maxMiB = 20; notes = "An active browser session can temporarily add roughly 40–120 MiB."; units = [ "cockpit.socket" ]; }
      { id = "authentik"; label = "Authentik server and worker"; minMiB = 220; typicalMiB = 340; maxMiB = 520; notes = "Includes the web/API server and background worker, but not PostgreSQL."; units = [ "authentik.service" "authentik-worker.service" ]; }
      { id = "postgresql"; label = "PostgreSQL for Authentik"; minMiB = 60; typicalMiB = 100; maxMiB = 180; units = [ "postgresql.service" ]; }
      { id = "copyparty"; label = "CopyParty"; minMiB = 80; typicalMiB = 140; maxMiB = 250; notes = "Large indexes, thumbnails, and concurrent transfers raise usage."; units = [ "copyparty.service" ]; }
      { id = "syncthing"; label = "Syncthing"; feature = "syncthing"; minMiB = 80; typicalMiB = 140; maxMiB = 250; units = [ "syncthing.service" ]; }
      { id = "vaultwarden"; label = "Vaultwarden"; feature = "vaultwarden"; minMiB = 20; typicalMiB = 45; maxMiB = 80; units = [ "vaultwarden.service" ]; }
      { id = "victoriametrics"; label = "VictoriaMetrics"; feature = "observability"; minMiB = 60; typicalMiB = 120; maxMiB = 250; notes = "Single-node metrics storage and PromQL-compatible query API."; units = [ "victoriametrics.service" ]; }
      { id = "telegraf"; label = "Telegraf collectors"; feature = "observability"; minMiB = 20; typicalMiB = 40; maxMiB = 80; units = [ "telegraf.service" ]; }
      { id = "vmalert"; label = "vmalert"; feature = "alerts"; installed = cfg.alerting.enable; minMiB = 20; typicalMiB = 35; maxMiB = 70; units = [ "vmalert-nas.service" ]; }
      { id = "alert-router"; label = "NAS alert router"; feature = "alerts"; installed = cfg.alerting.enable; minMiB = 8; typicalMiB = 15; maxMiB = 30; units = [ "nas-alert-router.service" ]; }
      { id = "grafana"; label = "Grafana"; feature = "grafana"; minMiB = 150; typicalMiB = 220; maxMiB = 350; units = [ "grafana.service" ]; }
      { id = "ntfy"; label = "ntfy push server"; feature = "notifications"; minMiB = 20; typicalMiB = 35; maxMiB = 60; units = [ "ntfy-sh.service" ]; }
      { id = "llama-swap"; label = "llama-swap, no model loaded"; feature = "aiRuntime"; minMiB = 20; typicalMiB = 35; maxMiB = 60; units = [ "nas-llama-swap.service" ]; }
      { id = "pi-coding-agent"; label = "Pi coding agent, active session"; feature = "aiCoding"; installed = cfg.ai.codingAgent.enable; minMiB = 30; typicalMiB = 100; maxMiB = 300; notes = "No Pi process is resident at idle; these values apply only while a transient coding session is active (tracked via nas-ai-coding.slice) and exclude LSP/browser/model processes. Filesystem writes are confined to the approved workspace; network egress is limited to the local llama-swap endpoint via IPAddressDeny/Allow."; units = [ "nas-ai-coding.slice" "nas-ai-coding-sessions.target" ]; }
      { id = "open-webui"; label = "Open WebUI, no model loaded"; feature = "aiWorkspace"; minMiB = 400; typicalMiB = 650; maxMiB = 1000; notes = "Typical warm start is modeled as 5–20 seconds; the gate records the actual last startup."; units = [ "open-webui.service" ]; }
      { id = "downloader"; label = "Model downloader"; feature = "aiDownloader"; minMiB = 50; typicalMiB = 90; maxMiB = 150; units = [ "podman-hfdownloader.service" ]; }
      { id = "virtualization"; label = "libvirt, no VM running"; feature = "virtualization"; minMiB = 50; typicalMiB = 90; maxMiB = 150; units = [ "libvirtd.service" ]; }
      { id = "ups-core"; label = "NUT UPS monitoring"; installed = cfg.power.ups.enable; minMiB = 20; typicalMiB = 40; maxMiB = 70; notes = "Safety monitoring remains independent of the optional web interface."; units = [ "upsd.service" "upsmon.service" ]; }
      { id = "ups-web"; label = "UPS web interface"; feature = "upsWeb"; minMiB = 20; typicalMiB = 35; maxMiB = 60; units = [ "podman-nut-webgui.service" ]; }
      { id = "misc"; label = "Timers and small helpers"; minMiB = 20; typicalMiB = 40; maxMiB = 80; units = [ ]; }
    ];
  };
in
{
  inherit featureCatalog;
}
