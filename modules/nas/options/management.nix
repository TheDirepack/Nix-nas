{ lib, ... }:

{
  options.nas = {
    networking = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Use NetworkManager as the runtime network configuration authority exposed through Cockpit.";
      };
      firewall = {
        enable = lib.mkOption {
          type = lib.types.bool;
          default = true;
          description = "Use firewalld as the runtime firewall authority with its nftables backend.";
        };
        zone = lib.mkOption {
          type = lib.types.strMatching "^[A-Za-z0-9_.-]+$";
          default = "nas-lan";
          description = "Initial firewalld zone assigned to trusted NAS interfaces and NetworkManager connections.";
        };
        seedDefaults = lib.mkOption {
          type = lib.types.bool;
          default = true;
          description = "Enforce the versioned mandatory firewalld baseline while preserving unrelated administrator additions.";
        };
      };
    };

    observability = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Install single-node VictoriaMetrics, Telegraf collectors, optional Grafana, vmalert, the NAS alert router, and native ntfy notification components.";
      };
      retentionTime = lib.mkOption {
        type = lib.types.str;
        default = "30d";
        description = "VictoriaMetrics local time-series retention duration.";
      };
      serviceUid = lib.mkOption {
        type = lib.types.int;
        default = 954;
        description = "Fixed host UID used for writable observability application state.";
      };
      serviceGid = lib.mkOption {
        type = lib.types.int;
        default = 954;
        description = "Fixed host GID used for writable observability application state.";
      };
      victoriaMetricsPort = lib.mkOption {
        type = lib.types.port;
        default = 8428;
        description = "Loopback single-node VictoriaMetrics web/API port.";
      };
      vmalertPort = lib.mkOption {
        type = lib.types.port;
        default = 8880;
        description = "Loopback vmalert health and status port.";
      };
      alertRouterPort = lib.mkOption {
        type = lib.types.port;
        default = 9093;
        description = "Loopback NAS alert-router web/API port.";
      };
      grafana = {
        enable = lib.mkOption {
          type = lib.types.bool;
          default = false;
          description = "Enable Grafana for historical NAS dashboards.";
        };
        port = lib.mkOption {
          type = lib.types.port;
          default = 3000;
          description = "Loopback Grafana HTTP port.";
        };
      };
      ntfy = {
        enable = lib.mkOption {
          type = lib.types.bool;
          default = false;
          description = "Enable the native ntfy push-notification server and direct NAS alert delivery.";
        };
        port = lib.mkOption {
          type = lib.types.port;
          default = 2586;
          description = "Loopback ntfy HTTP port.";
        };
      };
      thresholds = {
        filesystemWarningPercent = lib.mkOption {
          type = lib.types.ints.between 1 99;
          default = 15;
          description = "Alert when a monitored filesystem has less than this percentage available.";
        };
        filesystemCriticalPercent = lib.mkOption {
          type = lib.types.ints.between 1 99;
          default = 8;
          description = "Critical alert threshold for available filesystem percentage.";
        };
        diskTemperatureCelsius = lib.mkOption {
          type = lib.types.ints.between 30 100;
          default = 55;
          description = "SMART temperature warning threshold in Celsius.";
        };
      };
    };

    scheduler = {
      backend = lib.mkOption {
        type = lib.types.enum [ "systemd" "cockpit-scheduler" ];
        default = "systemd";
        description = "Scheduling authority. cockpit-scheduler requires a packaged 45Drives plugin and disables duplicate built-in timers.";
      };
      package = lib.mkOption {
        type = lib.types.nullOr lib.types.package;
        default = null;
        description = "Optional packaged 45Drives Cockpit Scheduler plugin. Kept explicit until a reproducible Nix package is available.";
      };
      seedDefaults = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Import the NAS default snapshot, scrub, SMART, health, and update schedules when Cockpit Scheduler is first enabled.";
      };
    };
  };
}
