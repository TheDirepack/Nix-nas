{ config, lib, pkgs, nasInternal, ... }:

let
  inherit (nasInternal)
    cfg
    lanHost
    nasAlertRouter
    observabilitySecretDir
    powerSecretDir
  ;
  obs = cfg.observability;
  grafana = obs.grafana;
  memoryPolicy = {
    performance = {
      victoriaAllowed = "256MiB";
      victoriaHigh = "384M";
      telemetryInterval = "30s";
      metricBufferLimit = 20000;
    };
    balanced = {
      victoriaAllowed = "96MiB";
      victoriaHigh = "128M";
      telemetryInterval = "60s";
      metricBufferLimit = 10000;
    };
    low-memory = {
      victoriaAllowed = "64MiB";
      victoriaHigh = "96M";
      telemetryInterval = "120s";
      metricBufferLimit = 5000;
    };
  }.${cfg.memoryProfile};
  monitoredUnits = lib.unique (
    [
      "nas-*"
      "podman-*.service"
      "zfs-*"
      "sanoid*"
      "syncoid*"
      "NetworkManager.service"
      "firewalld.service"
      "sshd.service"
      "postgresql.service"
      "authentik.service"
      "authentik-worker.service"
      "copyparty.service"
      "caddy.service"
      "cockpit.socket"
    ]
    ++ lib.optional cfg.syncthing.enable "syncthing.service"
    ++ lib.optional cfg.vaultwarden.enable "vaultwarden.service"
    ++ lib.optional cfg.ai.enable "open-webui.service"
    ++ lib.optional cfg.virtualization.enable "libvirtd.service"
    ++ lib.optionals cfg.observability.enable [ "victoriametrics.service" "telegraf.service" ]
    ++ lib.optional (cfg.observability.enable && cfg.alerting.enable) "vmalert-nas.service"
    ++ lib.optional (cfg.observability.enable && cfg.observability.grafana.enable) "grafana.service"
    ++ lib.optional cfg.observability.ntfy.enable "ntfy-sh.service"
  );
  smartctlReadOnly = pkgs.writeShellScript "nas-smartctl-readonly" ''
    set -euo pipefail

    die() {
      echo "nas-smartctl-readonly: refused SMART command" >&2
      exit 64
    }

    # Telegraf's smart input uses only two smartctl command shapes:
    #   smartctl --scan [--device=nvme]
    #   smartctl --info --health --attributes --tolerance=verypermissive \
    #     -n MODE --format=brief DEVICE [-d TYPE]
    # Keep the privileged wrapper intentionally narrower than smartctl itself.
    if [[ $# -eq 1 && "$1" == "--scan" ]]; then
      exec ${pkgs.smartmontools}/bin/smartctl "$@"
    fi
    if [[ $# -eq 2 && "$1" == "--scan" && "$2" == "--device=nvme" ]]; then
      exec ${pkgs.smartmontools}/bin/smartctl "$@"
    fi

    [[ $# -ge 8 && $# -le 10 ]] || die
    [[ "$1" == "--info" ]] || die
    [[ "$2" == "--health" ]] || die
    [[ "$3" == "--attributes" ]] || die
    [[ "$4" == "--tolerance=verypermissive" ]] || die
    [[ "$5" == "-n" ]] || die
    case "$6" in
      never|sleep|standby|idle) ;;
      *) die ;;
    esac
    [[ "$7" == "--format=brief" ]] || die
    device="$8"
    [[ "$device" == /dev/* && "$device" != *".."* && "$device" != *$'\n'* ]] || die
    if [[ $# -eq 10 ]]; then
      [[ "$9" == "-d" ]] || die
      [[ "$10" =~ ^[A-Za-z0-9_,:+.-]+$ ]] || die
    elif [[ $# -ne 8 ]]; then
      die
    fi

    exec ${pkgs.smartmontools}/bin/smartctl "$@"
  '';
  victoriaMetricsUrl = "http://127.0.0.1:${toString obs.victoriaMetricsPort}/victoriametrics";
  dashboardJson = builtins.toJSON {
    annotations.list = [ ];
    editable = true;
    fiscalYearStartMonth = 0;
    graphTooltip = 1;
    links = [ ];
    panels = [
      {
        type = "stat";
        title = "Telemetry sources reporting";
        id = 1;
        gridPos = { h = 6; w = 6; x = 0; y = 0; };
        datasource = { type = "victoriametrics-metrics-datasource"; uid = "nas-victoriametrics"; };
        targets = [ { refId = "A"; expr = "count(system_uptime)"; } ];
      }
      {
        type = "timeseries";
        title = "CPU busy";
        id = 2;
        gridPos = { h = 8; w = 18; x = 6; y = 0; };
        datasource = { type = "victoriametrics-metrics-datasource"; uid = "nas-victoriametrics"; };
        fieldConfig.defaults.unit = "percent";
        targets = [
          {
            refId = "A";
            expr = ''cpu_usage_active{cpu="cpu-total"}'';
            legendFormat = "{{host}}";
          }
        ];
      }
      {
        type = "timeseries";
        title = "Filesystem available";
        id = 3;
        gridPos = { h = 8; w = 12; x = 0; y = 8; };
        datasource = { type = "victoriametrics-metrics-datasource"; uid = "nas-victoriametrics"; };
        fieldConfig.defaults.unit = "percent";
        targets = [
          {
            refId = "A";
            expr = ''100 - disk_used_percent{fstype!~"tmpfs|ramfs|overlay"}'';
            legendFormat = "{{path}}";
          }
        ];
      }
      {
        type = "timeseries";
        title = "Disk temperatures";
        id = 4;
        gridPos = { h = 8; w = 12; x = 12; y = 8; };
        datasource = { type = "victoriametrics-metrics-datasource"; uid = "nas-victoriametrics"; };
        fieldConfig.defaults.unit = "celsius";
        targets = [
          {
            refId = "A";
            expr = "smart_device_temp_c";
            legendFormat = "{{device}}";
          }
        ];
      }
    ];
    refresh = "30s";
    schemaVersion = 40;
    tags = [ "nas" "overview" "victoriametrics" ];
    templating.list = [ ];
    time = { from = "now-6h"; to = "now"; };
    timezone = "browser";
    title = "NAS Overview";
    uid = "nas-overview";
    version = 2;
  };
  dashboardDir = pkgs.runCommand "nas-grafana-dashboards" { } ''
    mkdir -p "$out"
    cat > "$out/nas-overview.json" <<'JSON'
    ${dashboardJson}
    JSON
  '';
  rules = pkgs.writeText "nas-vmalert-rules.yml" ''
    groups:
      - name: nas-host
        rules:
          - alert: NasTelemetryStale
            expr: time() - timestamp(system_uptime) > 180
            for: 2m
            labels:
              severity: critical
            annotations:
              summary: "NAS telemetry is stale"
              description: "Telegraf has not delivered current host telemetry for more than three minutes."
          - alert: NasSystemdUnitFailed
            expr: systemd_units_active_code == 3
            for: 2m
            labels:
              severity: critical
            annotations:
              summary: "A systemd unit failed"
              description: "{{ $labels.name }} is in the failed state on {{ $labels.host }}."
          - alert: NasFilesystemLowSpace
            expr: 100 - disk_used_percent{fstype!~"tmpfs|ramfs|overlay"} < ${toString obs.thresholds.filesystemWarningPercent}
            for: 15m
            labels:
              severity: warning
            annotations:
              summary: "Filesystem space is low"
              description: "{{ $labels.path }} on {{ $labels.host }} has less than ${toString obs.thresholds.filesystemWarningPercent}% available."
          - alert: NasFilesystemCriticalSpace
            expr: 100 - disk_used_percent{fstype!~"tmpfs|ramfs|overlay"} < ${toString obs.thresholds.filesystemCriticalPercent}
            for: 5m
            labels:
              severity: critical
            annotations:
              summary: "Filesystem space is critically low"
              description: "{{ $labels.path }} on {{ $labels.host }} has less than ${toString obs.thresholds.filesystemCriticalPercent}% available."
          - alert: NasSmartHealthFailed
            expr: smart_device_health_ok == 0
            for: 2m
            labels:
              severity: critical
            annotations:
              summary: "SMART health check failed"
              description: "{{ $labels.device }} on {{ $labels.host }} reports a failed SMART status."
          - alert: NasDiskTemperatureHigh
            expr: smart_device_temp_c > ${toString obs.thresholds.diskTemperatureCelsius}
            for: 10m
            labels:
              severity: warning
            annotations:
              summary: "Disk temperature is high"
              description: "{{ $labels.device }} is above ${toString obs.thresholds.diskTemperatureCelsius}°C."
  '';
in
{
  config = lib.mkMerge [
    (lib.mkIf obs.enable {
      services.victoriametrics = {
        enable = true;
        listenAddress = "127.0.0.1:${toString obs.victoriaMetricsPort}";
        stateDir = "victoriametrics";
        retentionPeriod = obs.retentionTime;
        extraOptions = [
          "-http.pathPrefix=/victoriametrics"
          "-usePromCompatibleNaming"
          "-memory.allowedBytes=${memoryPolicy.victoriaAllowed}"
        ];
      };

      # Collect directly into VictoriaMetrics to keep the resident stack small.
      services.telegraf = {
        enable = true;
        extraConfig = {
          agent = {
            interval = memoryPolicy.telemetryInterval;
            round_interval = true;
            flush_interval = memoryPolicy.telemetryInterval;
            flush_jitter = "2s";
            metric_batch_size = 1000;
            metric_buffer_limit = memoryPolicy.metricBufferLimit;
            collection_jitter = "2s";
            omit_hostname = false;
          };
          outputs.influxdb = {
            urls = [ victoriaMetricsUrl ];
            database = "nas";
            skip_database_creation = true;
            timeout = "10s";
            content_encoding = "gzip";
          };
          # VictoriaMetrics' Influx ingestion maps non-numeric fields to zero.
          # Normalize SMART's boolean health field before output so healthy=1
          # and failed=0 remain distinguishable to vmalert.
          # Telegraf processors are TOML array-of-table plugins, even when only
          # one processor instance is configured.
          processors.converter = [
            {
              namepass = [ "smart_device" ];
              fields.float = [ "health_ok" ];
            }
          ];
          inputs = {
            cpu = {
              percpu = true;
              totalcpu = true;
              collect_cpu_time = false;
              report_active = true;
            };
            disk = {
              ignore_fs = [ "tmpfs" "devtmpfs" "devfs" "iso9660" "overlay" "aufs" "squashfs" ];
            };
            diskio = { };
            kernel = { };
            mem = { };
            processes = { };
            swap = { };
            system = { };
            systemd_units = {
              pattern = lib.concatStringsSep " " monitoredUnits;
              scope = "system";
              collect_disabled_units = false;
              details = false;
              timeout = "5s";
            };
            zfs = { };
            smart = {
              path_smartctl = "${smartctlReadOnly}";
              use_sudo = true;
              nocheck = "standby";
              attributes = false;
              timeout = "30s";
              read_method = "sequential";
            };
          } // lib.optionalAttrs cfg.power.ups.enable {
            upsd = {
              server = cfg.power.ups.web.upsdAddress;
              port = cfg.power.ups.web.upsdPort;
              force_float = true;
              stringify_ids = true;
            };
          };
        };
      };

      security.sudo.extraRules = [
        {
          users = [ "telegraf" ];
          commands = [
            {
              command = "${smartctlReadOnly}";
              options = [ "NOPASSWD" "NOSETENV" ];
            }
          ];
        }
      ];

      systemd.services.victoriametrics.serviceConfig.MemoryHigh = memoryPolicy.victoriaHigh;

      systemd.services.telegraf = {
        after = [ "victoriametrics.service" ];
        requires = [ "victoriametrics.service" ];
        path = [ pkgs.sudo ];
        # SMART is the only privileged Telegraf input. sudo can execute only the
        # immutable read-only wrapper above; the wrapper validates Telegraf's
        # documented scan/read shapes before invoking smartctl.
        serviceConfig = {
          # Ping collection is disabled, so Telegraf does not need CAP_NET_RAW.
          AmbientCapabilities = lib.mkForce [ ];
          RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
          PrivateTmp = true;
          ProtectHome = true;
          ProtectSystem = "strict";
          ProtectKernelTunables = true;
          ProtectKernelModules = true;
          ProtectControlGroups = true;
          RestrictSUIDSGID = true;
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
        };
      };

      services.vmalert.instances.nas = lib.mkIf cfg.alerting.enable {
        enable = true;
        settings = {
          "datasource.url" = victoriaMetricsUrl;
          "remoteRead.url" = victoriaMetricsUrl;
          "remoteWrite.url" = victoriaMetricsUrl;
          "notifier.url" = [ "http://127.0.0.1:${toString obs.alertRouterPort}" ];
          "httpListenAddr" = "127.0.0.1:${toString obs.vmalertPort}";
          "evaluationInterval" = "30s";
          rule = lib.mkOverride 90 [ rules ];
        };
      };

      systemd.services.nas-alert-router = lib.mkIf cfg.alerting.enable {
        description = "NAS vmalert notification router";
        after = [ "network-online.target" ] ++ lib.optional obs.ntfy.enable "ntfy-sh.service";
        wants = [ "network-online.target" ] ++ lib.optional obs.ntfy.enable "ntfy-sh.service";
        wantedBy = [ ];
        environment = {
          NAS_ALERT_ROUTER_LISTEN = "127.0.0.1:${toString obs.alertRouterPort}";
          NAS_ALERT_ROUTER_STATE = "/var/lib/nas-alert-router/state.json";
          NAS_ALERT_ROUTER_REPEAT_SECONDS = "14400";
          NAS_ALERT_ROUTER_NTFY_ENABLED = if obs.ntfy.enable then "1" else "0";
          NAS_NTFY_URL = "http://127.0.0.1:${toString obs.ntfy.port}";
          NAS_NTFY_TOPIC_FILE = "${observabilitySecretDir}/ntfy-topic";
          NAS_NTFY_PASSWORD_FILE = "${observabilitySecretDir}/ntfy-admin-password";
          NAS_NTFY_USERNAME = "admin";
        };
        unitConfig = lib.optionalAttrs obs.ntfy.enable {
          ConditionPathExists = [
            "${observabilitySecretDir}/ntfy-topic"
            "${observabilitySecretDir}/ntfy-admin-password"
          ];
        };
        serviceConfig = {
          Type = "simple";
          ExecStart = nasAlertRouter;
          User = "nas-observability";
          Group = "nas-observability";
          StateDirectory = "nas-alert-router";
          StateDirectoryMode = "0700";
          Restart = "on-failure";
          RestartSec = "5s";
          TimeoutStartSec = "30s";
          TimeoutStopSec = "30s";
          NoNewPrivileges = true;
          PrivateTmp = true;
          PrivateDevices = true;
          ProtectSystem = "strict";
          ProtectHome = true;
          ProtectKernelTunables = true;
          ProtectKernelModules = true;
          ProtectControlGroups = true;
          RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
          RestrictNamespaces = true;
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          CapabilityBoundingSet = [ ];
          SystemCallArchitectures = "native";
          SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ];
          UMask = "0077";
        } // lib.optionalAttrs obs.ntfy.enable {
          BindReadOnlyPaths = [
            "${observabilitySecretDir}/ntfy-topic"
            "${observabilitySecretDir}/ntfy-admin-password"
          ];
        };
      };

      services.grafana = lib.mkIf grafana.enable {
        enable = true;
        declarativePlugins = [ pkgs.grafanaPlugins.victoriametrics-metrics-datasource ];
        settings = {
          server = {
            http_addr = "127.0.0.1";
            http_port = grafana.port;
            domain = lanHost;
            root_url = "https://${lanHost}/metrics/";
            serve_from_sub_path = true;
          };
          security = {
            secret_key = "$__file{${observabilitySecretDir}/grafana-secret-key}";
            disable_gravatar = true;
            cookie_secure = true;
            cookie_samesite = "strict";
            allow_embedding = true;
          };
          users = {
            allow_sign_up = false;
            allow_org_create = false;
            auto_assign_org = true;
            auto_assign_org_role = "Admin";
          };
          auth.disable_login_form = true;
          "auth.proxy" = {
            enabled = true;
            header_name = "X-WEBAUTH-USER";
            header_property = "username";
            auto_sign_up = true;
            sync_ttl = 5;
            headers = "Name:X-WEBAUTH-NAME Email:X-WEBAUTH-EMAIL Role:X-WEBAUTH-ROLE";
            whitelist = "127.0.0.1";
            enable_login_token = false;
          };
          analytics = {
            reporting_enabled = false;
            check_for_updates = false;
            check_for_plugin_updates = false;
          };
        };
        provision = {
          enable = true;
          datasources.settings = {
            apiVersion = 1;
            datasources = [
              {
                name = "VictoriaMetrics";
                uid = "nas-victoriametrics";
                type = "victoriametrics-metrics-datasource";
                access = "proxy";
                url = victoriaMetricsUrl;
                isDefault = true;
                editable = false;
              }
            ];
          };
          dashboards.settings = {
            apiVersion = 1;
            providers = [
              {
                name = "NAS defaults";
                orgId = 1;
                folder = "NAS";
                type = "file";
                disableDeletion = true;
                updateIntervalSeconds = 60;
                allowUiUpdates = true;
                options.path = dashboardDir;
              }
            ];
          };
        };
      };
    })

    (lib.mkIf obs.ntfy.enable {
      services.ntfy-sh = {
        enable = true;
        environmentFile = "${observabilitySecretDir}/ntfy-environment";
        settings = {
          base-url = "https://${lanHost}";
          listen-http = "127.0.0.1:${toString obs.ntfy.port}";
          web-root = "/notifications";
          behind-proxy = true;
          proxy-trusted-hosts = "127.0.0.1/32";
          upstream-base-url = "https://ntfy.sh";
          cache-file = "/var/lib/ntfy-sh/cache.db";
          cache-duration = "7d";
          attachment-cache-dir = "/var/lib/ntfy-sh/attachments";
          attachment-total-size-limit = "1G";
          attachment-file-size-limit = "15M";
        };
      };
    })

    (lib.mkIf (obs.enable || obs.ntfy.enable) {
      users.groups.nas-observability.gid = obs.serviceGid;
      users.users.nas-observability = {
        isSystemUser = true;
        uid = obs.serviceUid;
        group = "nas-observability";
        home = "/var/lib/nas-observability";
        createHome = true;
      };
    })

    (lib.mkIf (cfg.power.ups.enable && cfg.power.ups.web.enable) {
      virtualisation.oci-containers.containers.nut-webgui = {
        autoStart = false;
        image = cfg.power.ups.web.image;
        volumes = [
          "${cfg.power.ups.passwordFile}:/run/secrets/nut-password:ro"
          "${powerSecretDir}/nut-webgui-server-key:/run/secrets/nut-webgui-server-key:ro"
        ];
        environment = {
          UID = "0";
          GID = "0";
          NUTWG__HTTP_SERVER__BASE_PATH = "/ups";
          NUTWG__HTTP_SERVER__LISTEN = "127.0.0.1";
          NUTWG__HTTP_SERVER__PORT = toString cfg.power.ups.web.port;
          NUTWG__HTTP_SERVER__WORKER_COUNT = "1";
          NUTWG__UPSD__ADDRESS = cfg.power.ups.web.upsdAddress;
          NUTWG__UPSD__PORT = toString cfg.power.ups.web.upsdPort;
          NUTWG__UPSD__USERNAME = cfg.power.ups.monitorUser;
          NUTWG__UPSD__PASSWORD = "/run/secrets/nut-password";
          NUTWG__UPSD__POLL_INTERVAL = "2";
          NUTWG__UPSD__POLL_FREQ = "30";
          NUTWG__SERVER_KEY = "/run/secrets/nut-webgui-server-key";
          NUTWG__LOG_LEVEL = "info";
        };
        capabilities.ALL = false;
        extraOptions = [
          "--network=host"
          "--security-opt=no-new-privileges"
          "--read-only"
          "--read-only-tmpfs"
          "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=32m"
          "--memory=256m"
          "--pids-limit=128"
        ];
      };
    })
  ];
}
