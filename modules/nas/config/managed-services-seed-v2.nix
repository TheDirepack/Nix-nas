{ config, lib, pkgs, nasInternal, ... }:

let
  cfg = config.nas;
  inherit (nasInternal) cockpitPort;
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

  helpers = import ./managed-services-helpers.nix { inherit lib config nasInternal; };
  inherit (helpers)
    durationSeconds
    syncSchedules
    daemon
    onDemand
    job
    scheduledJob
    platformService
    depends
    pathRoute
    httpTarget
    copypartyTarget
    identity
    capability
    adminCapability
    portal
    portListener
    syncthingGuiPort
    syncthingSyncPort
    syncthingDiscoveryPort
    vaultwardenPort
    nutUpsdPort
    ;
  # Operation aliases are canonicalized in helpers; reuse single definitions.
  operationJob = helpers.scheduledJob;
  operationDependency = helpers.depends;
  operationCalendar = helpers.calendar;
  operationSystemdSchedules = helpers.systemdSchedules;
  operationHealthSchedule = helpers.healthSchedule;

  baselineServices = {
    zfs-mount-guard = platformService (job "nas-zfs-mount-guard.service" "NAS storage mount guard");
    authentik = platformService (daemon "authentik.service" "Authentik identity provider");
    identity-sync = (scheduledJob "nas-identity-sync.service" "Reconcile Authentik NAS identity policy" syncSchedules) // {
      dependencies = [ (depends "authentik" "started") ];
    };
    copyparty = (daemon "copyparty.service" "CopyParty file service") // {
      dependencies = [
        (depends "zfs-mount-guard" "completed")
        (depends "identity-sync" "completed")
      ];
      authorization.capabilities = [
        (capability "files" "Browse and manage files")
        (capability "webdav" "Use WebDAV")
        (capability "admin" "Administer CopyParty")
      ];
      listeners = lib.optionalAttrs cfg.tftp.enable {
        tftp-request = (portListener "udp" cfg.tftp.port) // {
          targetPort = cfg.tftp.internalPort;
        };
        tftp-response = {
          protocol = "udp";
          exposure = {
            start = cfg.tftp.responsePortStart;
            end = cfg.tftp.responsePortEnd;
          };
          firewall = true;
        };
      };
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
      dependencies = [
        (depends "zfs-mount-guard" "completed")
        (depends "identity-sync" "completed")
      ];
      authorization.capabilities = [
        (capability "access" "Use personal Syncthing synchronization")
        (capability "admin" "Administer Syncthing")
      ];
      listeners = {
        sync-tcp = portListener "tcp" syncthingSyncPort;
        sync-quic = portListener "udp" syncthingSyncPort;
        local-discovery = portListener "udp" syncthingDiscoveryPort;
      };
      routes.web = (pathRoute [ "/syncthing" ] (httpTarget syncthingGuiPort) (identity "admin")) // {
        proxy.stripPrefix = "/syncthing";
        portal = portal "Syncthing" "Files" "sync" 20;
      };
    };
    syncthing-sync = (scheduledJob "nas-syncthing-sync.service" "Reconcile Syncthing identity-backed configuration" syncSchedules) // {
      dependencies = [
        (depends "authentik" "started")
        (depends "identity-sync" "completed")
        (depends "syncthing" "started")
      ];
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
      routes.main = (pathRoute [ "/ai/" ] (httpTarget cfg.ai.openWebuiPort) (identity "access")) // {
        proxy = {
          stripPrefix = "/ai";
          requestHeaders."X-Forwarded-Prefix" = "/ai";
          requestHeaders."X-Forwarded-Proto" = "https";
        };
        portal = portal "Open WebUI" "AI" "bot" 40;
      };
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
    virtualization = platformService ((daemon "libvirtd.service" "libvirt virtual-machine runtime") // {
      requiresCapabilities = [ "libvirt" "kvm" ];
    });
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
  // lib.optionalAttrs (cfg.power.ups.enable && cfg.power.ups.mode == "netserver") {
    ups-server = platformService ((daemon "upsd.service" "NUT UPS network server") // {
      listeners.nut = portListener "tcp" nutUpsdPort;
    });
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

  # (operation helpers aliased above from shared helpers; no duplication)

  operationServices = {
    zfs-pool-health = (operationJob "nas-zfs-pool-health.service" "Check ZFS pool health" operationHealthSchedule) // {
      dependencies = [ (operationDependency "zfs-mount-guard" "completed") ];
    };
    zfs-capacity-health = (operationJob "nas-zfs-capacity-health.service" "Check ZFS capacity" operationHealthSchedule) // {
      dependencies = [ (operationDependency "zfs-mount-guard" "completed") ];
    };
    zfs-snapshot-health = (operationJob "nas-zfs-snapshot-health.service" "Check ZFS snapshot freshness" operationHealthSchedule) // {
      dependencies = [ (operationDependency "zfs-mount-guard" "completed") ];
    };
    zfs-manual-snapshot = (operationJob "nas-zfs-manual-snapshot.service" "Create an administrator-requested ZFS snapshot" [ ]) // {
      dependencies = [ (operationDependency "zfs-mount-guard" "completed") ];
    };
    zfs-manual-scrub = (operationJob "nas-zfs-manual-scrub.service" "Start an administrator-requested ZFS scrub" [ ]) // {
      dependencies = [ (operationDependency "zfs-mount-guard" "completed") ];
    };
  }
  // lib.optionalAttrs cfg.backup.enable {
    backups = (operationJob "restic-backups-nas-boot-system.service" "Back up authoritative NAS state" (
      operationSystemdSchedules [ (operationCalendar "daily" 7200) ]
    )) // {
      dependencies = [ (operationDependency "zfs-mount-guard" "completed") ];
    };
  }
  // lib.optionalAttrs (cfg.backup.enable && cfg.backup.restoreVerification.enable) {
    backup-restore-verify = operationJob "nas-backup-restore-verify.service" "Restore and validate the latest NAS recovery backup" (
      operationSystemdSchedules [ (operationCalendar cfg.backup.restoreVerification.onCalendar 21600) ]
    );
  }
  // lib.optionalAttrs cfg.zfsReplication.enable {
    zfs-replication = (operationJob "nas-syncoid.service" "Replicate the NAS ZFS dataset" (
      operationSystemdSchedules [ (operationCalendar cfg.zfsReplication.onCalendar 7200) ]
    )) // {
      dependencies = [ (operationDependency "zfs-mount-guard" "completed") ];
    };
  }
  // lib.optionalAttrs cfg.installationReady {
    update-preview = operationJob "nas-update-preview.service" "Preview and validate configuration updates" [ ];
    update-sync = operationJob "nas-update-sync.service" "Synchronize the reviewed configuration" [ ];
    update-apply = operationJob "nas-update-apply.service" "Apply the reviewed configuration" [ ];
  }
  // lib.optionalAttrs (cfg.installationReady && cfg.autoUpdate.enable) {
    auto-update = operationJob "nas-auto-update.service" "Guarded automatic NAS configuration update" (
      operationSystemdSchedules [ (operationCalendar cfg.autoUpdate.onCalendar 3600) ]
    );
  };

  inherit (helpers)
    backupStage
    authentikArtifact
    copypartyArtifact
    vaultwardenDataDir
    vaultwardenBackupDir
    copypartyDataDir
    ;

  backupResources = {
    authentik-database = {
      path = config.services.postgresql.dataDir;
      scope = "system";
      stateClass = "authoritative";
      capabilities = [ "read" ];
      backup = {
        enabled = true;
        consistency = "native-dump";
      };
    };
    authentik-database-dump = {
      path = authentikArtifact;
      scope = "system";
      stateClass = "derived";
      capabilities = [ "read" "write" ];
      backup.enabled = false;
    };
    copyparty-databases = {
      path = copypartyDataDir;
      scope = "system";
      stateClass = "authoritative";
      capabilities = [ "read" ];
      backup = {
        enabled = true;
        consistency = "native-dump";
      };
    };
    copyparty-database-dump = {
      path = copypartyArtifact;
      scope = "system";
      stateClass = "derived";
      capabilities = [ "read" "write" ];
      backup.enabled = false;
    };
  }
  // lib.optionalAttrs cfg.syncthing.enable {
    syncthing-config = {
      path = nasInternal.syncthingConfigDir;
      scope = "system";
      stateClass = "authoritative";
      capabilities = [ "read" ];
      backup = {
        enabled = true;
        consistency = "filesystem";
      };
    };
  }
  // lib.optionalAttrs cfg.vaultwarden.enable {
    vaultwarden-data = {
      path = vaultwardenDataDir;
      scope = "system";
      stateClass = "authoritative";
      capabilities = [ "read" ];
      backup = {
        enabled = true;
        consistency = "native-dump";
      };
    };
    vaultwarden-dump = {
      path = vaultwardenBackupDir;
      scope = "system";
      stateClass = "derived";
      capabilities = [ "read" "write" ];
      backup.enabled = false;
    };
  };

  backupServices = {
    authentik-database-dump = {
      name = "Create a consistent Authentik PostgreSQL dump";
      managed = true;
      workload.kind = "job";
      runtime = {
        type = "systemd";
        unit = "nas-backup-authentik-dump.service";
      };
      storage = [
        {
          resource = "authentik-database";
          mountPath = config.services.postgresql.dataDir;
          access = "read";
        }
        {
          resource = "authentik-database-dump";
          mountPath = authentikArtifact;
          access = "write";
        }
      ];
    };
    copyparty-database-dump = {
      name = "Create consistent CopyParty SQLite dumps";
      managed = true;
      workload.kind = "job";
      runtime = {
        type = "systemd";
        unit = "nas-backup-copyparty-dump.service";
      };
      storage = [
        {
          resource = "copyparty-databases";
          mountPath = copypartyDataDir;
          access = "read";
        }
        {
          resource = "copyparty-database-dump";
          mountPath = copypartyArtifact;
          access = "write";
        }
      ];
    };
  } // lib.optionalAttrs cfg.vaultwarden.enable {
    vaultwarden-dump = {
      name = "Create a consistent Vaultwarden SQLite backup";
      managed = true;
      workload.kind = "job";
      runtime = {
        type = "systemd";
        unit = "backup-vaultwarden.service";
      };
      storage = [
        {
          resource = "vaultwarden-data";
          mountPath = vaultwardenDataDir;
          access = "read";
        }
        {
          resource = "vaultwarden-dump";
          mountPath = vaultwardenBackupDir;
          access = "write";
        }
      ];
    };
  };

  # --- platform services (Cockpit route) ---
  platformServices = {
    cockpit = {
      name = "Cockpit system administration";
      managed = false;
      workload = {
        kind = "daemon";
        activation = "persistent";
      };
      runtime = {
        type = "systemd";
        unit = "cockpit.socket";
      };
      authorization.capabilities = [
        { id = "admin"; title = "Administer the NAS with Cockpit"; }
      ];
      routes.console = {
        exposure = {
          type = "path";
          paths = [ "/console" ];
        };
        target = {
          type = "http";
          host = "127.0.0.1";
          port = cockpitPort;
        };
        auth = {
          mode = "identity";
          capability = "admin";
        };
        proxy.requestHeaders = {
          "X-Forwarded-Proto" = "https";
          "X-Forwarded-Prefix" = "/console";
        };
        portal = {
          visible = true;
          title = "System Console";
          category = "Administration";
          icon = "terminal";
          order = 5;
        };
      };
    };
  };

  mergedServices = baselineServices // operationServices // backupServices // platformServices;
  mergedStorageResources = backupResources;

  seedFile = yamlFormat.generate "managed-services-seed-v2.yaml" {
    schemaVersion = 3;
    services = mergedServices;
    storageResources = mergedStorageResources;
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
