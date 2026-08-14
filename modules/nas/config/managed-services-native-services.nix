{ config, lib, pkgs, nasInternal, ... }:

let
  cfg = config.nas;
  inherit (nasInternal) syncthingGuiPort vaultwardenPort;
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
    ;

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
      # V2 owns all externally reachable route ownership; native file contains no routes.
      # The file-transfer ACLs and WebDAV policy remain CopyParty-native.
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
        sync-tcp = portListener "tcp" 22000;
        sync-quic = portListener "udp" 22000;
        local-discovery = portListener "udp" 21027;
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
    };
    telegraf = (daemon "telegraf.service" "Telegraf metric collector") // {
      dependencies = [ (depends "victoriametrics" "started") ];
    };
  }
  // lib.optionalAttrs (cfg.observability.enable && cfg.alerting.enable) {
    alert-router = (daemon "nas-alert-router.service" "NAS alert router") // {
      authorization.capabilities = adminCapability "View alert routing";
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
    };
  }
  // lib.optionalAttrs cfg.observability.ntfy.enable {
    notifications = (daemon "ntfy-sh.service" "ntfy notification server");
  }
  // lib.optionalAttrs (cfg.power.ups.enable && cfg.power.ups.mode == "netserver") {
    ups-server = platformService ((daemon "upsd.service" "NUT UPS network server") // {
      listeners.nut = portListener "tcp" 3493;
    });
  }
  // lib.optionalAttrs (cfg.power.ups.enable && cfg.power.ups.web.enable) {
    ups-web = (onDemand "podman-nut-webgui.service" "NUT web interface" 600) // {
      authorization.capabilities = adminCapability "Administer UPS monitoring";
      readiness.probes = [ { type = "tcp"; port = cfg.power.ups.web.port; } ];
    };
  };

in
{
  # Seed generation is now centralized in managed-services-seed-v2.nix which
  # produces one complete V3 document containing baseline services, operations,
  # backup resources, and platform routes. This module retains only native
  # service definitions; it no longer contributes a separate seed file.
}
