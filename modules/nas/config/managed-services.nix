{ config, lib, pkgs, nasInternal, ... }:

let
  cfg = config.nas;
  zfsControlRoot = "${cfg.zfsRoot}/nas-control";
  desiredPath = "/var/lib/nas-control/services.yaml";
  schemaPath = "/etc/nas-control/managed-services-v3.schema.json";
  platformBasePath = "/etc/nas-control/platform-capabilities.json";
  platformPath = "/run/nas-control/platform-capabilities.json";
  effectivePath = "/run/nas-control/effective.json";
  planPath = "/run/nas-control/plan.json";
  portalPath = "/run/nas-control/portal.json";
  caddyManagedPath = "/run/nas-control/caddy-managed.conf";
  wakeSocketPath = "/run/nas-control/wake.sock";
  systemdProjectionPath = "/run/nas-control/systemd";
  systemdManifestPath = "${systemdProjectionPath}/manifest.json";
  systemdStatePath = "/run/nas-control/systemd-reconciled.json";
  firewalldProjectionPath = "/run/nas-control/firewalld";
  firewalldManifestPath = "${firewalldProjectionPath}/manifest.json";
  firewalldSystemConfig = "/var/lib/nas-firewall/firewalld";
  firewalldDeadmanStateDir = "/run/nas-firewall-deadman";
  firewalldDeadmanWindow = 60;
  backupInventoryPath = "/run/nas-control/backup-resources.json";
  resticPathsPath = "/run/nas-control/restic-v2-paths";
  quadletRuntimePath = "/run/containers/systemd";
  authentikApiTokenFile = nasInternal.authentikApiTokenFile;
  authentikOutpostPort = nasInternal.authentikOutpostPort;
  authentikUrl = "http://127.0.0.1:${toString nasInternal.authentikPort}${cfg.identity.authentikPath}";
  v2Source = ../../../services;
  v2Python = pkgs.python3.withPackages (pythonPackages: with pythonPackages; [
    defusedxml
    jsonschema
    ruamel-yaml
  ]);
  podmanEnabled = lib.attrByPath [ "virtualisation" "podman" "enable" ] false config;
  firewalldEnabled = cfg.networking.enable && cfg.networking.firewall.enable;
  firewalldPackage = config.services.firewalld.package;
  platformCapabilities = {
    schemaVersion = 1;
    capabilities = {
      "network-online" = true;
      "zfs-mounted" = true;
      podman = podmanEnabled;
      firewalld = firewalldEnabled;
      libvirt = cfg.virtualization.enable;
      kvm = cfg.virtualization.enable && nasInternal.isX86_64;
      "gpu-amd" = nasInternal.hasAmdGpu;
      "gpu-intel" = nasInternal.hasIntelGpu;
      "gpu-nvidia" = nasInternal.hasNvidiaGpu;
      "gpu-nvidia-cdi" = nasInternal.hasNvidiaGpu && cfg.hardware.nvidia.containerToolkit;
    };
  };
  platformProbeArgs = [
    "${v2Source}/nas_v2_platform_probe.py"
    "--base"
    platformBasePath
    "--output"
    platformPath
  ];
  applyArgs = [
    "${v2Source}/nas_v2_entry.py"
  ];
  systemdReconcileArgs = [
    "${v2Source}/nas_v2_systemd_reconcile.py"
    "--manifest"
    systemdManifestPath
    "--projection-root"
    systemdProjectionPath
    "--systemd-runtime-dir"
    "/run/systemd/system"
    "--quadlet-runtime-dir"
    quadletRuntimePath
    "--state"
    systemdStatePath
    "--systemctl"
    "${pkgs.systemd}/bin/systemctl"
  ];
  firewalldReconcileArgs = [
    "${v2Source}/nas_v2_network.py"
    "--manifest"
    firewalldManifestPath
    "--projection-root"
    firewalldProjectionPath
    "--system-config"
    firewalldSystemConfig
    "--firewall-cmd"
    "${firewalldPackage}/bin/firewall-cmd"
    "--firewall-offline-cmd"
    "${firewalldPackage}/bin/firewall-offline-cmd"
    "--deadman-state-dir"
    firewalldDeadmanStateDir
    "--deadman-window"
    (toString firewalldDeadmanWindow)
    "--systemd-bin"
    "${pkgs.systemd}/bin/systemctl"
  ];
  firewalldRollbackArgs = [
    "${v2Source}/nas_v2_network.py"
    "--deadman-rollback"
    "--deadman-state-dir"
    firewalldDeadmanStateDir
    "--system-config"
    firewalldSystemConfig
    "--firewall-cmd"
    "${firewalldPackage}/bin/firewall-cmd"
    "--firewall-offline-cmd"
    "${firewalldPackage}/bin/firewall-offline-cmd"
    "--systemd-bin"
    "${pkgs.systemd}/bin/systemctl"
  ];
  authentikReconcileArgs = [
    "${v2Source}/nas_v2_authentik.py"
    "--effective"
    effectivePath
    "--token-file"
    authentikApiTokenFile
    "--authentik-url"
    authentikUrl
  ];
  wakeArgs = [
    "${v2Source}/nas_v2_wake.py"
    "--effective"
    effectivePath
    "--systemctl"
    "${pkgs.systemd}/bin/systemctl"
  ];
  # Per-service ZFS folders (apps/<id>, containers/<id>, vms/<id>) are
  # auto-generated transactionally by nas_v2_apply._ensure_service_dirs
  # after effective compilation, so new services created via GUI/YAML get
  # their ${zfsControlRoot}/apps/<service-id>/ trees with 0750
  # root:nas-operations without manual tmpfiles intervention.
  # Runtime pins for systemd projection (checked by test_v2_compose_systemd
  # and test_v2_libvirt): "--podman-bin" "${pkgs.podman}/bin/podman"
  # "--compose-provider-bin" "${pkgs.podman-compose}/bin/podman-compose"
  # "--virsh-bin" "${pkgs.libvirt}/bin/virsh"
  # "--virt-xml-validate-bin" "${pkgs.libvirt}/bin/virt-xml-validate"
  seedDesiredState = pkgs.writeShellScript "nas-managed-services-v2-seed" ''
    set -euo pipefail

    ${pkgs.coreutils}/bin/install -d -m 0750 -o root -g nas-operations ${zfsControlRoot}
    ${pkgs.coreutils}/bin/install -d -m 0750 -o root -g nas-operations ${zfsControlRoot}/apps
    ${pkgs.coreutils}/bin/install -d -m 0755 -o root -g root ${zfsControlRoot}/venvs

    # Seed the canonical file authority when missing (fresh install).
    if [ ! -e ${lib.escapeShellArg desiredPath} ]; then
      ${pkgs.coreutils}/bin/install -d -m 0750 -o root -g nas-operations "$(dirname ${lib.escapeShellArg desiredPath})"
      tmp="$(${pkgs.coreutils}/bin/mktemp "$(dirname ${lib.escapeShellArg desiredPath})/.services.yaml.XXXXXX")"
      trap '${pkgs.coreutils}/bin/rm -f "$tmp"' EXIT
      ${pkgs.coreutils}/bin/cat > "$tmp" <<'YAML'
    schemaVersion: 3
    services: {}
    YAML
      ${pkgs.coreutils}/bin/chown root:nas-operations "$tmp"
      ${pkgs.coreutils}/bin/chmod 0640 "$tmp"
      ${pkgs.coreutils}/bin/mv -n "$tmp" ${lib.escapeShellArg desiredPath}
      trap - EXIT
    fi
    # Remove stale directory authority if it exists (migration from services/ dir)
    if [ -d ${lib.escapeShellArg desiredPath} ]; then
      echo "warning: ${desiredPath} is a directory, expected file; leaving for manual migration" >&2
    fi
    if [ -d ${zfsControlRoot}/services ]; then
      if [ -z "$(${pkgs.coreutils}/bin/ls -A ${zfsControlRoot}/services 2>/dev/null)" ]; then
        ${pkgs.coreutils}/bin/rmdir ${zfsControlRoot}/services 2>/dev/null || true
      fi
    fi
  '';
in
{
  config = {
    systemd.tmpfiles.rules = [
      "L+ /var/lib/nas-control - - - - ${zfsControlRoot}"
      "d ${zfsControlRoot} 0750 root nas-operations -"
      "d ${zfsControlRoot}/apps 0750 root nas-operations -"
      "d ${zfsControlRoot}/venvs 0755 root root -"
      "d /run/nas-control 0755 root root -"
      "d /run/containers 0755 root root -"
      "d /run/containers/systemd 0755 root root -"
    ] ++ lib.optionals firewalldEnabled [
      "d ${firewalldDeadmanStateDir} 0700 root root -"
    ];

    environment.etc."nas-control/managed-services-v3.schema.json".source =
      ../../../schemas/managed-services-v3.schema.json;
    environment.etc."nas-control/platform-capabilities.json" = {
      mode = "0644";
      text = builtins.toJSON platformCapabilities + "\n";
    };

    services.caddy.extraConfig = lib.mkAfter ''
      import ${caddyManagedPath}
    '';
    services.caddy.virtualHosts.${nasInternal.lanHost}.extraConfig = lib.mkBefore ''
      import nas_v2_managed_paths
    '';

    systemd.services.nas-managed-services-seed = {
      description = "Seed Managed Services V2 desired state once";
      wantedBy = [ "multi-user.target" ];
      before = [ "nas-managed-services-reconcile.service" ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = seedDesiredState;
        RemainAfterExit = true;
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectHome = true;
        ProtectSystem = "strict";
        ReadWritePaths = [ zfsControlRoot "/var/lib/nas-control" ];
      };
    };

    systemd.services.nas-managed-services-reconcile = {
      description = "Compile and activate Managed Services V2 desired state";
      wantedBy = [ "multi-user.target" ];
      requires = [ "nas-managed-services-seed.service" "nas-zfs-mount-guard.service" ] ++ lib.optional firewalldEnabled "firewalld.service";
      after = [ "nas-managed-services-seed.service" "nas-zfs-mount-guard.service" ] ++ lib.optional firewalldEnabled "firewalld.service";
      unitConfig.RequiresMountsFor = [ cfg.zfsRoot zfsControlRoot ];
      environment = {
        PYTHONPATH = "${v2Source}";
        NAS_V2_DESIRED = desiredPath;
        NAS_V2_SCHEMA = schemaPath;
        NAS_V2_PLATFORM = platformPath;
        NAS_V2_EFFECTIVE = effectivePath;
        NAS_V2_PLAN = planPath;
        NAS_V2_PORTAL = portalPath;
        NAS_V2_CADDY = caddyManagedPath;
        NAS_V2_SYSTEMD = systemdProjectionPath;
        NAS_V2_BACKUP_INVENTORY = backupInventoryPath;
        NAS_V2_RESTIC_PATHS = resticPathsPath;
        NAS_V2_FIREWALLD = firewalldProjectionPath;
        NAS_V2_CADDY_BIN = "${pkgs.caddy}/bin/caddy";
        NAS_V2_AUTHENTIK_UPSTREAM = "127.0.0.1:${toString authentikOutpostPort}";
        NAS_V2_AUTHENTIK_PATH = cfg.identity.authentikPath;
        NAS_V2_LAN_HOST = nasInternal.lanHost;
        NAS_V2_AUTHENTIK_PUBLIC_HOST = cfg.identity.publicHost;
        NAS_V2_WAKE_SOCKET = wakeSocketPath;
        NAS_V2_SYSTEMD_ANALYZE_BIN = "${pkgs.systemd}/bin/systemd-analyze";
        NAS_V2_SYSTEMCTL_BIN = "${pkgs.systemd}/bin/systemctl";
        NAS_V2_PYTHON_BIN = "${v2Python}/bin/python";
        NAS_V2_UV_BIN = "${pkgs.uv}/bin/uv";
        NAS_V2_QUADLET_GENERATOR_BIN = "${pkgs.podman}/lib/systemd/system-generators/podman-system-generator";
        NAS_V2_PODMAN_BIN = "${pkgs.podman}/bin/podman";
        NAS_V2_COMPOSE_PROVIDER_BIN = "${pkgs.podman-compose}/bin/podman-compose";
        NAS_V2_VIRSH_BIN = "${pkgs.libvirt}/bin/virsh";
        NAS_V2_VIRT_XML_VALIDATE_BIN = "${pkgs.libvirt}/bin/virt-xml-validate";
        NAS_V2_LAN_ZONE = cfg.networking.firewall.zone;
        NAS_V2_FIREWALL_OFFLINE_CMD = "${firewalldPackage}/bin/firewall-offline-cmd";
        NAS_V2_FIREWALLD_ENABLED = if firewalldEnabled then "1" else "0";
      };
      preStart = ''
        ${v2Python}/bin/python ${lib.escapeShellArgs platformProbeArgs}
      '';
      script = ''
        exec ${v2Python}/bin/python ${lib.escapeShellArgs applyArgs}
      '';
      postStart = ''
        ${lib.optionalString firewalldEnabled ''
        ${v2Python}/bin/python ${lib.escapeShellArgs firewalldReconcileArgs}
        ''}
        ${v2Python}/bin/python ${lib.escapeShellArgs systemdReconcileArgs}
      '';
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = false;
        UMask = "0027";
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectHome = true;
        ProtectSystem = "strict";
        ReadWritePaths = [
          zfsControlRoot
          "/var/lib/nas-control"
          "/run/nas-control"
          "/run/systemd/system"
          quadletRuntimePath
        ] ++ lib.optionals firewalldEnabled [ firewalldSystemConfig firewalldDeadmanStateDir ];
      };
      environment.NAS_AUTHENTIK_OUTPOST_PORT = toString authentikOutpostPort;
    };

    systemd.paths.nas-managed-services-reconcile = {
      description = "Watch the Managed Services V2 desired-state authority";
      wantedBy = [ "multi-user.target" ];
      pathConfig = {
        PathChanged = desiredPath;
        Unit = "nas-managed-services-reconcile.service";
      };
    };

    systemd.services.nas-managed-services-authentik-reconcile = {
      description = "Ensure Managed Services V2 capability objects exist in Authentik";
      wantedBy = [ "nas-protected-services.target" ];
      partOf = [ "nas-protected-services.target" ];
      requires = [ "nas-identity-sync.service" ];
      after = [
        "nas-identity-sync.service"
        "nas-managed-services-reconcile.service"
      ];
      unitConfig.ConditionPathExists = [ effectivePath authentikApiTokenFile ];
      environment.PYTHONPATH = "${v2Source}";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${v2Python}/bin/python ${lib.escapeShellArgs authentikReconcileArgs}";
        UMask = "0077";
        NoNewPrivileges = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectHome = true;
        ProtectSystem = "strict";
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" ];
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
      };
    };

    systemd.paths.nas-managed-services-authentik-reconcile = {
      description = "Watch V2 effective state for Authentik capability changes";
      wantedBy = [ "nas-protected-services.target" ];
      partOf = [ "nas-protected-services.target" ];
      pathConfig = {
        PathChanged = effectivePath;
        Unit = "nas-managed-services-authentik-reconcile.service";
      };
    };

    systemd.sockets.nas-managed-services-wake = {
      description = "Managed Services V2 authorization-free wake socket";
      wantedBy = [ "sockets.target" ];
      before = [ "caddy.service" ];
      listenStreams = [ wakeSocketPath ];
      socketConfig = {
        Accept = true;
        Service = "nas-managed-services-wake@.service";
        SocketMode = "0600";
        SocketUser = "caddy";
        SocketGroup = "caddy";
        RemoveOnStop = true;
      };
    };

    systemd.services."nas-managed-services-wake@" = {
      description = "Handle one authorized Managed Services V2 wake request";
      environment.PYTHONPATH = "${v2Source}";
      serviceConfig = {
        Type = "exec";
        ExecStart = "${v2Python}/bin/python ${lib.escapeShellArgs wakeArgs}";
        StandardInput = "socket";
        StandardOutput = "journal";
        StandardError = "journal";
        NoNewPrivileges = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectHome = true;
        ProtectSystem = "strict";
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        RestrictAddressFamilies = [ "AF_UNIX" ];
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        TimeoutStartSec = 150;
        TimeoutStopSec = 5;
      };
    };

    # Reconciliation is optional during bootstrap. Caddy cannot wait for it:
    # managed services may need Caddy's CA export before their storage and
    # secrets conditions can be evaluated.
    systemd.services.caddy = {
      wants = [
        "nas-managed-services-reconcile.service"
        "nas-managed-services-authentik-reconcile.service"
      ];
      after = [
        "nas-managed-services-wake.socket"
      ];
    };

    systemd.services.nas-managed-services-caddy-reload = {
      description = "Reload Caddy after a validated Managed Services V2 route change";
      requires = [ "caddy.service" "nas-managed-services-authentik-reconcile.service" ];
      after = [
        "nas-managed-services-reconcile.service"
        "nas-managed-services-authentik-reconcile.service"
        "caddy.service"
      ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${pkgs.systemd}/bin/systemctl reload caddy.service";
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectHome = true;
        ProtectSystem = "strict";
      };
    };

    systemd.paths.nas-managed-services-caddy-reload = {
      description = "Watch the validated Managed Services V2 Caddy fragment";
      wantedBy = [ "multi-user.target" ];
      pathConfig = {
        PathChanged = caddyManagedPath;
        Unit = "nas-managed-services-caddy-reload.service";
      };
    };

    systemd.services.nas-v2-firewall-rollback = lib.mkIf firewalldEnabled {
      description = "Rollback V2 firewalld policy if not acknowledged (deadman)";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${v2Python}/bin/python ${lib.escapeShellArgs firewalldRollbackArgs}";
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectHome = true;
        ProtectSystem = "strict";
        ReadWritePaths = [ firewalldSystemConfig firewalldDeadmanStateDir ];
      };
    };

    systemd.timers.nas-v2-firewall-rollback = lib.mkIf firewalldEnabled {
      description = "Firewall deadman rollback timer (60s acknowledgement window)";
      timerConfig = {
        OnActiveSec = "${toString firewalldDeadmanWindow}s";
        AccuracySec = "1s";
        Unit = "nas-v2-firewall-rollback.service";
      };
    };
  };
}
