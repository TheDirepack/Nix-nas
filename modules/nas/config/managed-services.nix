{ config, lib, pkgs, nasInternal, ... }:

let
  cfg = config.nas;
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
  backupInventoryPath = "/run/nas-control/backup-resources.json";
  resticPathsPath = "/run/nas-control/restic-v2-paths";
  quadletRuntimePath = "/run/containers/systemd";
  authentikApiTokenFile = nasInternal.authentikApiTokenFile;
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
    "${v2Source}/nas_v2_cli.py"
    "apply"
    "--spec"
    desiredPath
    "--schema"
    schemaPath
    "--platform"
    platformPath
    "--effective"
    effectivePath
    "--plan"
    planPath
    "--portal-output"
    portalPath
    "--caddy-output"
    caddyManagedPath
    "--caddy-bin"
    "${pkgs.caddy}/bin/caddy"
    "--authentik-upstream"
    "127.0.0.1:${toString nasInternal.authentikPort}"
    "--authentik-path"
    cfg.identity.authentikPath
    "--lan-host"
    nasInternal.lanHost
    "--wake-socket"
    wakeSocketPath
    "--systemd-output"
    systemdProjectionPath
    "--systemd-analyze-bin"
    "${pkgs.systemd}/bin/systemd-analyze"
    "--systemctl-bin"
    "${pkgs.systemd}/bin/systemctl"
    "--python-bin"
    "${v2Python}/bin/python"
    "--uv-bin"
    "${pkgs.uv}/bin/uv"
    "--quadlet-generator-bin"
    "${pkgs.podman}/lib/systemd/system-generators/podman-system-generator"
    "--podman-bin"
    "${pkgs.podman}/bin/podman"
    "--compose-provider-bin"
    "${pkgs.podman-compose}/bin/podman-compose"
    "--virsh-bin"
    "${pkgs.libvirt}/bin/virsh"
    "--virt-xml-validate-bin"
    "${pkgs.libvirt}/bin/virt-xml-validate"
    "--backup-inventory"
    backupInventoryPath
    "--restic-paths"
    resticPathsPath
    "--v2-source"
    "${v2Source}"
  ] ++ lib.optionals firewalldEnabled [
    "--firewalld-output"
    firewalldProjectionPath
    "--firewalld-lan-zone"
    cfg.networking.firewall.zone
    "--firewall-offline-cmd"
    "${firewalldPackage}/bin/firewall-offline-cmd"
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
    "${v2Source}/nas_v2_firewalld_reconcile.py"
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
  seedDesiredState = pkgs.writeShellScript "nas-managed-services-v2-seed" ''
    set -euo pipefail

    ${pkgs.coreutils}/bin/install -d -m 0750 -o root -g nas-operations /var/lib/nas-control
    ${pkgs.coreutils}/bin/install -d -m 0750 -o root -g nas-operations /var/lib/nas-control/apps
    ${pkgs.coreutils}/bin/install -d -m 0755 -o root -g root /var/lib/nas-control/venvs

    if [ ! -e ${lib.escapeShellArg desiredPath} ]; then
      tmp="$(${pkgs.coreutils}/bin/mktemp /var/lib/nas-control/.services.yaml.XXXXXX)"
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
  '';
in
{
  config = {
    systemd.tmpfiles.rules = [
      "d /var/lib/nas-control 0750 root nas-operations -"
      "d /var/lib/nas-control/apps 0750 root nas-operations -"
      "d /var/lib/nas-control/venvs 0755 root root -"
      "d /run/nas-control 0755 root root -"
      "d /run/containers 0755 root root -"
      "d /run/containers/systemd 0755 root root -"
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
        ReadWritePaths = [ "/var/lib/nas-control" ];
      };
    };

    systemd.services.nas-managed-services-reconcile = {
      description = "Compile and activate Managed Services V2 desired state";
      wantedBy = [ "multi-user.target" ];
      requires = [ "nas-managed-services-seed.service" ] ++ lib.optional firewalldEnabled "firewalld.service";
      after = [ "nas-managed-services-seed.service" ] ++ lib.optional firewalldEnabled "firewalld.service";
      before = [ "caddy.service" ];
      environment.PYTHONPATH = "${v2Source}";
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
          "/var/lib/nas-control"
          "/run/nas-control"
          "/run/systemd/system"
          quadletRuntimePath
        ] ++ lib.optional firewalldEnabled firewalldSystemConfig;
      };
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
      before = [ "caddy.service" ];
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

    systemd.services.caddy = {
      requires = [
        "nas-managed-services-reconcile.service"
        "nas-managed-services-authentik-reconcile.service"
        "nas-managed-services-wake.socket"
      ];
      after = [
        "nas-managed-services-reconcile.service"
        "nas-managed-services-authentik-reconcile.service"
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
  };
}
