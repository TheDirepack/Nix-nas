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
  systemdProjectionPath = "/run/nas-control/systemd";
  firewalldProjectionPath = "/run/nas-control/firewalld";
  backupInventoryPath = "/run/nas-control/backup-resources.json";
  resticPathsPath = "/run/nas-control/restic-v2-paths";
  quadletRuntimePath = "/run/containers/systemd";
  authentikPort = nasInternal.authentikPort;
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

  seedDesiredState = pkgs.writeShellScript "nas-managed-services-v2-seed" ''
    set -euo pipefail

    ${pkgs.coreutils}/bin/install -d -m 0750 -o root -g nas-operations ${zfsControlRoot}
    ${pkgs.coreutils}/bin/install -d -m 0750 -o root -g nas-operations ${zfsControlRoot}/apps

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
  '';
in
{
  config = {
    systemd.tmpfiles.rules = [
      "L+ /var/lib/nas-control - - - - ${zfsControlRoot}"
      "d ${zfsControlRoot} 0750 root nas-operations -"
      "d ${zfsControlRoot}/apps 0750 root nas-operations -"
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
        ReadWritePaths = [ zfsControlRoot "/var/lib/nas-control" ];
      };
    };

    # This unit is intentionally only the finite compile entry point. Native
    # subsystem activation/rollback belongs to managed-services-transactions;
    # generation publication belongs to managed-services-generations.
    systemd.services.nas-managed-services-reconcile = {
      description = "Compile and activate Managed Services V2 desired state";
      wantedBy = [ "multi-user.target" ];
      requires = [
        "nas-managed-services-seed.service"
        "nas-zfs-mount-guard.service"
      ] ++ lib.optional firewalldEnabled "firewalld.service";
      after = [
        "nas-managed-services-seed.service"
        "nas-zfs-mount-guard.service"
      ] ++ lib.optional firewalldEnabled "firewalld.service";
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
        # Authentik's embedded outpost is served by the main loopback listener;
        # a second proxy-outpost daemon/listener only duplicated Authentik.
        NAS_V2_AUTHENTIK_UPSTREAM = "127.0.0.1:${toString authentikPort}";
        NAS_V2_AUTHENTIK_PATH = cfg.identity.authentikPath;
        NAS_V2_LAN_HOST = nasInternal.lanHost;
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
        exec ${v2Python}/bin/python ${v2Source}/nas_v2_entry.py
      '';
      serviceConfig = {
        Type = "oneshot";
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
        ];
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

    # The concrete Authentik implementation is supplied by the blueprint
    # adapter module. Keep only lifecycle/hardening shared by that finite job.
    systemd.services.nas-managed-services-authentik-reconcile = {
      description = "Apply Managed Services V2 Authentik projection";
      wantedBy = [ "nas-protected-services.target" ];
      partOf = [ "nas-protected-services.target" ];
      requires = [ "nas-identity-sync.service" ];
      after = [
        "nas-identity-sync.service"
        "nas-managed-services-reconcile.service"
      ];
      environment.PYTHONPATH = "${v2Source}";
      serviceConfig = {
        Type = "oneshot";
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
        RestrictAddressFamilies = [ "AF_UNIX" ];
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
      };
    };

    systemd.paths.nas-managed-services-authentik-reconcile = {
      description = "Watch V2 generation changes for Authentik projection";
      wantedBy = [ "nas-protected-services.target" ];
      partOf = [ "nas-protected-services.target" ];
      pathConfig = {
        PathChanged = effectivePath;
        Unit = "nas-managed-services-authentik-reconcile.service";
      };
    };

    # Reconciliation is optional during bootstrap. Caddy cannot require it:
    # managed services may need Caddy's CA before their state is available.
    systemd.services.caddy.wants = [
      "nas-managed-services-reconcile.service"
      "nas-managed-services-authentik-reconcile.service"
    ];
  };
}
