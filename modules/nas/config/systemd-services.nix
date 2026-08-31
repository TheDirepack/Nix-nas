{ config, lib, pkgs, nasInternal, ... }:

let
  inherit (nasInternal)
    authentikApiTokenFile
    authentikDataDir
    authentikEnvironmentFile
    authentikRuntimeApiTokenFile
    authentikRuntimeEnvironmentFile
    authentikPort
    bootstrapUsername
    bootstrapPassword
    caddyBackendUnits
    caddyCaExportDir
    caddyCaExportPath
    caddyInternalCaPath
    cfg
    copypartyDataDir
    copypartyMountRoot
    failureAlert
    nasAlert
    nasIdentitySync
    nasPythonApplication
    nasSetup
    nasUpdate
    nasZfsMountCheck
    nasZfsUnlock
    observabilitySecretDir
    postgresqlDataDir
    powerSecretDir
    sanoidMonitorConfig
    secretRoot
    shareRoot
    syncthingDataDir
    syncthingGuiPort
    vaultwardenBackupDir
    vaultwardenDataDir
    vaultwardenSecretDir
    vmStoragePath
    zfsKeyPath
  ;
in
{
  config.systemd.services = {
    nas-bootstrap-administrator = lib.mkIf cfg.firstStart.enable {
      description = "Create the disposable local administrator for first-run setup";
      wantedBy = [ "multi-user.target" ];
      before = [ "nas-first-start.service" ];
      unitConfig.ConditionPathExists = "!/var/lib/nas-setup/state.json";
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = pkgs.writeShellScript "nas-bootstrap-administrator" ''
          set -euo pipefail
          if ! ${pkgs.glibc.bin}/bin/getent passwd ${bootstrapUsername} >/dev/null 2>&1; then
            ${pkgs.shadow}/bin/useradd --create-home --shell /run/current-system/sw/bin/bash ${bootstrapUsername} || {
              rc=$?
              [[ "$rc" -eq 9 ]] || exit "$rc"
            }
          fi
          printf '%s\n' '${bootstrapUsername}:${bootstrapPassword}' | ${pkgs.shadow}/bin/chpasswd
          ${pkgs.shadow}/bin/usermod --append --groups wheel,nas-administrators,nas-operations ${bootstrapUsername}
        '';
        NoNewPrivileges = false;
        UMask = "0077";
      };
    };

    nas-first-start = lib.mkIf cfg.firstStart.enable {
      description = "Prepare the automatic NixOS NAS first-start workflow";
      wantedBy = [ "multi-user.target" ];
      wants = [ "nas-bootstrap-administrator.service" ];
      after = [ "nas-bootstrap-administrator.service" "local-fs.target" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        StateDirectory = "nas-first-start";
        StateDirectoryMode = "0755";
        ExecStart = "${nasSetup}/bin/nas-setup prepare-first-start --config ${lib.escapeShellArg cfg.firstStart.configFile}";
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ReadOnlyPaths = [ "-${cfg.firstStart.configFile}" ];
        ReadWritePaths = [ "/var/lib/nas-first-start" ];
        RestrictAddressFamilies = [ "AF_UNIX" ];
        UMask = "0022";
      };
    };

    nas-protected-restart = {
      description = "Restart protected NAS services under the shared operation coordinator";
      wantedBy = lib.mkOverride 90 [ ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${nasPythonApplication}/bin/nas-operation-run --action protected-restart --class identity --class runtime -- ${pkgs.systemd}/bin/systemctl restart nas-protected-services.target";
        NoNewPrivileges = false;
      };
    };

    nas-zfs-unlock = lib.mkIf cfg.zfsEncryption.enable {
      description = "Unlock the KeePassXC-managed NAS ZFS encryption root";
      wantedBy = lib.mkOverride 90 [ ];
      partOf = [ "nas-protected-services.target" ];
      requires = [ "zfs.target" ];
      after = [ "zfs.target" ];
      before = [ "nas-zfs-mount-guard.service" ];
      unitConfig.ConditionPathExists = [ zfsKeyPath "${secretRoot}/ready" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${nasZfsUnlock}/bin/nas-zfs-unlock";
        NoNewPrivileges = false;
      };
    };

    nas-zfs-mount-guard = {
      description = "Verify the exact NAS ZFS dataset and mountpoint";
      partOf = [ "nas-protected-services.target" ];
      wants = [ "zfs.target" ];
      requires = lib.optional cfg.zfsEncryption.enable "nas-zfs-unlock.service";
      after = [ "zfs.target" ] ++ lib.optional cfg.zfsEncryption.enable "nas-zfs-unlock.service";
      unitConfig = {
        RequiresMountsFor = lib.optional (!cfg.zfsEncryption.enable) cfg.zfsRoot;
        AssertPathIsMountPoint = cfg.zfsRoot;
        ConditionPathExists = [ "/var/lib/nas-setup/state.json" ];
      };
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${nasZfsMountCheck}/bin/nas-zfs-mount-check";
        # The dataset may be created after boot (first-run setup creates the
        # pool and mounts it at runtime), in which case the boot-time tmpfiles
        # pass only materialized ${cfg.zfsRoot}/* as plain root-filesystem
        # directories that the new mount shadows. Re-apply the rules scoped to
        # the ZFS root so per-type app directories (postgresql, authentik,
        # nas-control, ...) exist behind the mount before any protected
        # service starts. Idempotent; no-op when the dirs already exist.
        ExecStartPost = "${pkgs.systemd}/bin/systemd-tmpfiles --create --prefix ${cfg.zfsRoot}";
      };
    };

    postgresql = {
      wantedBy = lib.mkOverride 90 [ ];
      partOf = [ "nas-protected-services.target" ];
      before = [ "authentik-migrate.service" ];
      requires = [ "nas-bootstrap-runtime-select.service" ];
      after = [ "nas-bootstrap-runtime-select.service" ];
      unitConfig.RequiresMountsFor = [ ];
    };

    authentik-migrate = {
      onFailure = failureAlert;
      # The first-boot Authentik runtime exists before protected secrets are
      # activated. Enable the bootstrap transaction directly so it cannot be
      # skipped when Caddy is already running during a generation switch.
      wantedBy = lib.mkOverride 90 [ "multi-user.target" ];
      partOf = [ "nas-protected-services.target" ];
      unitConfig.ConditionPathExists = authentikRuntimeEnvironmentFile;
    };

    authentik-worker = {
      onFailure = failureAlert;
      wantedBy = lib.mkOverride 90 [ "multi-user.target" ];
      partOf = [ "nas-protected-services.target" ];
      unitConfig.ConditionPathExists = authentikRuntimeEnvironmentFile;
    };

    authentik = {
      onFailure = failureAlert;
      wantedBy = lib.mkOverride 90 [ "multi-user.target" ];
      partOf = [ "nas-protected-services.target" ];
      unitConfig.ConditionPathExists = authentikRuntimeEnvironmentFile;
    };

    nas-identity-bootstrap = {
      description = "Reconcile the Authentik portal provider before starting its proxy outpost";
      # Authentik is ordered after runtime selection, which creates the token
      # this unit requires. Starting from multi-user.target races that token.
      wantedBy = [ "authentik.service" ];
      requires = [ "authentik.service" ];
      after = [ "authentik.service" ];
      unitConfig.ConditionPathExists = [
        authentikRuntimeApiTokenFile
        "!/var/lib/nas-setup/state.json"
      ];
      environment = {
        NAS_AUTHENTIK_BOOTSTRAP_TOKEN_FILE = authentikRuntimeApiTokenFile;
        NAS_PUBLIC_HOST = cfg.identity.publicHost;
      };
      serviceConfig = {
        Type = "oneshot";
        ExecStart = pkgs.writeShellScript "nas-identity-bootstrap" ''
          set -u
          ${nasPythonApplication}/bin/nas-operation-run \
            --action identity-bootstrap --class identity --class runtime -- \
            ${nasIdentitySync}/bin/nas-identity-sync bootstrap
          rc=$?
          # An active first-start transaction owns bootstrap reconciliation.
          # Treat its lock as a successful handoff so protected-service startup
          # cannot wait on the transaction that is waiting for this unit.
          [[ "$rc" -eq 0 || "$rc" -eq 75 ]] && exit 0
          exit "$rc"
        '';
        ExecStartPost = "${pkgs.systemd}/bin/systemctl start --no-block nas-authentik-proxy-outpost.service";
        Restart = "on-failure";
        RestartSec = "5s";
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectHome = true;
        ProtectSystem = "strict";
        ReadWritePaths = [ "/run/lock" "/run/nas-operations" ];
        RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" ];
        UMask = "0077";
      };
    };

    nas-identity-sync = {
      description = "Bootstrap and validate Authentik NAS identity policy";
      wantedBy = lib.mkOverride 90 [ ];
      partOf = [ "nas-protected-services.target" ];
      requires = [ "authentik.service" ];
      after = [ "authentik.service" ];
      unitConfig.ConditionPathExists = [
        "${secretRoot}/ready"
        authentikApiTokenFile
        "/var/lib/nas-setup/state.json"
        "/run/nas-control/effective.json"
      ];
      serviceConfig = {
        Type = "oneshot";
        # Authentik restarts and feature reconciliation can briefly hold the
        # runtime operation class. Retry the timer-triggered validation after
        # that transient coordination conflict instead of leaving the target
        # failed until the next timer tick.
        Restart = "on-failure";
        RestartSec = "5s";
        ExecStart = [
          "${nasIdentitySync}/bin/nas-identity-sync bootstrap"
          "${nasIdentitySync}/bin/nas-identity-sync status"
        ];
        UMask = "0077";
      };
      environment.NAS_PUBLIC_HOST = cfg.identity.publicHost;
    };

    nas-copyparty-share-root = {
      description = "Prepare the ZFS-backed CopyParty share root";
      partOf = [ "nas-protected-services.target" ];
      before = [ "copyparty.service" ];
      requires = [ "nas-zfs-mount-guard.service" ];
      after = [ "nas-zfs-mount-guard.service" ];
      unitConfig = {
        RequiresMountsFor = lib.optional (!cfg.zfsEncryption.enable) cfg.zfsRoot;
        ConditionPathIsMountPoint = cfg.zfsRoot;
      };
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = [
          "${pkgs.coreutils}/bin/install -d -m 2770 -o copyparty -g copyparty ${lib.escapeShellArg shareRoot}"
          "${pkgs.coreutils}/bin/install -d -m 2770 -o copyparty -g copyparty ${lib.escapeShellArg (shareRoot + "/admin")}"
          "${pkgs.coreutils}/bin/install -d -m 2770 -o copyparty -g copyparty ${lib.escapeShellArg (shareRoot + "/users")}"
        ] ++ lib.optional cfg.tftp.enable
          "${pkgs.coreutils}/bin/install -d -m 2770 -o copyparty -g copyparty ${lib.escapeShellArg (shareRoot + "/tftp")}";
      };
    };

    copyparty = {
      onFailure = failureAlert;
      wantedBy = lib.mkOverride 90 [ ];
      partOf = [ "nas-protected-services.target" ];
      requires = [ "nas-copyparty-share-root.service" ];
      after = [ "nas-copyparty-share-root.service" ];
      unitConfig = {
        RequiresMountsFor = [ cfg.zfsRoot copypartyDataDir ];
        ConditionPathExists = "${secretRoot}/ready";
        ConditionPathIsMountPoint = cfg.zfsRoot;
      };
      serviceConfig = {
        RuntimeDirectoryMode = lib.mkOverride 90 "0750";
        UMask = lib.mkForce "0007";
        ExecStartPre = lib.mkBefore (
          [
            "+${pkgs.coreutils}/bin/install -d -m 2770 -o copyparty -g copyparty ${lib.escapeShellArg shareRoot}"
            "+${pkgs.coreutils}/bin/install -d -m 2770 -o copyparty -g copyparty ${lib.escapeShellArg (shareRoot + "/users")}"
          ]
          ++ lib.optional cfg.tftp.enable
            "+${pkgs.coreutils}/bin/install -d -m 2770 -o copyparty -g copyparty ${lib.escapeShellArg (shareRoot + "/tftp")}"
        );
        BindPaths = lib.mkOverride 90 [
          copypartyDataDir
          "/var/cache/copyparty"
          "${shareRoot}:${copypartyMountRoot}"
        ];
      };
    };

    nas-vm-storage = lib.mkIf cfg.virtualization.enable {
      description = "Create the libvirt VM storage directory on ZFS";
      requires = [ "nas-zfs-mount-guard.service" ];
      after = [ "nas-zfs-mount-guard.service" ];
      unitConfig = {
        RequiresMountsFor = lib.optional (!cfg.zfsEncryption.enable) cfg.zfsRoot;
        ConditionPathIsMountPoint = cfg.zfsRoot;
      };
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStartPre = "${pkgs.util-linux}/bin/mountpoint --quiet -- ${lib.escapeShellArg cfg.zfsRoot}";
        ExecStart = "${pkgs.coreutils}/bin/install -d -m 2770 -o qemu-libvirtd -g libvirtd ${lib.escapeShellArg vmStoragePath}";
      };
    };

    nas-vm-storage-pool = lib.mkIf cfg.virtualization.enable {
      description = "Define the ZFS-backed libvirt storage pool";
      wantedBy = lib.mkOverride 90 [ ];
      requires = [ "nas-vm-storage.service" ];
      after = [ "libvirtd.service" "nas-vm-storage.service" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = pkgs.writeShellScript "nas-vm-storage-pool" ''
          set -euo pipefail
          pool=nas-zfs
          target=${lib.escapeShellArg vmStoragePath}
          virsh=${pkgs.libvirt}/bin/virsh
          if "$virsh" pool-info "$pool" >/dev/null 2>&1; then
            current="$($virsh pool-dumpxml "$pool" | ${pkgs.python3}/bin/python3 -c 'import sys, xml.etree.ElementTree as ET; print(ET.parse(sys.stdin).findtext("./target/path") or "")')"
            [[ "$current" == "$target" ]] || {
              echo "libvirt pool $pool targets $current instead of $target" >&2
              exit 1
            }
          else
            "$virsh" pool-define-as "$pool" dir --target "$target" >/dev/null
          fi
          "$virsh" pool-info "$pool" | grep -q 'State:.*running' || "$virsh" pool-start "$pool" >/dev/null
          "$virsh" pool-autostart "$pool" >/dev/null
        '';
      };
    };

    libvirtd = lib.mkIf cfg.virtualization.enable {
      onFailure = failureAlert;
      wantedBy = lib.mkOverride 90 [ ];
      partOf = [ "nas-protected-services.target" ];
      unitConfig = {
        RequiresMountsFor = lib.optional (!cfg.zfsEncryption.enable) cfg.zfsRoot;
        ConditionPathIsMountPoint = cfg.zfsRoot;
        ConditionPathExists = [ "${secretRoot}/ready" ] ++ lib.optional cfg.zfsEncryption.enable zfsKeyPath;
      };
    };

    syncthing = lib.mkIf cfg.syncthing.enable {
      onFailure = failureAlert;
      wantedBy = lib.mkOverride 90 [ ];
      partOf = [ "nas-protected-services.target" ];
      environment = {
        STNODEFAULTFOLDER = "1";
        GOMEMLIMIT = "192MiB";
      };
      requires = [ "nas-zfs-mount-guard.service" ];
      after = [ "nas-zfs-mount-guard.service" "network-online.target" ];
      wants = [ "network-online.target" ];
      unitConfig = {
        RequiresMountsFor = [ cfg.zfsRoot syncthingDataDir ];
        ConditionPathIsMountPoint = cfg.zfsRoot;
        ConditionPathExists = [ "${secretRoot}/ready" ] ++ lib.optional cfg.zfsEncryption.enable zfsKeyPath;
      };
      serviceConfig = {
        UMask = "0007";
        ReadWritePaths = [ syncthingDataDir "${shareRoot}/users" ];
      };
    };

    syncthing-init = lib.mkIf cfg.syncthing.enable {
      wantedBy = lib.mkOverride 90 [ ];
      partOf = [ "nas-protected-services.target" ];
      requires = [ "syncthing.service" ];
      after = [ "syncthing.service" ];
      unitConfig.ConditionPathExists = [ "${secretRoot}/ready" ] ++ lib.optional cfg.zfsEncryption.enable zfsKeyPath;
    };

    nas-syncthing-sync = lib.mkIf cfg.syncthing.enable {
      description = "Reconcile Authentik-owned Syncthing folders and devices";
      wantedBy = lib.mkOverride 90 [ ];
      partOf = [ "nas-protected-services.target" ];
      requires = [ "authentik.service" "syncthing.service" ];
      after = [ "authentik.service" "syncthing.service" ];
      unitConfig.ConditionPathExists = authentikApiTokenFile;
      serviceConfig = {
        Type = "oneshot";
        ExecStartPre = pkgs.writeShellScript "wait-for-syncthing" ''
          exec ${pkgs.curl}/bin/curl \
            --fail --silent --show-error \
            --connect-timeout 2 --max-time 5 \
            --retry 30 --retry-delay 2 --retry-connrefused --retry-all-errors \
            http://127.0.0.1:${toString syncthingGuiPort}/rest/noauth/health
        '';
        ExecStart = "${nasIdentitySync}/bin/nas-identity-sync sync-syncthing";
      };
    };

    nas-caddy-ca-export = lib.mkIf cfg.vaultwarden.enable {
      description = "Export Caddy internal CA for Vaultwarden OIDC";
      onFailure = failureAlert;
      wantedBy = lib.mkOverride 90 [ ];
      partOf = [ "nas-protected-services.target" "caddy.service" ];
      requires = [ "caddy.service" ];
      after = [ "caddy.service" ];
      before = [ "vaultwarden.service" ];
      unitConfig.ConditionPathExists = "${secretRoot}/ready";
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        RuntimeDirectory = "nas-caddy-ca";
        RuntimeDirectoryMode = "0755";
        ExecStart = pkgs.writeShellScript "nas-caddy-ca-export" ''
          set -euo pipefail
          for attempt in $(${pkgs.coreutils}/bin/seq 1 60); do
            if [[ -r ${caddyInternalCaPath} ]]; then
              tmp="$(${pkgs.coreutils}/bin/mktemp ${caddyCaExportDir}/ca-bundle.XXXXXX)"
              ${pkgs.coreutils}/bin/cat ${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt ${caddyInternalCaPath} > "$tmp"
              ${pkgs.coreutils}/bin/install -m 0444 -o root -g root "$tmp" ${caddyCaExportPath}
              ${pkgs.coreutils}/bin/rm -f -- "$tmp"
              exit 0
            fi
            ${pkgs.coreutils}/bin/sleep 1
          done
          echo "Caddy internal CA did not appear at ${caddyInternalCaPath}." >&2
          exit 1
        '';
        NoNewPrivileges = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        UMask = "0033";
      };
    };

    vaultwarden = lib.mkIf cfg.vaultwarden.enable {
      onFailure = failureAlert;
      wantedBy = lib.mkOverride 90 [ ];
      partOf = [ "nas-protected-services.target" "caddy.service" "nas-caddy-ca-export.service" ];
      requires = [ "nas-caddy-ca-export.service" "nas-zfs-mount-guard.service" ];
      after = [ "nas-caddy-ca-export.service" "nas-zfs-mount-guard.service" ];
      environment = {
        SSL_CERT_FILE = caddyCaExportPath;
        NIX_SSL_CERT_FILE = caddyCaExportPath;
      };
      unitConfig = {
        ConditionPathExists = "${vaultwardenSecretDir}/environment";
        RequiresMountsFor = [ cfg.zfsRoot vaultwardenDataDir vaultwardenBackupDir ];
        ConditionPathIsMountPoint = cfg.zfsRoot;
      };
      serviceConfig.BindReadOnlyPaths = [ caddyCaExportPath ];
    };

    backup-vaultwarden = lib.mkIf cfg.vaultwarden.enable { onFailure = failureAlert; };

    grafana = lib.mkIf (cfg.observability.enable && cfg.observability.grafana.enable) {
      onFailure = failureAlert;
      wantedBy = lib.mkOverride 90 [ ];
      partOf = [ "nas-protected-services.target" ];
      unitConfig.ConditionPathExists = [ "${secretRoot}/ready" "${observabilitySecretDir}/grafana-secret-key" ];
      serviceConfig.BindReadOnlyPaths = [ observabilitySecretDir ];
    };

    victoriametrics = lib.mkIf cfg.observability.enable {
      onFailure = failureAlert;
      wantedBy = lib.mkOverride 90 [ ];
      partOf = [ "nas-protected-services.target" ];
      postStart = lib.mkOverride 90 ''
        ${pkgs.coreutils}/bin/timeout 90s ${pkgs.curl}/bin/curl \
          --fail --silent --show-error \
          --connect-timeout 1 --max-time 2 \
          --retry 90 --retry-delay 1 --retry-connrefused --retry-all-errors \
          http://127.0.0.1:${toString cfg.observability.victoriaMetricsPort}/victoriametrics/ping >/dev/null
      '';
    };

    vmalert-nas = lib.mkIf (cfg.observability.enable && cfg.alerting.enable) {
      onFailure = failureAlert;
      wantedBy = lib.mkOverride 90 [ ];
      partOf = [ "nas-protected-services.target" ];
      after = [ "victoriametrics.service" "nas-alert-router.service" ];
      requires = [ "victoriametrics.service" "nas-alert-router.service" ];
    };

    nas-alert-router = lib.mkIf (cfg.observability.enable && cfg.alerting.enable) {
      onFailure = failureAlert;
      wantedBy = lib.mkOverride 90 [ ];
      partOf = [ "nas-protected-services.target" ];
    };

    ntfy-sh = lib.mkIf cfg.observability.ntfy.enable {
      onFailure = failureAlert;
      wantedBy = lib.mkOverride 90 [ ];
      partOf = [ "nas-protected-services.target" ];
      unitConfig.ConditionPathExists = "${observabilitySecretDir}/ntfy-environment";
    };

    telegraf = lib.mkIf cfg.observability.enable {
      onFailure = failureAlert;
      wantedBy = lib.mkOverride 90 [ ];
      partOf = [ "nas-protected-services.target" ];
    };

    podman-nut-webgui = lib.mkIf (cfg.power.ups.enable && cfg.power.ups.web.enable) {
      onFailure = failureAlert;
      wantedBy = lib.mkOverride 90 [ ];
      partOf = [ "nas-protected-services.target" ];
      unitConfig.ConditionPathExists = [ "${secretRoot}/ready" "${powerSecretDir}/nut-webgui-server-key" ];
      serviceConfig = {
        RestartSec = "5s";
        TimeoutStartSec = lib.mkOverride 90 "15min";
        TimeoutStopSec = lib.mkOverride 90 "2min";
      };
    };

    caddy = {
      onFailure = failureAlert;
      wantedBy = lib.mkOverride 90 [ "multi-user.target" ];
      partOf = [ "nas-protected-services.target" ];
      wants = caddyBackendUnits;
      # The bootstrap-phase Caddy must come up before secret activation; the
      # selector (nas-caddy-bootstrap.service) synchronously ensures reconcile
      # is fresh post-secrets. Do not require reconcile here: pre-secrets it
      # cannot run (ZFS mount guard) and would permanently block Caddy.
      requires = [ "nas-caddy-bootstrap.service" ];
      after = caddyBackendUnits ++ [
        "nas-caddy-bootstrap.service"
      ];
    };

    sanoid = lib.mkIf (cfg.scheduler.backend == "systemd") { onFailure = failureAlert; };
    zfs-scrub = lib.mkIf (cfg.scheduler.backend == "systemd") { onFailure = failureAlert; };
    zpool-trim = lib.mkIf (cfg.zfsTrimEnable && cfg.scheduler.backend == "systemd") { onFailure = failureAlert; };

    restic-backups-nas-boot-system = lib.mkIf cfg.backup.enable {
      onFailure = failureAlert;
      wantedBy = lib.mkOverride 90 [ ];
      after = [ "postgresql.service" ];
      wants = [ "postgresql.service" ];
    };

    nas-zfs-manual-snapshot = {
      description = "Take an administrator-requested Sanoid snapshot";
      after = [ "zfs.target" ];
      wants = [ "zfs.target" ];
      onFailure = failureAlert;
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${pkgs.sanoid}/bin/sanoid --take-snapshots";
        Nice = 10;
        IOSchedulingClass = "idle";
        TimeoutStartSec = "2h";
      };
    };

    nas-zfs-manual-scrub = {
      description = "Start an administrator-requested ZFS scrub";
      after = [ "zfs.target" ];
      wants = [ "zfs.target" ];
      onFailure = failureAlert;
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${pkgs.zfs}/bin/zpool scrub ${lib.escapeShellArg cfg.zfsPool}";
        TimeoutStartSec = "5min";
      };
    };

    nas-zfs-pool-health = {
      after = [ "zfs.target" ];
      wants = [ "zfs.target" ];
      onFailure = failureAlert;
      description = "Check ZFS pool health with Sanoid";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${pkgs.sanoid}/bin/sanoid --monitor-health --configdir ${sanoidMonitorConfig}";
      };
    };

    nas-zfs-capacity-health = {
      after = [ "zfs.target" ];
      wants = [ "zfs.target" ];
      onFailure = failureAlert;
      description = "Check ZFS pool capacity with Sanoid";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${pkgs.sanoid}/bin/sanoid --monitor-capacity --configdir ${sanoidMonitorConfig}";
      };
    };

    nas-zfs-snapshot-health = {
      after = [ "zfs.target" ];
      wants = [ "zfs.target" ];
      onFailure = failureAlert;
      description = "Check ZFS snapshot freshness with Sanoid";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${pkgs.sanoid}/bin/sanoid --monitor-snapshots --configdir ${sanoidMonitorConfig}";
      };
    };

    "nas-health-alert@" = lib.mkIf cfg.alerting.enable {
      description = "Send a NAS health failure notification for %i";
      after = [ "ntfy-sh.service" ];
      wants = [ "ntfy-sh.service" ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${nasAlert}/bin/nas-alert 'NAS health check failed: %i' 'The systemd unit %i failed on ${config.networking.hostName}. Review it in Cockpit or with journalctl -u %i.'";
      };
    };

    nas-update-preview = lib.mkIf cfg.installationReady {
      description = "Preview and validate the reviewed NAS configuration update candidate";
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      onFailure = failureAlert;
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${nasUpdate}/bin/nas-update";
        Environment = [ "NAS_CONFIG_DIR=${cfg.configurationDir}" ];
        WorkingDirectory = cfg.configurationDir;
        TimeoutStartSec = "10min";
        UMask = "0077";
      };
    };

    nas-update-sync = lib.mkIf cfg.installationReady {
      description = "Fast-forward the reviewed NAS configuration";
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      onFailure = failureAlert;
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${nasUpdate}/bin/nas-update --sync --non-interactive";
        Environment = [ "NAS_CONFIG_DIR=${cfg.configurationDir}" ];
        WorkingDirectory = cfg.configurationDir;
        TimeoutStartSec = "6h";
        TimeoutStopSec = "15min";
        UMask = "0077";
      };
    };

    nas-update-apply = lib.mkIf cfg.installationReady {
      description = "Apply the reviewed NAS configuration";
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      onFailure = failureAlert;
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${nasUpdate}/bin/nas-update --apply --non-interactive";
        Environment = [ "NAS_CONFIG_DIR=${cfg.configurationDir}" ];
        WorkingDirectory = cfg.configurationDir;
        TimeoutStartSec = "6h";
        TimeoutStopSec = "15min";
        UMask = "0077";
      };
    };

    nas-auto-update = lib.mkIf (cfg.autoUpdate.enable && cfg.installationReady) {
      description = "Guarded automatic NAS configuration update";
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      onFailure = failureAlert;
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${nasUpdate}/bin/nas-update --sync --non-interactive${lib.optionalString cfg.autoUpdate.apply " --apply"}";
        Environment = [ "NAS_CONFIG_DIR=${cfg.configurationDir}" ];
        WorkingDirectory = cfg.configurationDir;
        Nice = 10;
        IOSchedulingClass = "idle";
        TimeoutStartSec = "6h";
        TimeoutStopSec = "15min";
        UMask = "0077";
      };
    };
  };
}
