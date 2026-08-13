{ config, lib, pkgs, nasInternal, ... }:

let
  inherit (nasInternal)
    authentikApiTokenFile
    authentikBootstrapTokenFile
    authentikEnvironmentFile
    authentikPort
    caddyBackendUnits
    caddyCaExportDir
    caddyCaExportPath
    caddyInternalCaPath
    cfg
    copypartyMountRoot
    failureAlert
    nasAlert
    nasFeatureControl
    nasIdentitySync
    nasPythonApplication
    nasSetup
    nasUpdate
    nasZfsMountCheck
    nasZfsUnlock
    observabilitySecretDir
    powerSecretDir
    protectedServiceUnits
    sanoidMonitorConfig
    secretRoot
    shareRoot
    syncthingGuiPort
    vaultwardenSecretDir
    vmStoragePath
    zfsKeyPath
  ;
in
{
  config.systemd.services = {
    nas-first-start = lib.mkIf cfg.firstStart.enable {
      description = "Prepare the automatic NixOS NAS first-start workflow";
      wantedBy = [ "multi-user.target" ];
      wants = [ "cockpit.socket" ];
      before = [ "cockpit.socket" ];
      after = [ "local-fs.target" ];
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
      };
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${nasZfsMountCheck}/bin/nas-zfs-mount-check";
      };
    };

    # Protected services start only after runtime secrets are staged.
    postgresql = {
      wantedBy = lib.mkOverride 90 [ ];
      partOf = [ "nas-protected-services.target" ];
      before = [ "authentik-migrate.service" ];
    };

    authentik-migrate = {
      onFailure = failureAlert;
      wantedBy = lib.mkOverride 90 [ ];
      partOf = [ "nas-protected-services.target" ];
      unitConfig.ConditionPathExists = [ "${secretRoot}/ready" authentikEnvironmentFile ];
    };

    authentik-worker = {
      onFailure = failureAlert;
      wantedBy = lib.mkOverride 90 [ ];
      partOf = [ "nas-protected-services.target" ];
      unitConfig.ConditionPathExists = [ "${secretRoot}/ready" authentikEnvironmentFile ];
    };

    authentik = {
      onFailure = failureAlert;
      wantedBy = lib.mkOverride 90 [ ];
      partOf = [ "nas-protected-services.target" ];
      unitConfig.ConditionPathExists = [ "${secretRoot}/ready" authentikEnvironmentFile ];
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
        authentikBootstrapTokenFile
        "/var/lib/nas-setup/state.json"
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
    };

    nas-copyparty-share-root = {
      description = "Prepare the ZFS-backed CopyParty share root";
      partOf = [ "nas-protected-services.target" ];
      before = [ "copyparty.service" ];
      requires = [ "nas-zfs-mount-guard.service" ];
      after = [ "nas-zfs-mount-guard.service" ];
      unitConfig = {
        RequiresMountsFor = lib.optional (!cfg.zfsEncryption.enable) cfg.zfsRoot;
        AssertPathIsMountPoint = cfg.zfsRoot;
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
        RequiresMountsFor = lib.optional (!cfg.zfsEncryption.enable) cfg.zfsRoot;
        ConditionPathExists = "${secretRoot}/ready";
        AssertPathIsMountPoint = cfg.zfsRoot;
      };
      serviceConfig = {
        RuntimeDirectoryMode = lib.mkOverride 90 "0750";
        UMask = lib.mkForce "0007";
        # CopyParty's private namespace needs the host account database for
        # its startup hook; TemporaryFileSystem otherwise hides /etc/passwd.
        BindReadOnlyPaths = lib.mkAfter [ "/etc/passwd" ];
        BindPaths = lib.mkOverride 90 [
          "/var/lib/copyparty"
          "/var/cache/copyparty"
          "${shareRoot}:${copypartyMountRoot}"
        ];
      };
    };

    nas-vm-storage = lib.mkIf cfg.virtualization.enable {
      description = "Create the libvirt VM storage directory on ZFS";
      before = [ "libvirtd.service" ];
      requiredBy = [ "libvirtd.service" ];
      requires = [ "nas-zfs-mount-guard.service" ];
      after = [ "nas-zfs-mount-guard.service" ];
      unitConfig = {
        RequiresMountsFor = lib.optional (!cfg.zfsEncryption.enable) cfg.zfsRoot;
        AssertPathIsMountPoint = cfg.zfsRoot;
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
      # Runtime feature policy owns this unit. Do not make protected-services.target
      # pull libvirt in when the saved virtualization mode is off.
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
      requires = [ "nas-vm-storage.service" ];
      after = [ "nas-vm-storage.service" ];
      unitConfig = {
        RequiresMountsFor = lib.optional (!cfg.zfsEncryption.enable) cfg.zfsRoot;
        AssertPathIsMountPoint = cfg.zfsRoot;
        ConditionPathExists = [ "${secretRoot}/ready" ] ++ lib.optional cfg.zfsEncryption.enable zfsKeyPath;
      };
    };

    syncthing = lib.mkIf cfg.syncthing.enable {
      onFailure = failureAlert;
      wantedBy = lib.mkOverride 90 [ ];
      partOf = [ "nas-protected-services.target" ];
      environment = {
        STNODEFAULTFOLDER = "1";
        # Balanced Go heap target; Syncthing may briefly exceed this for non-heap
        # allocations, so this is a GC target rather than a hard cgroup limit.
        GOMEMLIMIT = "192MiB";
      };
      requires = [ "nas-zfs-mount-guard.service" ];
      after = [ "nas-zfs-mount-guard.service" "network-online.target" ];
      wants = [ "network-online.target" ];
      unitConfig = {
        RequiresMountsFor = lib.optional (!cfg.zfsEncryption.enable) cfg.zfsRoot;
        AssertPathIsMountPoint = cfg.zfsRoot;
        ConditionPathExists = [ "${secretRoot}/ready" ] ++ lib.optional cfg.zfsEncryption.enable zfsKeyPath;
      };
      serviceConfig = {
        UMask = "0007";
        ReadWritePaths = [ "${shareRoot}/users" ];
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

    nas-on-demand-gate = {
      description = "Authenticated on-demand NAS feature gate and idle reaper";
      onFailure = failureAlert;
      wantedBy = lib.mkOverride 90 [ ];
      partOf = [ "nas-protected-services.target" ];
      after = [ "authentik.service" ];
      before = [ "caddy.service" "nas-feature-apply.service" ];
      unitConfig.ConditionPathExists = "${secretRoot}/ready";
      serviceConfig = {
        Type = "simple";
        User = "nas-feature-gate";
        Group = "caddy";
        SupplementaryGroups = [ "nas-feature-control" ] ++ lib.optional cfg.ai.enable "nas-ai-models";
        Environment = "NAS_AI_API_KEY_FILE=${secretRoot}/ai/gate-api-key";
        ExecStart = "${nasFeatureControl}/bin/nas-feature-control serve";
        Restart = "on-failure";
        RestartSec = "2s";
        RuntimeDirectory = "nas-on-demand";
        RuntimeDirectoryMode = "0750";
        UMask = "0007";
        NoNewPrivileges = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        RestrictSUIDSGID = true;
        RestrictRealtime = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" ];
        ReadWritePaths = [ "/var/lib/nas-control" "/run/nas-control" "/run/nas-on-demand" ];
      };
    };

    nas-feature-apply = {
      description = "Apply persistent NAS feature switches";
      onFailure = failureAlert;
      wantedBy = lib.mkOverride 90 [ ];
      partOf = [ "nas-protected-services.target" ];
      after = protectedServiceUnits;
      unitConfig.ConditionPathExists = "${secretRoot}/ready";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = pkgs.writeShellScript "nas-feature-apply" ''
          set -euo pipefail
          error_file="$(${pkgs.coreutils}/bin/mktemp)"
          if ${nasFeatureControl}/bin/nas-feature-control apply 2>"$error_file"; then
            rm -f -- "$error_file"
            exit 0
          fi
          if ${pkgs.gnugrep}/bin/grep -qF \
            "Another privileged operation conflicts with feature-apply:" "$error_file"; then
            echo "Feature policy application deferred to the owning operation." >&2
            rm -f -- "$error_file"
            exit 0
          fi
          ${pkgs.coreutils}/bin/cat "$error_file" >&2
          rm -f -- "$error_file"
          exit 1
        '';
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
      requires = [ "nas-caddy-ca-export.service" ];
      after = [ "nas-caddy-ca-export.service" ];
      environment = {
        SSL_CERT_FILE = caddyCaExportPath;
        NIX_SSL_CERT_FILE = caddyCaExportPath;
      };
      unitConfig.ConditionPathExists = "${vaultwardenSecretDir}/environment";
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
      wantedBy = lib.mkOverride 90 [ ];
      partOf = [ "nas-protected-services.target" ];
      wants = caddyBackendUnits;
      requires = [ "nas-managed-services-reconcile.service" ];
      after = caddyBackendUnits ++ [ "nas-managed-services-reconcile.service" ];
      unitConfig.ConditionPathExists = "${secretRoot}/ready";
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
