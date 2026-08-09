from __future__ import annotations

import unittest

from repo_test_utils import text


class ContractTests(unittest.TestCase):
    def test_zfs_replication_and_boot_recovery_roles_are_separate(self):
        options = text("modules/nas/options/storage.nix") + text("modules/nas/options/operations.nix")
        storage = text("modules/nas/config/storage-monitoring.nix")
        self.assertIn("zfsReplication", options)
        self.assertIn("syncoid", storage)
        self.assertIn("nas-boot-system", storage)
        self.assertIn('"/boot"', storage)
        self.assertIn('"/etc/ssh"', storage)
        self.assertIn("shares.db", storage)
        self.assertIn("pkgs.sqlite", storage)
        self.assertIn("source_db.backup(destination_db)", storage)
        self.assertIn('sqlite3.connect(f"file:{source}?mode=ro", uri=True)', storage)
        self.assertNotIn(".backup '$destination'", storage)
        self.assertNotIn('"/var/lib/copyparty"', storage)
        self.assertIn("backupStage = cfg.backup.stagingPath", storage)
        self.assertIn('"$backup_stage/copyparty"', storage)
        self.assertNotIn("/run/nas-backup-stage", storage)
        self.assertIn("backups/restic-system", storage)
        self.assertIn("NAS_ZFS_REPLICATION_ENABLE", text("modules/nas/internal/account-tools.nix"))
        self.assertIn('onRequestAction("zfs-replicate"', text("cockpit/src/app.jsx"))
        self.assertIn('"zfs-replicate"', text("services/nas_cockpit_api.py"))
        validation = text("modules/nas/config/validation.nix")
        self.assertIn("cfg.zfsReplication.target != cfg.zfsDataset", validation)
        self.assertIn('lib.hasPrefix "-" cfg.zfsReplication.target', validation)
        self.assertIn("^[^[:space:]]+$", validation)

    def test_native_ntfy_and_telegraf_smart_collection_are_authoritative(self):
        observability = text("modules/nas/config/observability.nix")
        storage = text("modules/nas/config/storage-monitoring.nix")
        self.assertIn("services.ntfy-sh", observability)
        self.assertIn("services.telegraf", observability)
        self.assertIn('path_smartctl = "${smartctlReadOnly}";', observability)
        self.assertIn('command = "${smartctlReadOnly}";', observability)
        self.assertIn("use_sudo = true", observability)
        self.assertIn("services.smartd.enable = lib.mkDefault false", storage)

    def test_secret_readiness_is_bounded_and_diagnostic(self):
        secrets = text("modules/nas/internal/secret-tools.nix")
        authentik = text("modules/nas/config/application-services.nix")
        self.assertIn("timeout 90s curl", secrets)
        self.assertIn("exit 71", secrets)
        self.assertIn("exit 72", secrets)
        self.assertIn("exit 73", secrets)
        self.assertNotIn("seq 1 90", secrets)
        self.assertIn("/bin/timeout 90s", authentik)

    def test_cockpit_remains_available_for_locked_state_stdin_unlock(self):
        base = text("modules/nas/internal/base.nix")
        system = text("modules/nas/config/system.nix")
        firewall = text("modules/nas/config/network-firewall.nix")
        services = text("modules/nas/config/application-services.nix")
        proxy = text("modules/nas/config/reverse-proxy.nix")
        secrets = text("modules/nas/internal/secret-tools.nix")
        self.assertNotIn('protectedServiceUnits = [\n    "cockpit.socket"', base)
        self.assertIn('wantedBy = lib.mkOverride 90 [ "sockets.target" ]', system)
        self.assertIn("lib.optional cfg.hostPolicy.directCockpitRecovery", firewall)
        self.assertIn("port = toString cockpitPort;", firewall)
        self.assertIn("directCockpitRecovery = true;", text("local.nix"))
        self.assertIn("nas-owned-zone.xml", firewall)
        self.assertIn("AllowUnencrypted = false", services)
        self.assertIn("https://${lanHost}:${toString cockpitPort}", services)
        self.assertIn("reverse_proxy https://127.0.0.1:${toString cockpitPort}", proxy)
        self.assertIn("activate-stdin)", secrets)
        self.assertIn("password_from_stdin=true", secrets)

    def test_firewall_defaults_fail_closed_and_vm_interfaces_are_explicit(self):
        firewall = text("modules/nas/config/network-firewall.nix")
        integration = text("tests/nixos/integration.nix")
        encrypted = text("tests/nixos/encrypted.nix")
        qemu = text("tests/nixos/qemu-installed.nix")
        vm_common = text("tests/nixos/vm-common.nix")
        guest = text("tests/vm/guest-test.sh")
        self.assertIn("DefaultZone=drop", firewall)
        self.assertIn('DefaultZone = "drop";', firewall)
        self.assertIn("${pkgs.findutils}/bin/find", firewall)
        self.assertNotIn("DefaultZone=public", firewall)
        self.assertIn('trustedInterfaces = pkgs.lib.mkForce [ "eth1" ]', integration)
        self.assertIn('trustedInterfaces = lib.mkForce [ "eth1" ]', encrypted)
        self.assertIn("usePredictableInterfaceNames = lib.mkForce false", qemu)
        self.assertIn('trustedInterfaces = lib.mkForce [ "eth0" ]', qemu)
        self.assertNotIn("trustedInterfaces", vm_common)
        self.assertIn("nas-untrusted-test", guest)
        self.assertIn("untrusted namespace reached protected TCP port", guest)

    def test_vmalert_and_alert_router_do_not_require_ntfy(self):
        observability = text("modules/nas/config/observability.nix")
        self.assertIn(
            "services.vmalert.instances.nas = lib.mkIf cfg.alerting.enable",
            observability,
        )
        self.assertIn(
            "systemd.services.nas-alert-router = lib.mkIf cfg.alerting.enable",
            observability,
        )
        self.assertIn('NAS_ALERT_ROUTER_NTFY_ENABLED = if obs.ntfy.enable then "1" else "0"', observability)
        self.assertNotIn("services.prometheus", observability)

    def test_victoriametrics_replaces_prometheus_server(self):
        observability = text("modules/nas/config/observability.nix")
        catalog = text("modules/nas/internal/feature-catalog.nix")
        proxy = text("modules/nas/config/reverse-proxy.nix")
        self.assertIn("services.victoriametrics", observability)
        self.assertIn("services.vmalert.instances.nas", observability)
        self.assertIn('"evaluationInterval" = "30s"', observability)
        self.assertIn("-http.pathPrefix=/victoriametrics", observability)
        self.assertNotIn("services.prometheus", observability)
        self.assertIn("services.telegraf", observability)
        self.assertIn('namepass = [ "smart_device" ];', observability)
        self.assertIn('fields.float = [ "health_ok" ];', observability)
        self.assertIn("smart_device_health_ok == 0", observability)
        self.assertIn("nas-alert-router.service", catalog)
        self.assertIn("victoriametrics.service", catalog)
        self.assertIn("vmalert-nas.service", catalog)
        self.assertIn("/victoriametrics/vmui", proxy)
        self.assertIn("handle /victoriametrics/*", proxy)
        self.assertNotIn("handle_path /victoriametrics/*", proxy)

    def test_nixos_2605_build_regressions_and_observability_ids_are_fixed(self):
        schedules = text("modules/nas/config/schedules.nix")
        zfs = text("modules/nas/internal/zfs-tools.nix")
        power = text("modules/nas/internal/power-tools.nix")
        validation = text("modules/nas/config/validation.nix")
        management = text("modules/nas/options/management.nix")
        observability = text("modules/nas/config/observability.nix")
        self.assertNotIn("multilingual", text("docs/book.toml"))
        self.assertIn('"network-online.target"', schedules)
        self.assertNotIn("optionalString (!cfg.zfsEncryption.enable)", zfs)
        self.assertNotIn("optionalString (!cfg.power.ups.enable)", power)
        self.assertIn("pkgs.nodejs_22", zfs)
        self.assertIn("pkgs.buildPackages.nodejs_22", zfs)
        self.assertIn("serviceGid = lib.mkOption", management)
        self.assertIn("cfg.observability.serviceGid", validation)
        self.assertIn("obs.serviceGid", observability)
        self.assertNotIn("serviceUid (also used as the service GID)", validation)
        self.assertIn('${if cfg.tftp.writable then "rw" else "r"}: *', text("modules/nas/config/system.nix"))
        self.assertIn('lib.escapeShellArg (shareRoot + "/tftp")', text("modules/nas/config/systemd-services.nix"))
        self.assertNotIn("world-writable filesystem permissions", validation)
        mount_guard = (
            "nas-zfs-mount-guard = {\n"
            '      description = "Verify the exact NAS ZFS dataset and mountpoint";\n'
            '      partOf = [ "nas-protected-services.target" ];'
        )
        self.assertIn(mount_guard, text("modules/nas/config/systemd-services.nix"))

    def test_observability_consumes_the_v2_service_registry_shape(self):
        observability = text("modules/nas/config/observability.nix")
        feature_catalog = text("modules/nas/internal/feature-catalog.nix")
        self.assertIn("entry.runtime.units", observability)
        self.assertIn("entry.enabled", observability)
        self.assertNotIn("entry.available", observability)
        self.assertNotRegex(feature_catalog, r"serviceRegistry\.[A-Za-z0-9_]+\.(?:port|units)\b")
        self.assertIn(".endpoints.main.targetPort", feature_catalog)
        self.assertIn(".runtime.units", feature_catalog)

    def test_shared_operation_coordinator_covers_update_secrets_and_setup_children(self):
        system = text("modules/nas/config/system.nix")
        identities = text("modules/nas/config/identities.nix")
        secrets = text("modules/nas/internal/secret-tools.nix")
        update = text("scripts/update-nas.sh")
        package = text("pyproject.toml")
        self.assertIn('"d /run/nas-operations 2770 root nas-operations -"', system)
        self.assertIn("users.groups.nas-operations", identities)
        self.assertIn('nas-operation-run = "nas_operation_lock:main"', package)
        self.assertIn("enter_operation_coordinator", secrets)
        self.assertIn("--class secrets --class runtime", secrets)
        self.assertIn("operation_class=update", update)
        self.assertIn("operation_class=appliance", update)
        self.assertIn('--class "$operation_class"', update)
        self.assertNotIn("exec 8>/run/nas-operations/appliance.lock", update)
        self.assertNotIn("install -d -m 0770 -o root -g wheel /run/nas-operations", update)

    def test_state_wrapper_is_profile_aware_private_and_excludes_regenerable_metric_history(self):
        account = text("modules/nas/internal/account-tools.nix")
        system = text("modules/nas/config/system.nix")
        self.assertIn("NAS_STATE_REGISTRY_REQUIRED=1", account)
        self.assertIn("NAS_STATE_RUNTIME_ROOT=/run/nas-state", account)
        self.assertIn("NAS_STATE_QUIESCE_UNITS_JSON", account)
        self.assertIn('"d /run/nas-state 0700 root root -"', system)
        self.assertNotIn('name = "victoriametrics"; source = "/var/lib/victoriametrics"', account)
        self.assertIn('lib.optional cfg.virtualization.enable "libvirtd.service"', account)

    def test_alpha4_memory_controls_and_recovery_wiring_are_declared(self):
        observability = text("modules/nas/config/observability.nix")
        catalog = text("modules/nas/internal/feature-catalog.nix")
        ai_options = text("modules/ai/options.nix")
        systemd = text("modules/nas/config/systemd-services.nix")
        base = text("modules/nas/internal/base.nix")
        account = text("modules/nas/internal/account-tools.nix")
        identity_model = text("services/nas_identity_model.py")
        self.assertIn('"nas-health-alert@%n.service"', base)

        self.assertIn('victoriaAllowed = "96MiB";', observability)
        self.assertIn('victoriaHigh = "128M";', observability)
        self.assertIn('telemetryInterval = "60s";', observability)
        self.assertIn('victoriaAllowed = "64MiB";', observability)
        self.assertIn('victoriaAllowed = "256MiB";', observability)
        self.assertIn('"-memory.allowedBytes=${memoryPolicy.victoriaAllowed}"', observability)
        self.assertIn("MemoryHigh = memoryPolicy.victoriaHigh", observability)
        self.assertIn("interval = memoryPolicy.telemetryInterval", observability)
        self.assertIn("flush_interval = memoryPolicy.telemetryInterval", observability)
        self.assertIn('cache-file = "/var/lib/ntfy-sh/cache.db"', observability)
        self.assertIn("default = 300;", ai_options)
        self.assertIn("idleSeconds = 600;", catalog)
        self.assertIn('GOMEMLIMIT = "192MiB"', systemd)
        self.assertIn('"numConnections": 1', identity_model)
        self.assertIn('"pullerMaxPendingKiB": 16384', identity_model)
        self.assertIn('"weakHashThresholdPct": 101', identity_model)

        self.assertIn("nas-vm-storage-pool = lib.mkIf cfg.virtualization.enable", systemd)
        self.assertIn("pool=nas-zfs", systemd)
        self.assertIn('pool-define-as "$pool" dir --target "$target"', systemd)
        self.assertIn('pool-autostart "$pool"', systemd)
        self.assertIn("NAS_STATE_RESTORE_UNITS_JSON", account)
        self.assertIn("NAS_SOURCE_REVISION=", account)
        self.assertIn("owner = cfg.adminUser;", account)
        self.assertIn('group = "users";', account)

    def test_vm_first_start_uses_normalized_plan_digest_and_negative_stale_digest(self):
        for path in ("tests/vm/guest-test.sh", "tests/vm/encrypted-guest-test.sh"):
            guest = text(path)
            self.assertIn("prepare-first-start", guest)
            self.assertIn("--confirm-plan-digest", guest)
            self.assertIn("stale", guest.lower())

    def test_update_snapshots_have_bounded_retention(self):
        update = text("scripts/update-nas.sh")
        self.assertIn("NAS_UPDATE_STATE_RETAIN_COUNT", update)
        self.assertIn("prune_state_snapshots", update)
        self.assertIn("state_snapshot_retain_count <= 20", update)

    def test_disko_examples_remain_isolated(self):
        os_example = text("installation/disko-os-disk-example.nix")
        pool_example = text("installation/disko-fresh-pool-example.nix")
        active = "\n".join(
            text(path)
            for path in [
                "flake.nix",
                "modules/nas/default.nix",
                "modules/ai/default.nix",
                "local.nix",
                "modules/nas/default.nix",
            ]
        )
        self.assertIn("REPLACE_WITH_OS_DISK_ID", os_example)
        self.assertIn("REPLACE_WITH_DATA_DISK_0", pool_example)
        self.assertIn("REPLACE_WITH_DATA_DISK_1", pool_example)
        self.assertNotIn("disko-os-disk-example.nix", active)
        self.assertNotIn("disko-fresh-pool-example.nix", active)


if __name__ == "__main__":
    unittest.main()
