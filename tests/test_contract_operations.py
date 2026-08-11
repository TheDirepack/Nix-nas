from __future__ import annotations

import unittest

from repo_test_utils import ROOT, text


class ContractTests(unittest.TestCase):
    def test_zfs_replication_and_boot_recovery_roles_are_separate(self) -> None:
        options = text("modules/nas/options/storage.nix") + text("modules/nas/options/operations.nix")
        storage = text("modules/nas/config/storage-monitoring.nix")
        backup_resources = text("modules/nas/config/managed-services-backup-resources.nix")
        self.assertIn("zfsReplication", options)
        self.assertIn("syncoid", storage)
        self.assertIn("nas-boot-system", storage)
        self.assertIn("nas_v2_backup_runtime.py prepare", storage)
        self.assertIn("backupStage = cfg.backup.stagingPath", storage)
        self.assertNotIn("/run/nas-backup-stage", storage)
        self.assertIn("source_db.backup(destination_db)", backup_resources)
        self.assertIn("native-dump", backup_resources)

    def test_native_ntfy_and_telegraf_smart_collection_are_authoritative(self) -> None:
        observability = text("modules/nas/config/observability.nix")
        storage = text("modules/nas/config/storage-monitoring.nix")
        self.assertIn("services.ntfy-sh", observability)
        self.assertIn("services.telegraf", observability)
        self.assertIn('path_smartctl = "${smartctlReadOnly}";', observability)
        self.assertIn("use_sudo = true", observability)
        self.assertIn("services.smartd.enable = lib.mkDefault false", storage)

    def test_secret_readiness_is_bounded_and_diagnostic(self) -> None:
        secrets = text("modules/nas/internal/secret-tools.nix")
        authentik = text("modules/nas/config/application-services.nix")
        self.assertIn("timeout 90s curl", secrets)
        for code in (71, 72, 73):
            self.assertIn(f"exit {code}", secrets)
        self.assertNotIn("seq 1 90", secrets)
        self.assertIn("/bin/timeout 90s", authentik)

    def test_cockpit_recovery_socket_is_available_before_protected_services(self) -> None:
        base = text("modules/nas/internal/base.nix")
        system = text("modules/nas/config/system.nix")
        firewall = text("modules/nas/config/network-firewall.nix")
        services = text("modules/nas/config/application-services.nix")
        secrets = text("modules/nas/internal/secret-tools.nix")
        self.assertNotIn('protectedServiceUnits = [\n    "cockpit.socket"', base)
        self.assertIn('wantedBy = lib.mkOverride 90 [ "multi-user.target" ]', system)
        self.assertIn("DefaultDependencies = false", system)
        self.assertIn('conflicts = [ "shutdown.target" ]', system)
        self.assertIn('requires = [ "sysinit.target" ]', system)
        self.assertIn("lib.optional cfg.hostPolicy.directCockpitRecovery", firewall)
        self.assertIn("AllowUnencrypted = false", services)
        self.assertIn("activate-stdin)", secrets)

    def test_firewall_defaults_fail_closed_and_vm_interfaces_are_explicit(self) -> None:
        firewall = text("modules/nas/config/network-firewall.nix")
        integration = text("tests/nixos/integration.nix")
        encrypted = text("tests/nixos/encrypted.nix")
        qemu = text("tests/nixos/qemu-installed.nix")
        guest = text("tests/vm/guest-test.sh")
        self.assertIn("DefaultZone=drop", firewall)
        self.assertNotIn("DefaultZone=public", firewall)
        self.assertIn('trustedInterfaces = pkgs.lib.mkForce [ "eth1" ]', integration)
        self.assertIn('trustedInterfaces = lib.mkForce [ "eth1" ]', encrypted)
        self.assertIn('trustedInterfaces = lib.mkForce [ "eth0" ]', qemu)
        self.assertIn("nas-untrusted-test", guest)
        self.assertIn("untrusted namespace reached protected TCP port", guest)

    def test_victoriametrics_replaces_prometheus_and_routes_are_v2_owned(self) -> None:
        observability = text("modules/nas/config/observability.nix")
        desired = text("config/managed-services-v2.yaml")
        proxy = text("modules/nas/config/reverse-proxy.nix")
        self.assertIn("services.victoriametrics", observability)
        self.assertIn("services.vmalert.instances.nas", observability)
        self.assertIn("services.telegraf", observability)
        self.assertNotIn("services.prometheus", observability)
        self.assertIn("victoriametrics", desired)
        self.assertIn("/victoriametrics", desired)
        self.assertNotIn("handle /victoriametrics/*", proxy)
        self.assertFalse((ROOT / "modules/nas/internal/feature-catalog.nix").exists())
        self.assertFalse((ROOT / "modules/nas/config/managed-services-migration.nix").exists())

    def test_nixos_2605_build_regressions_are_fixed(self) -> None:
        schedules = text("modules/nas/config/schedules.nix")
        zfs = text("modules/nas/internal/zfs-tools.nix")
        power = text("modules/nas/internal/power-tools.nix")
        validation = text("modules/nas/config/validation.nix")
        self.assertNotIn("multilingual", text("docs/book.toml"))
        self.assertIn('"network-online.target"', schedules)
        self.assertNotIn("optionalString (!cfg.zfsEncryption.enable)", zfs)
        self.assertNotIn("optionalString (!cfg.power.ups.enable)", power)
        self.assertIn("pkgs.nodejs_22", zfs)
        self.assertIn("cfg.observability.serviceGid", validation)
        self.assertIn('${if cfg.tftp.writable then "rw" else "r"}: *', text("modules/nas/config/system.nix"))

    def test_observability_consumes_compiled_v2_service_state(self) -> None:
        observability = text("modules/nas/config/observability.nix")
        v2 = text("modules/nas/config/managed-services-v2.nix")
        self.assertIn("managedServicesV2", v2)
        self.assertNotIn("featureCatalog", observability)
        self.assertNotIn("serviceRegistry", observability)
        self.assertFalse((ROOT / "modules/nas/internal/service-registry.nix").exists())

    def test_shared_operation_coordinator_covers_update_secrets_and_setup_children(self) -> None:
        system = text("modules/nas/config/system.nix")
        identities = text("modules/nas/config/identities.nix")
        secrets = text("modules/nas/internal/secret-tools.nix")
        update = text("scripts/update-nas.sh")
        package = text("pyproject.toml")
        self.assertIn('"d /run/nas-operations 2770 root nas-operations -"', system)
        self.assertIn("users.groups.nas-operations", identities)
        self.assertIn('nas-operation-run = "nas_operation_lock:main"', package)
        self.assertIn("enter_operation_coordinator", secrets)
        self.assertIn("operation_class=update", update)
        self.assertNotIn("exec 8>/run/nas-operations/appliance.lock", update)

    def test_state_wrapper_is_profile_aware_private_and_excludes_regenerable_metrics(self) -> None:
        account = text("modules/nas/internal/account-tools.nix")
        system = text("modules/nas/config/system.nix")
        self.assertIn("NAS_STATE_REGISTRY_REQUIRED=1", account)
        self.assertIn("NAS_STATE_RUNTIME_ROOT=/run/nas-state", account)
        self.assertIn("NAS_STATE_QUIESCE_UNITS_JSON", account)
        self.assertIn('"d /run/nas-state 0700 root root -"', system)
        self.assertNotIn('name = "victoriametrics"; source = "/var/lib/victoriametrics"', account)
        self.assertIn('lib.optional cfg.virtualization.enable "libvirtd.service"', account)

    def test_managed_service_memory_policy_is_declared_without_feature_catalog(self) -> None:
        observability = text("modules/nas/config/observability.nix")
        ai_options = text("modules/ai/options.nix")
        systemd = text("modules/nas/config/systemd-services.nix")
        identity_model = text("services/nas_identity_model.py")
        self.assertIn('victoriaAllowed = "96MiB";', observability)
        self.assertIn('victoriaHigh = "128M";', observability)
        self.assertIn("MemoryHigh = memoryPolicy.victoriaHigh", observability)
        self.assertIn("default = 300;", ai_options)
        self.assertIn('GOMEMLIMIT = "192MiB"', systemd)
        self.assertIn('"numConnections": 1', identity_model)
        self.assertFalse((ROOT / "modules/nas/internal/feature-catalog.nix").exists())

    def test_vm_first_start_uses_normalized_plan_digest_and_negative_stale_digest(self) -> None:
        for path in ("tests/vm/guest-test.sh", "tests/vm/encrypted-guest-test.sh"):
            guest = text(path)
            self.assertIn("prepare-first-start", guest)
            self.assertIn("--confirm-plan-digest", guest)
            self.assertIn("stale", guest.lower())

    def test_update_snapshots_have_bounded_retention(self) -> None:
        update = text("scripts/update-nas.sh")
        self.assertIn("NAS_UPDATE_STATE_RETAIN_COUNT", update)
        self.assertIn("prune_state_snapshots", update)
        self.assertIn("state_snapshot_retain_count <= 20", update)


if __name__ == "__main__":
    unittest.main()
