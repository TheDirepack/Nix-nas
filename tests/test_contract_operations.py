from __future__ import annotations

import unittest

from repo_test_utils import ROOT, text


class ContractTests(unittest.TestCase):
    def test_caddy_wants_but_does_not_wait_for_managed_services_reconciliation(self) -> None:
        managed = text("modules/nas/config/managed-services.nix")
        self.assertIn("systemd.services.caddy.wants = [", managed)
        self.assertIn('"nas-managed-services-reconcile.service"', managed)
        self.assertIn('"nas-managed-services-authentik-reconcile.service"', managed)
        self.assertNotIn("systemd.services.caddy.requires", managed)
        self.assertNotIn("systemd.services.caddy.after", managed)
        reconcile = managed.split("systemd.services.nas-managed-services-reconcile = {", 1)[1].split(
            "systemd.paths.nas-managed-services-reconcile", 1
        )[0]
        self.assertNotIn('before = [ "caddy.service" ];', reconcile)

    def test_caddy_bootstrap_does_not_block_on_managed_services_reconciliation(self) -> None:
        bootstrap = text("modules/nas/config/caddy-bootstrap.nix")
        self.assertIn("systemctl start --no-block nas-managed-services-reconcile.service || true", bootstrap)

    def test_zfs_replication_and_boot_recovery_roles_are_separate(self) -> None:
        options = text("modules/nas/options/storage.nix") + text("modules/nas/options/operations.nix")
        storage = text("modules/nas/config/storage-monitoring.nix")
        seed = text("modules/nas/config/managed-services-seed-v2.nix")
        self.assertIn("zfsReplication", options)
        self.assertIn("syncoid", storage)
        self.assertIn("nas-boot-system", storage)
        self.assertIn("nas_v2_backup.py prepare", storage)
        self.assertIn("backupStage = cfg.backup.stagingPath", storage)
        self.assertNotIn("/run/nas-backup-stage", storage)
        self.assertIn("source_db.backup(destination_db)", storage)
        self.assertIn("native-dump", seed)

    def test_native_ntfy_and_telegraf_smart_collection_are_authoritative(self) -> None:
        observability = text("modules/nas/config/observability.nix")
        storage = text("modules/nas/config/storage-monitoring.nix")
        self.assertIn("services.ntfy-sh", observability)
        self.assertIn('base-url = "https://${lanHost}";', observability)
        self.assertIn('web-root = "/notifications";', observability)
        self.assertIn("services.telegraf", observability)
        self.assertIn('path_smartctl = "${smartctlReadOnly}";', observability)
        self.assertIn("use_sudo = true", observability)
        self.assertIn("services.smartd.enable = lib.mkDefault false", storage)
        schedules = text("modules/nas/config/schedules.nix")
        self.assertIn("protectedServiceUnits", schedules)
        self.assertIn("nas-protected-services", schedules)

    def test_secret_readiness_is_bounded_and_diagnostic(self) -> None:
        secrets = text("modules/nas/internal/secret-tools.nix")
        authentik = text("modules/nas/config/application-services.nix")
        self.assertIn("timeout 90s curl", secrets)
        for code in (71, 72, 73):
            self.assertIn(f"exit {code}", secrets)
        self.assertNotIn("seq 1 90", secrets)
        self.assertIn("/bin/timeout 90s", authentik)
        self.assertIn('blueprints_dir = "${nasAuthentikBlueprints}/share/authentik/blueprints";', authentik)
        blueprints = text("modules/nas/internal/account-tools.nix")
        self.assertIn("${pkgs.authentik.src}/blueprints/.", blueprints)

    def test_zfs_recovery_export_supports_piped_and_interactive_passwords(self):
        zfs_tools = text("modules/nas/internal/zfs-tools.nix")
        encrypted_guest = text("tests/vm/encrypted-guest-test.sh")
        self.assertIn("if [[ -t 0 ]]; then", zfs_tools)
        self.assertIn("show-zfs-key-stdin", zfs_tools)
        self.assertIn("nas-zfs-export-recovery-key /tmp/nas-zfs-recovery.key", encrypted_guest)

    def test_feature_apply_defers_to_an_owned_runtime_operation(self):
        systemd = text("modules/nas/config/managed-services.nix")
        self.assertIn("nas-managed-services-reconcile", systemd)

    def test_v2_authority_bootstraps_before_first_run_storage(self) -> None:
        managed = text("modules/nas/config/managed-services.nix")
        seed = managed.split("systemd.services.nas-managed-services-seed = {", 1)[1].split(
            "systemd.services.nas-managed-services-reconcile = {", 1
        )[0]
        reconcile = managed.split("systemd.services.nas-managed-services-reconcile = {", 1)[1].split(
            "systemd.paths.nas-managed-services-reconcile = {", 1
        )[0]
        protected = text("modules/nas/config/systemd-services.nix")

        self.assertNotIn("nas-zfs-mount-guard.service", seed)
        self.assertNotIn("RequiresMountsFor", seed)
        self.assertIn("nas-zfs-mount-guard.service", reconcile)
        self.assertIn("RequiresMountsFor", reconcile)
        self.assertIn("postgresql = {", protected)
        self.assertIn('requires = [ "nas-bootstrap-runtime-select.service" ];', protected)

    def test_identity_runtime_reinitializes_on_zfs_and_retires_bootstrap_authorities(self) -> None:
        applications = text("modules/nas/config/application-services.nix")
        services = text("modules/nas/config/systemd-services.nix")
        setup = text("services/nas_setup.py")
        secrets = text("modules/nas/internal/secret-tools.nix")
        self.assertIn("nas-bootstrap-runtime-select.service", applications)
        self.assertIn("bootstrapAuthentikDataDir", applications)
        self.assertIn("bootstrapPostgresqlDataDir", applications)
        self.assertIn("operational-runtime-select", applications)
        self.assertIn("promote_bootstrap_runtime", setup)
        self.assertIn("retire-bootstrap", setup)
        self.assertIn("retire-authentik-bootstrap-stdin", setup)
        self.assertNotIn('run_root(["mv", str(source), str(destination)])', setup)
        self.assertIn("command_retire_authentik_bootstrap_stdin", secrets)
        self.assertIn(
            '[[ -n "$authentik_bootstrap_token" && "$authentik_api_token" == "$authentik_bootstrap_token" ]]', secrets
        )
        self.assertIn('ConditionPathExists = "!/var/lib/nas-setup/state.json"', services)

    def test_first_boot_authentik_uses_only_a_random_bootstrap_runtime_environment(self) -> None:
        applications = text("modules/nas/config/application-services.nix")
        base = text("modules/nas/internal/base.nix")
        services = text("modules/nas/config/systemd-services.nix")
        setup = text("services/nas_setup.py")
        self.assertIn("nas-bootstrap-authentik-secrets", applications)
        self.assertIn("openssl rand -hex 64", applications)
        self.assertIn("AUTHENTIK_BOOTSTRAP_PASSWORD=nas-admin-first-boot", applications)
        self.assertIn('authentikRuntimeEnvironmentFile = "/run/nas-authentik/environment";', base)
        self.assertIn('authentikRuntimeApiTokenFile = "/run/nas-authentik/api-token";', base)
        self.assertNotIn("EnvironmentFile = [ authentikEnvironmentFile ];", applications)
        self.assertIn("ConditionPathExists = authentikRuntimeEnvironmentFile;", services)
        self.assertNotIn('ConditionPathExists = [ "${secretRoot}/ready" authentikEnvironmentFile ];', services)
        self.assertIn("retire_bootstrap_runtime", setup)
        self.assertIn('run_root(["rm", "-rf", str(bootstrap_root)])', setup)

    def test_cockpit_is_isolated_until_authentik_can_authorize_it(self) -> None:
        base = text("modules/nas/internal/base.nix")
        system = text("modules/nas/config/system.nix")
        firewall = text("modules/nas/config/network-firewall.nix")
        caddy = text("modules/nas/config/caddy-bootstrap.nix")
        services = text("modules/nas/config/application-services.nix")
        secrets = text("modules/nas/internal/secret-tools.nix")
        self.assertNotIn('protectedServiceUnits = [\n    "cockpit.socket"', base)
        self.assertIn("systemd.sockets.cockpit.enable = false;", system)
        self.assertNotIn("directCockpitRecovery", firewall)
        self.assertIn("nas-management-network-guard.service", caddy)
        console = caddy.split("handle /console* {", 1)[1].split("reverse_proxy", 1)[0]
        self.assertIn("${caddyForwardAuth}", console)
        self.assertIn("@missingCockpitAdmin", caddy)
        self.assertIn("respond @missingCockpitAdmin 403", caddy)
        self.assertIn("nas-cockpit-sso", services)
        self.assertIn("--local-session", services)
        self.assertNotIn("settings.bearer", services)
        self.assertNotIn("nas-cockpit-oauth", services)
        self.assertIn("--address 127.0.0.1", services)
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
        seed = text("modules/nas/config/managed-services-seed-v2.nix")
        proxy = text("modules/nas/config/reverse-proxy.nix")
        self.assertIn("services.victoriametrics", observability)
        self.assertIn("services.vmalert.instances.nas", observability)
        self.assertIn("services.telegraf", observability)
        self.assertNotIn("services.prometheus", observability)
        self.assertIn("victoriametrics =", seed)
        self.assertIn('pathRoute [ "/victoriametrics/" ]', seed)
        self.assertNotIn("handle /victoriametrics/*", proxy)
        self.assertFalse((ROOT / "modules/nas/config/managed-services-native-services.nix").exists())
        self.assertFalse((ROOT / "modules/nas/config/managed-services-platform-routes.nix").exists())
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
        v2 = text("modules/nas/config/managed-services.nix")
        self.assertIn('effectivePath = "/run/nas-control/effective.json";', v2)
        self.assertIn("nas-managed-services-reconcile", v2)
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
        self.assertIn('"d /run/nas-first-start 0700 root root -"', system)
        self.assertIn("users.groups.nas-operations", identities)
        self.assertIn('extraGroups = [ "copyparty" ]', identities)
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
            self.assertIn("/setup/api", guest)
            self.assertIn("planDigest", guest)
            self.assertIn("stale", guest.lower())
        self.assertIn("prepare-first-start", text("tests/vm/guest-test.sh"))

    def test_update_snapshots_have_bounded_retention(self) -> None:
        update = text("scripts/update-nas.sh")
        self.assertIn("NAS_UPDATE_STATE_RETAIN_COUNT", update)
        self.assertIn("prune_state_snapshots", update)
        self.assertIn("state_snapshot_retain_count <= 20", update)


if __name__ == "__main__":
    unittest.main()
