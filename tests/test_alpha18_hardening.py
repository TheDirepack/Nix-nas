from __future__ import annotations

import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


class Alpha18HardeningContracts(unittest.TestCase):
    def test_feature_catalog_imports_every_external_value(self) -> None:
        catalog = text("modules/nas/internal/feature-catalog.nix")
        inherit_block = catalog.split(";", 1)[0]
        self.assertIn("cfg", inherit_block)
        self.assertIn("serviceRegistry", inherit_block)
        self.assertNotIn("alertmanager", inherit_block.lower())

    def test_flake_exports_modules_directly(self) -> None:
        flake = text("flake.nix")
        self.assertFalse((ROOT / "nas-module.nix").exists())
        self.assertFalse((ROOT / "ai-module.nix").exists())
        self.assertIn("core = import ./modules/nas;", flake)
        self.assertIn("ai = import ./modules/ai;", flake)
        default_block = flake.split("default = { ... }:", 1)[1].split("profiles =", 1)[0]
        self.assertIn("copyparty.nixosModules.default", default_block)
        self.assertIn("ai", default_block)
        self.assertIn("core", default_block)
        self.assertIn("copyparty.overlays.default", default_block)

    def test_feature_gate_is_unprivileged_and_polkit_is_unit_scoped(self) -> None:
        identities = text("modules/nas/config/identities.nix")
        units = text("modules/nas/config/systemd-services.nix")
        self.assertIn("users.users.nas-feature-gate", identities)
        self.assertIn('subject.user === "nas-feature-gate"', identities)
        self.assertIn('action.id === "org.freedesktop.systemd1.manage-units"', identities)
        self.assertIn("lib.attrValues featureCatalog.features", identities)
        self.assertIn("entry.stopUnits or [ ]", identities)
        self.assertIn('User = "nas-feature-gate";', units)
        self.assertNotIn('User = "root";', units.split("nas-on-demand-gate", 1)[1].split("};", 1)[0])

    def test_cockpit_mutations_dispatch_through_systemd_units(self) -> None:
        source = text("services/nas_cockpit_api.py")
        action_block = source.split("ACTIONS:", 1)[1].split("\n\n\ndef diagnostic", 1)[0]
        self.assertNotIn('("sanoid",', action_block)
        self.assertNotIn('("zpool",', action_block)
        self.assertNotIn('("nas-update",', action_block)
        for unit in (
            "nas-zfs-manual-snapshot.service",
            "nas-zfs-manual-scrub.service",
            "nas-update-preview.service",
            "nas-update-sync.service",
            "nas-update-apply.service",
        ):
            self.assertIn(unit, action_block)
            self.assertIn(unit.removesuffix(".service"), text("modules/nas/config/systemd-services.nix"))

    def test_runtime_account_token_is_scoped_and_bootstrap_is_not_routine(self) -> None:
        identity = text("services/nas_identity_sync.py")
        blueprint = text("authentik/blueprints/nas-user-settings.yaml")
        self.assertIn("bootstrap-runtime-token", identity)
        self.assertIn("NAS automation", blueprint)
        self.assertIn("authentik_core.enable_group_superuser", blueprint)
        apply_block = identity.split('if args.command == "apply-accounts":', 1)[1].split(
            "\n        if args.command", 1
        )[0]
        self.assertNotIn("bootstrap=True", apply_block)

    def test_setup_and_account_inputs_have_closed_schemas(self) -> None:
        validation = text("scripts/validate-repository-data.py")
        for relative in ("schemas/first-run.schema.json", "schemas/account-plan.schema.json"):
            schema = text(relative)
            self.assertIn('"additionalProperties": false', schema)
            self.assertIn(relative, validation)

    def test_python_is_packaged_as_one_application(self) -> None:
        package = text("modules/nas/internal/account-tools.nix")
        pyproject = text("pyproject.toml")
        self.assertIn("buildPythonApplication", package)
        for entrypoint in ("nas-cockpit-api", "nas-feature-control", "nas-identity-sync", "nas-setup"):
            self.assertIn(entrypoint, pyproject)

    def test_preflight_and_release_publication_distinguish_complete_evidence(self) -> None:
        preflight = text("scripts/preflight.sh")
        package = text("scripts/package-release.sh")
        self.assertIn("NAS_PREFLIGHT_REQUIRE_COMPLETE", preflight)
        self.assertIn("write_status partial", preflight)
        self.assertIn("--source-only", package)
        self.assertIn("provenance", package)
        self.assertIn("MANIFEST.sha256", package)

    def test_backup_policy_requires_disk_staging_and_independent_recovery(self) -> None:
        options = text("modules/nas/options/operations.nix")
        storage = text("modules/nas/config/storage-monitoring.nix")
        validation = text("modules/nas/config/validation.nix")
        self.assertIn('default = "/var/lib/nas-backup/staging";', options)
        self.assertIn("stagingMinFreeBytes", options)
        self.assertIn("backupStage", storage)
        self.assertNotIn("/run/nas-backup-stage", storage)
        self.assertIn("allowSamePoolRepository", validation)
        self.assertIn("off-pool Restic repository or enabled ZFS replication", validation)

    def test_firewall_baseline_is_exact_and_cockpit_fails_closed(self) -> None:
        firewall = text("modules/nas/config/network-firewall.nix")
        system = text("modules/nas/config/system.nix")
        self.assertNotIn("networking.nftables.enable", firewall)
        self.assertIn("nas-firewall-baseline", firewall)
        self.assertNotIn("baseline-schema-version", firewall)
        self.assertIn("nas-management-network-guard", firewall)
        self.assertIn("nas-owned-zone.xml", firewall)
        self.assertIn("--query-service", firewall)
        self.assertIn("--query-port", firewall)
        self.assertNotIn("runtimeSafetyCommands", firewall)
        self.assertNotIn('rule: "${firewallCmd} --permanent', firewall)
        self.assertIn("nas-management-network-guard.service", system)

    def test_authentik_has_one_non_secret_config_channel_and_distinct_runtime_dirs(self) -> None:
        services = text("modules/nas/config/application-services.nix")
        self.assertNotIn("AUTHENTIK_LISTEN__", services)
        self.assertNotIn("AUTHENTIK_WEB__", services)
        for directory in ("authentik-migrate", "authentik-worker", "authentik-server"):
            self.assertIn(f'RuntimeDirectory = "{directory}";', services)

    def test_host_compatibility_policy_is_not_hidden_in_reusable_module(self) -> None:
        reusable = "\n".join(path.read_text(encoding="utf-8") for path in (ROOT / "modules").rglob("*.nix"))
        self.assertNotIn("system.stateVersion", reusable)
        self.assertIn('system.stateVersion = "26.05";', text("local.nix"))
        self.assertIn('[ "x86_64-linux" ]', text("modules/nas/internal/base.nix"))

    def test_victoriametrics_stack_has_no_prometheus_runtime_dependencies(self) -> None:
        observability = text("modules/nas/config/observability.nix")
        self.assertIn("services.victoriametrics", observability)
        self.assertIn("services.telegraf", observability)
        self.assertIn("AmbientCapabilities = lib.mkForce [ ];", observability)
        self.assertIn('RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];', observability)
        self.assertIn("systemd.services.nas-alert-router", observability)
        self.assertIn("grafanaPlugins.victoriametrics-metrics-datasource", observability)
        self.assertIn('type = "victoriametrics-metrics-datasource";', observability)
        self.assertNotIn("services.prometheus", observability)
        self.assertNotIn("prometheus-alertmanager", observability)
        self.assertNotIn('type = "prometheus";', observability)
        self.assertFalse((ROOT / "packages/alertmanager-bin.nix").exists())
        authentik = text("modules/nas/config/application-services.nix")
        self.assertNotIn("PROMETHEUS_MULTIPROC_DIR", authentik)
        self.assertNotIn("authentik-metrics", authentik)

    def test_scheduler_state_uses_the_declared_backend_name(self) -> None:
        tools = text("modules/nas/internal/account-tools.nix")
        self.assertIn('cfg.scheduler.backend == "cockpit-scheduler"', tools)
        self.assertNotIn('cfg.scheduler.backend == "cockpit"', tools)

    def test_update_rollback_tracks_persistent_profile_mutation(self) -> None:
        update = text("scripts/update-nas.sh")
        for marker in ("old_profile", "new_profile", "switch_attempted", "--rollback"):
            self.assertIn(marker, update)

    def test_mkforce_is_machine_allowlisted(self) -> None:
        result = subprocess.run(
            ["python3", str(ROOT / "scripts/check-mkforce.py")],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_ci_has_fixed_runner_concurrency_and_direct_dependency_ordering(self) -> None:
        workflow = text(".github/workflows/ci.yml")
        self.assertIn("cancel-in-progress: true", workflow)
        self.assertNotIn("ubuntu-latest", workflow)
        self.assertIn("check-coverage.py", workflow)
        for retired_gate in ("prebuild-gate:", "build-gate:", "runtime-gate:", "final-system-gate:"):
            self.assertNotIn(retired_gate, workflow)
        self.assertIn(
            "needs: [test, test-nonroot, security, caddy-validate, static, dependency-audit, coverage-diff]", workflow
        )
        self.assertGreaterEqual(workflow.count("needs: [build]"), 2)
        self.assertIn("needs: [integration, browser, build]", workflow)
        self.assertIn("needs: [integration, browser, installer]", workflow)

    def test_mutable_state_has_versioned_export_diff_validate_and_restore(self) -> None:
        pyproject = text("pyproject.toml")
        state = text("services/nas_state.py")
        schema = text("schemas/state-bundle.schema.json")
        self.assertIn('nas-state = "nas_state:main"', pyproject)
        for command in ("export", "validate", "diff", "restore"):
            self.assertIn(f'add_parser("{command}"', state)
        self.assertIn('"const": 2', schema)
        self.assertIn("registryDigest", schema)
        self.assertIn("producerVersion", schema)
        self.assertIn("rollbackBundle", state)

    def test_profiles_keep_optional_services_out_of_base_defaults(self) -> None:
        flake = text("flake.nix")
        local = text("local.nix")
        for profile in ("core-storage", "identity-sharing", "observability", "virtualization", "local-ai"):
            self.assertIn(profile, flake)
        for relative in (
            "modules/profiles/core-storage.nix",
            "modules/profiles/identity-sharing.nix",
            "modules/profiles/observability.nix",
            "modules/profiles/virtualization.nix",
            "modules/profiles/local-ai.nix",
        ):
            self.assertTrue((ROOT / relative).is_file())
        self.assertIn("./modules/profiles/core-storage.nix", local)
        self.assertIn("./modules/profiles/identity-sharing.nix", local)

    def test_service_registry_is_generated_and_consumed(self) -> None:
        registry = text("modules/nas/internal/service-registry.nix")
        system = text("modules/nas/config/system.nix")
        cockpit = text("services/nas_cockpit_api.py")
        schema = text("schemas/service-registry.schema.json")
        for service in ("identity", "cockpit", "aiApi", "syncthing", "vaultwarden", "grafana"):
            self.assertIn(f"{service} = mkService", registry)
        self.assertIn("endpoints.json", system)
        self.assertIn("NAS_ENDPOINT_REGISTRY", cockpit)
        self.assertIn('"additionalProperties": false', schema)

    def test_backup_restore_verification_is_isolated_and_scheduled(self) -> None:
        storage = text("modules/nas/config/storage-monitoring.nix")
        schedules = text("modules/nas/config/schedules.nix")
        validation = text("modules/nas/config/validation.nix")
        self.assertIn("nas-backup-restore-verify", storage)
        self.assertIn("restic", storage)
        self.assertIn("pg_restore", storage)
        self.assertIn("PRAGMA integrity_check", storage)
        self.assertIn("django_migrations", storage)
        self.assertIn('install -d -m 0711 "$verify_root"', storage)
        self.assertIn("stagingMinFreeBytes", storage)
        self.assertIn("nas-backup-restore-verify", schedules)
        self.assertIn("restoreVerification.targetPath", validation)
        self.assertNotIn("/run/nas-backup", storage)

    def test_release_metadata_has_one_machine_checked_version(self) -> None:
        preflight = text("scripts/preflight.sh")
        structure = text("scripts/validate-structure.py")
        self.assertIn("check-version.py", preflight)
        self.assertIn("check-version.py", structure)
        result = subprocess.run(
            ["python3", str(ROOT / "scripts/check-version.py")],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
