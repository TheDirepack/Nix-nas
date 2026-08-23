from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


class Alpha18HardeningContracts(unittest.TestCase):
    def test_managed_services_v2_schema_is_the_service_authority(self) -> None:
        schema = json.loads(text("schemas/managed-services-v3.schema.json"))
        spec = text("services/nas_v2_spec.py")
        default_module = text("modules/nas/default.nix")
        self.assertEqual(schema["properties"]["schemaVersion"]["const"], 3)
        self.assertIn("compile_document", spec)
        for module in (
            "managed-services.nix",
            "managed-services-seed-v2.nix",
        ):
            self.assertIn(module, default_module)
        self.assertNotIn("managed-services-v2.nix", default_module)
        self.assertFalse((ROOT / "modules/nas/internal/feature-catalog.nix").exists())
        self.assertFalse((ROOT / "modules/nas/internal/service-registry.nix").exists())
        self.assertFalse((ROOT / "schemas/service-registry.schema.json").exists())

    def test_flake_exports_modules_directly(self) -> None:
        flake = text("flake.nix")
        self.assertFalse((ROOT / "nas-module.nix").exists())
        self.assertFalse((ROOT / "ai-module.nix").exists())
        self.assertIn("core = import ./modules/nas;", flake)
        self.assertIn("ai = import ./modules/ai;", flake)
        default_block = flake.split("default = { ... }:", 1)[1].split("profiles =", 1)[0]
        self.assertIn("copyparty.nixosModules.default", default_block)
        self.assertIn("copyparty.overlays.default", default_block)

    def test_legacy_feature_gate_privilege_surface_is_removed(self) -> None:
        tree = "\n".join(
            path.read_text(encoding="utf-8", errors="replace")
            for root in (ROOT / "modules", ROOT / "services")
            for path in root.rglob("*")
            if path.is_file() and path.suffix in {".nix", ".py"}
        )
        self.assertNotIn("nas-feature-control", tree)
        self.assertNotIn("nas-feature-gate", tree)
        self.assertNotIn("nas-on-demand-gate", tree)
        self.assertNotIn("nas-feature-apply", tree)
        self.assertFalse((ROOT / "modules/nas/config/managed-services-legacy-disable.nix").exists())

    def test_cockpit_mutations_dispatch_through_systemd_units(self) -> None:
        source = text("services/nas_cockpit_api.py")
        action_block = source.split("ACTIONS:", 1)[1].split("\n\n\ndef diagnostic", 1)[0]
        for unit in (
            "nas-zfs-manual-snapshot.service",
            "nas-zfs-manual-scrub.service",
            "nas-update-preview.service",
            "nas-update-sync.service",
            "nas-update-apply.service",
        ):
            self.assertIn(unit, action_block)
        self.assertNotIn('("zpool",', action_block)
        self.assertNotIn('("nas-update",', action_block)

    def test_setup_and_account_inputs_have_closed_schemas(self) -> None:
        validation = text("scripts/validate-repository-data.py")
        for relative in ("schemas/first-run.schema.json", "schemas/account-plan.schema.json"):
            schema = text(relative)
            self.assertIn('"additionalProperties": false', schema)
            self.assertIn(relative, validation)

    def test_python_is_packaged_as_one_v2_application(self) -> None:
        package = text("modules/nas/internal/account-tools.nix")
        pyproject = text("pyproject.toml")
        self.assertIn("buildPythonApplication", package)
        for entrypoint in (
            "nas-cockpit-api",
            "nas-identity-sync",
            "nas-setup",
            "nas-managed-services",
            "nas-managed-services-control",
            "nas-managed-session",
        ):
            self.assertIn(entrypoint, pyproject)
        for retired in ("nas-feature-control", "nas-managed-service", "nas-migrate-state"):
            self.assertNotIn(f'{retired} = "', pyproject)

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

    def test_firewall_baseline_is_exact_and_cockpit_fails_closed(self) -> None:
        firewall = text("modules/nas/config/network-firewall.nix")
        system = text("modules/nas/config/system.nix")
        caddy = text("modules/nas/config/caddy-bootstrap.nix")
        self.assertIn("nas-firewall-baseline", firewall)
        self.assertIn("nas-management-network-guard", firewall)
        self.assertIn("nas-owned-zone.xml", firewall)
        self.assertIn("--query-service", firewall)
        self.assertIn("--query-port", firewall)
        self.assertIn("systemd.sockets.cockpit.enable = false;", system)
        self.assertIn("nas-management-network-guard.service", caddy)

    def test_authentik_has_one_non_secret_config_channel_and_distinct_runtime_dirs(self) -> None:
        services = text("modules/nas/config/application-services.nix")
        self.assertIn('AUTHENTIK_LISTEN__HTTP="127.0.0.1:${toString authentikOutpostPort}"', services)
        self.assertNotIn("AUTHENTIK_WEB__", services)
        for directory in ("authentik-migrate", "authentik-worker", "authentik-server"):
            self.assertIn(f'RuntimeDirectory = "{directory}";', services)

    def test_host_compatibility_policy_is_not_hidden_in_reusable_module(self) -> None:
        reusable = "\n".join(path.read_text(encoding="utf-8") for path in (ROOT / "modules").rglob("*.nix"))
        self.assertNotRegex(reusable, r"system\.stateVersion\s*=")
        self.assertIn('system.stateVersion = "26.05";', text("local.nix"))
        self.assertIn('[ "x86_64-linux" ]', text("modules/nas/internal/base.nix"))

    def test_victoriametrics_stack_has_no_prometheus_runtime_dependencies(self) -> None:
        observability = text("modules/nas/config/observability.nix")
        self.assertIn("services.victoriametrics", observability)
        self.assertIn("services.telegraf", observability)
        self.assertIn("systemd.services.nas-alert-router", observability)
        self.assertNotIn("services.prometheus", observability)
        self.assertNotIn("prometheus-alertmanager", observability)

    def test_mutable_state_has_versioned_export_diff_validate_and_restore(self) -> None:
        state = text("services/nas_state.py")
        schema = text("schemas/state-bundle.schema.json")
        self.assertIn('nas-state = "nas_state:main"', text("pyproject.toml"))
        for command in ("export", "validate", "diff", "restore"):
            self.assertIn(f'add_parser("{command}"', state)
        self.assertIn('"const": 2', schema)
        self.assertIn("registryDigest", schema)
        self.assertIn("rollbackBundle", state)

    def test_profiles_keep_optional_services_out_of_base_defaults(self) -> None:
        flake = text("flake.nix")
        for profile in ("core-storage", "identity-sharing", "observability", "virtualization", "local-ai"):
            self.assertIn(profile, flake)
            self.assertTrue((ROOT / "modules/profiles" / f"{profile}.nix").is_file())

    def test_mkforce_and_version_contracts_remain_machine_checked(self) -> None:
        for script in ("check-mkforce.py", "check-version.py"):
            result = subprocess.run(
                ["python3", str(ROOT / "scripts" / script)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
