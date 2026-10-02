from __future__ import annotations

import ast
import contextlib
import json
import os
import subprocess
import sys
import tempfile
import pathlib
import unittest
from unittest import mock

from repo_test_utils import ROOT, text

sys.path.insert(0, str(ROOT / "services"))
import nas_cockpit_api as api  # noqa: E402
import nas_common as common  # noqa: E402
import nas_identity_model as identity  # noqa: E402
import nas_setup_config as setup  # noqa: E402
import nas_v2_caddy as caddy  # noqa: E402


class DeadPathCleanupTests(unittest.TestCase):
    def test_portal_requires_compiled_routes_not_legacy_service_routes(self):
        with self.assertRaisesRegex(caddy.PortalProjectionError, "compiled routes"):
            caddy.compile_portal_projection({"schemaVersion": 3, "services": {}})

    def test_setup_capabilities_require_current_schema_and_explicit_scope(self):
        for legacy in ("version", "scope"):
            with self.subTest(legacy=legacy), tempfile.TemporaryDirectory() as raw:
                with (
                    mock.patch.object(api, "SETUP_CAPABILITY_DIR", pathlib.Path(raw)),
                    mock.patch.object(api, "first_start_job_status", return_value={"status": "running"}),
                ):
                    token = api.issue_setup_capability("a" * 24, now=100)
                    path = api._capability_record_path(token)
                    record = json.loads(path.read_text())
                    if legacy == "version":
                        record["schemaVersion"] = 1
                    else:
                        record.pop("scope")
                    path.write_text(json.dumps(record))
                    self.assertIsNone(api.lookup_setup_capability(token, now=101))

    def test_storage_aliases_are_rejected_not_silently_normalized(self):
        for key, value in (("device", "/dev/test"), ("wipeDevice", False)):
            with self.subTest(key=key), self.assertRaisesRegex(setup.SetupError, "unknown field"):
                setup.normalize_config({"storage": {key: value}})
        storage = setup.normalize_config({"storage": {}})["storage"]
        self.assertEqual(storage["devices"], [])
        self.assertFalse(storage["wipeDevices"])

    def test_identity_roles_share_one_immutable_registry(self):
        self.assertIs(identity.RESERVED_GROUPS, setup.RESERVED_GROUPS)
        self.assertIs(identity.RESERVED_GROUPS, common.RESERVED_GROUPS)
        self.assertIsInstance(common.RESERVED_GROUPS, frozenset)

    def test_admin_override_reaches_policy_caddy_portal_and_blueprint(self):
        script = """
import nas_common as common
import nas_v2_caddy as caddy
import nas_v2_authentik_blueprint as blueprint
from test_v2_authentik_blueprint import effective
state = effective()
route = state["derived"]["routes"][0]
route.update(onDemandWake=False, target={"type":"http", "host":"127.0.0.1", "port":8080},
    proxy={"requestHeaders":{}, "removeRequestHeaders":[], "responseHeaders":{},
           "trustedIdentityHeaders":[], "requireHeaders":{}})
assert common.application_capability_allowed({"custom_admin"}, "demo")
assert "custom_admin" in caddy.generate_caddyfile(state)
assert "custom_admin" in caddy.compile_portal_projection(state)["entries"][0]["access"]["groups"]
assert '[name, "custom_admin"]' in blueprint.render_blueprint(state, public_host="nas.test")[0].decode()
"""
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=20,
            env={
                **os.environ,
                "NAS_IDENTITY_ADMIN_GROUP": "custom_admin",
                "PYTHONPATH": f"{ROOT / 'services'}:{ROOT / 'tests'}",
            },
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_single_host_action_keeps_guard_and_result(self):
        with (
            mock.patch.object(api, "operation_guard", return_value=contextlib.nullcontext()) as guard,
            mock.patch.object(api, "run", return_value=common.CommandResult(0, "ok", "")) as run,
        ):
            result = api.run_action("protected-restart")
        guard.assert_called_once_with("protected-restart", ("identity", "runtime"))
        self.assertTrue(result["ok"])
        self.assertEqual(len(result["commands"]), 1)
        self.assertEqual(run.call_count, 1)
        self.assertNotIn("ActionSpec", vars(api))
        self.assertNotIn("HOST_ACTIONS", vars(api))

    def test_unused_api_fields_and_probes_are_absent(self):
        with (
            mock.patch.object(api, "managed_services_status", return_value={"services": []}),
            mock.patch.object(api, "_json_command", return_value={}) as command,
            mock.patch.object(api, "run", return_value=common.CommandResult(0, "", "")) as run,
            mock.patch.object(api, "shared_operation_state", return_value={"busyClasses": []}),
        ):
            report = api.overview()
        self.assertTrue({"identity", "capabilities", "timers"}.isdisjoint(report))
        self.assertTrue({"workerOwnedActions", "managedJobs", "firstStartConflicts"}.isdisjoint(report["operations"]))
        self.assertFalse(any(call.args[0][0] == "nas-identity-sync" for call in command.call_args_list))
        self.assertFalse(any("list-timers" in call.args[0] for call in run.call_args_list))

    def test_nix_wires_ports_and_has_no_dead_production_dependencies_or_retention(self):
        accounts = text("modules/nas/internal/account-tools.nix")
        self.assertIn("export NAS_SYNCTHING_URL=http://127.0.0.1:${toString syncthingGuiPort}", accounts)
        managed = text("modules/nas/config/managed-services.nix")
        self.assertIn("NAS_V2_COCKPIT_PORT = toString nasInternal.cockpitPort;", managed)
        self.assertNotIn("pyyaml", accounts.lower())
        self.assertNotIn("pyyaml", text("modules/nas/internal/secret-tools.nix").lower())
        self.assertNotIn("rcloneExtraArgs", text("modules/nas/options/operations.nix"))
        storage = text("modules/nas/config/storage-monitoring.nix")
        for field in ("pruneOpts", "runCheck", "checkOpts"):
            self.assertNotIn(field, storage)
        profile = text("modules/nas/config/managed-services-backup-profile.nix")
        self.assertIn('"keep-daily" = 14;', profile)
        self.assertIn('"check-after" = true;', profile)

    def test_unreferenced_wrappers_are_removed(self):
        removed = {
            "nas_state.py": {"bounded"},
            "nas_v2_history.py": {"authority_matches_commit"},
            "nas_v2_spec.py": {"is_directory_authority", "hash_authority", "load_and_compile"},
            "nas_v2_apply.py": {"save_and_apply"},
            "nas_v2_network.py": {"_deny_egress_needs_firewalld"},
            "nas_logging.py": {"log_event"},
            "nas_cockpit_api.py": {
                "refresh_setup_capability",
                "revoke_setup_capability",
                "identity_status",
                "capability_status",
            },
        }
        for file, names in removed.items():
            definitions = {
                node.name for node in ast.parse(text(f"services/{file}")).body if isinstance(node, ast.FunctionDef)
            }
            self.assertTrue(names.isdisjoint(definitions), file)
