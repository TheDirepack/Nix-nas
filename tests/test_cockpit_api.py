from __future__ import annotations

import contextlib
import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

SPEC = importlib.util.spec_from_file_location("nas_cockpit_api", SERVICES / "nas_cockpit_api.py")
assert SPEC and SPEC.loader
api = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = api
SPEC.loader.exec_module(api)


class CockpitApiTests(unittest.TestCase):
    def completed(self, *, returncode: int = 0, stdout: str = "", stderr: str = ""):
        return mock.Mock(returncode=returncode, stdout=stdout, stderr=stderr)

    def test_managed_service_rejects_hostile_identifier_before_lock_or_subprocess(self) -> None:
        with mock.patch.object(api, "acquire_operation") as lock, mock.patch.object(api, "run") as run:
            with self.assertRaisesRegex(api.ApiError, "service identifier"):
                api.set_managed_service("../escape", "always")
        lock.assert_not_called()
        run.assert_not_called()

    def test_managed_service_uses_only_canonical_v2_control_command(self) -> None:
        active = mock.Mock(coordination_token="coord-token")
        with (
            mock.patch.object(api, "acquire_operation", return_value=contextlib.nullcontext(active)) as lock,
            mock.patch.object(api, "run", return_value=self.completed(stdout='{"ok":true}\n')) as run,
        ):
            self.assertEqual(api.set_managed_service("ai-workspace", "on-demand"), {"ok": True})
        lock.assert_called_once_with("managed-service-policy", ("runtime",))
        command = run.call_args.args[0]
        self.assertEqual(command, ["nas-managed-services-control", "set", "ai-workspace", "on-demand"])
        self.assertNotIn("nas-feature-control", command)
        self.assertEqual(run.call_args.kwargs["env"]["NAS_OPERATION_COORDINATION_TOKEN"], "coord-token")

    def test_managed_services_status_fails_closed_on_invalid_json(self) -> None:
        with mock.patch.object(api, "run", return_value=self.completed(stdout="not-json")):
            value = api.managed_services_status()
        self.assertFalse(value["ok"])
        self.assertEqual(value["services"], [])

    def test_portal_entries_accept_only_v2_projection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "portal.json"
            path.write_text(
                json.dumps(
                    {
                        "schemaVersion": 2,
                        "source": "managed-services-v2",
                        "entries": [{"id": "files.web", "label": "Files", "url": "/shares/"}],
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch.object(api, "PORTAL_MODEL", path):
                self.assertEqual(api.portal_entries()[0]["id"], "files.web")
            path.write_text(json.dumps({"source": "legacy", "entries": [{"id": "bad"}]}), encoding="utf-8")
            with mock.patch.object(api, "PORTAL_MODEL", path):
                self.assertEqual(api.portal_entries(), [])

    def test_static_links_are_same_origin_paths(self) -> None:
        links = api.static_links()
        self.assertTrue(links)
        self.assertTrue(all(value.startswith("/") and not value.startswith("//") for value in links.values()))

    def test_operation_state_exposes_v2_lifecycle_conflicts(self) -> None:
        with mock.patch.object(api, "shared_operation_state", return_value={"busyClasses": ["runtime"], "active": []}):
            value = api.operation_state()
        self.assertEqual(value["managedServicesConflicts"], ["runtime"])

    def test_unknown_action_fails_before_subprocess(self) -> None:
        with (
            mock.patch.object(api, "managed_services_status", return_value={"services": []}),
            mock.patch.object(api, "run") as run,
        ):
            with self.assertRaisesRegex(api.ApiError, "Unknown action"):
                api.run_action("reboot")
        run.assert_not_called()

    def test_v2_jobs_are_discovered_and_started_through_the_compiled_owner_unit(self) -> None:
        with (
            mock.patch.object(
                api,
                "managed_services_status",
                return_value={
                    "services": [
                        {
                            "id": "snapshot",
                            "label": "Create snapshot",
                            "description": "",
                            "managed": True,
                            "effective": True,
                            "workloadKind": "job",
                            "units": [{"unit": "nas-zfs-manual-snapshot.service", "role": "owner"}],
                        }
                    ]
                },
            ),
            mock.patch.object(api, "run", return_value=self.completed(stdout="started")) as run,
        ):
            self.assertEqual(api.managed_job_rows()[0]["id"], "snapshot")
            result = api.run_action("snapshot")
        self.assertTrue(result["ok"])
        run.assert_called_once_with(
            ("systemctl", "start", "nas-zfs-manual-snapshot.service"),
            check=False,
            timeout_seconds=21600,
        )

    def test_first_start_request_validates_plan_and_duplicate_devices_before_reservation(self) -> None:
        request = {
            "password": "database-password",
            "planDigest": "a" * 64,
            "devices": ["/dev/disk/by-id/a", "/dev/disk/by-id/a"],
            "administrator": {
                "username": "nasadmin",
                "name": "NAS Administrator",
                "email": "admin@example.test",
                "password": "administrator-password",
            },
        }
        with mock.patch.object(api, "reserve_operation") as reserve:
            with self.assertRaisesRegex(api.ApiError, "duplicates"):
                api.start_first_start(request)
        reserve.assert_not_called()

    def test_first_start_job_id_is_strict(self) -> None:
        with self.assertRaisesRegex(api.ApiError, "job identifier"):
            api.first_start_job_status("../etc/passwd")

    def test_json_helpers_reject_wrong_shapes_and_nul(self) -> None:
        with self.assertRaises(api.ApiError):
            api._json_string({"value": "bad\x00value"}, "value")
        with self.assertRaises(api.ApiError):
            api._json_string_list({"values": ["ok", 7]}, "values")

    def test_ai_local_model_update_is_runtime_coordinated(self) -> None:
        request = {
            "id": "local-qwen",
            "path": "/tank/ai/models/qwen.gguf",
            "context": 32768,
            "ttl": 300,
            "tools": True,
            "extraArgs": ["--flash-attn=on"],
        }
        with (
            mock.patch.object(api, "acquire_operation", return_value=contextlib.nullcontext()) as lock,
            mock.patch.object(api.ai_config, "set_local_model", return_value={"ok": True}) as setter,
        ):
            self.assertTrue(api.set_ai_local_model(request)["ok"])
        lock.assert_called_once_with("ai-local-model-set", ("runtime",))
        setter.assert_called_once_with(
            "local-qwen",
            "/tank/ai/models/qwen.gguf",
            context=32768,
            ttl=300,
            tools=True,
            extra_args=["--flash-attn=on"],
        )

    def test_ai_role_and_advanced_updates_are_runtime_coordinated(self) -> None:
        with (
            mock.patch.object(api, "acquire_operation", return_value=contextlib.nullcontext()) as lock,
            mock.patch.object(api.ai_config, "set_role", return_value={"ok": True}) as role,
            mock.patch.object(api.ai_config, "replace_advanced", return_value={"ok": True}) as advanced,
        ):
            self.assertTrue(
                api.set_ai_role(
                    {"role": "coding/default", "targets": ["cloud/coder"], "strategy": "pin", "spillover": 1}
                )["ok"]
            )
            self.assertTrue(api.set_ai_advanced({"globalTTL": 300})["ok"])
        self.assertEqual(lock.call_count, 2)
        role.assert_called_once_with("coding/default", ["cloud/coder"], strategy="pin", spillover=1)
        advanced.assert_called_once_with({"globalTTL": 300})

    def test_source_control_rejects_unknown_operation_before_filesystem_or_subprocess(self) -> None:
        with mock.patch.object(api, "run") as run:
            with self.assertRaisesRegex(api.ApiError, "Unsupported"):
                api.source_control({"operation": "shell"})
        run.assert_not_called()

    def test_parser_contains_only_current_v2_and_appliance_commands(self) -> None:
        parser = api.build_parser()
        help_text = parser.format_help()
        self.assertNotIn("feature", help_text.lower())
        with self.assertRaises(SystemExit):
            parser.parse_args(["feature", "ai", "always"])
        parsed = parser.parse_args(["managed-service", "ai-workspace", "always"])
        self.assertEqual(parsed.service, "ai-workspace")


if __name__ == "__main__":
    unittest.main()
