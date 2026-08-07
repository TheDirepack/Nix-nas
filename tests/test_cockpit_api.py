from __future__ import annotations

import importlib.util
import io
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))
SPEC = importlib.util.spec_from_file_location("nas_cockpit_api", ROOT / "services" / "nas_cockpit_api.py")
assert SPEC and SPEC.loader
api = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = api
SPEC.loader.exec_module(api)


class CockpitApiTests(unittest.TestCase):
    def completed(self, *, returncode: int = 0, stdout: str = "", stderr: str = ""):
        return mock.Mock(returncode=returncode, stdout=stdout, stderr=stderr)

    def test_every_allowlisted_action_runs_only_its_declared_commands(self):
        for name, spec in api.ACTIONS.items():
            calls: list[tuple[str, ...]] = []
            patches = {
                "BACKUP_INSTALLED": True,
                "ZFS_REPLICATION_INSTALLED": True,
                "SYNCTHING_INSTALLED": True,
            }
            with (
                self.subTest(action=name),
                mock.patch.multiple(api, **patches),
                mock.patch.object(
                    api,
                    "run",
                    side_effect=lambda command, **_kwargs: calls.append(tuple(command)) or self.completed(),
                ),
                mock.patch.object(api, "operation_guard", side_effect=lambda *_args: __import__("contextlib").nullcontext()),
            ):
                result = api.safe_action(name)
                self.assertTrue(result["ok"])
                self.assertEqual(calls, list(spec.commands))

    def test_operation_guard_reports_and_rejects_conflicting_work(self):
        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch.dict(
                api.shared_operation_state.__globals__,
                {"OPERATION_ROOT": pathlib.Path(temporary)},
            ),
        ):
            with api.operation_guard("first", ("storage",)):
                state = api.operation_state()
                self.assertIn("storage", state["busyClasses"])
                self.assertEqual(["first"], [item["action"] for item in state["active"]])
                with mock.patch.object(api, "run") as run:
                    with self.assertRaisesRegex(api.ApiError, "conflicts with scrub"):
                        api.safe_action("scrub")
                    run.assert_not_called()
            self.assertNotIn("storage", api.operation_state()["busyClasses"])

    def test_worker_owned_actions_do_not_hold_conflicting_api_lock(self):
        for action in ("identity-sync", "update-preview", "update-sync", "update-apply", "protected-restart", "syncthing-reconcile"):
            with (
                self.subTest(action=action),
                mock.patch.object(api, "SYNCTHING_INSTALLED", True),
                mock.patch.object(api, "operation_guard") as guard,
                mock.patch.object(api, "run", return_value=self.completed()),
            ):
                api.safe_action(action)
                guard.assert_not_called()

    def test_worker_owned_actions_map_to_lock_owning_workers(self):
        expected = {
            "identity-sync": "nas-identity-sync.service",
            "update-preview": "nas-update-preview.service",
            "update-sync": "nas-update-sync.service",
            "update-apply": "nas-update-apply.service",
            "protected-restart": "nas-protected-restart.service",
            "syncthing-reconcile": "nas-syncthing-sync.service",
        }
        self.assertEqual(
            {
                name: spec.commands[0][2]
                for name, spec in api.ACTIONS.items()
                if spec.worker_owns_operation
            },
            expected,
        )
        systemd = (ROOT / "modules" / "nas" / "config" / "systemd-services.nix").read_text(encoding="utf-8")
        updater = (ROOT / "scripts" / "update-nas.sh").read_text(encoding="utf-8")
        self.assertIn("nas-protected-restart =", systemd)
        self.assertIn("--action protected-restart --class identity --class runtime", systemd)
        self.assertIn("operation_class=update", updater)
        self.assertIn('if $apply || $sync; then', updater)
        self.assertIn('exec "$operation_runner" --action nas-update --class "$operation_class"', updater)

    def test_feature_mutation_delegates_operation_lock_to_worker(self):
        with (
            mock.patch.object(api, "operation_guard") as guard,
            mock.patch.object(api, "json_command", return_value={"ok": True}) as command,
        ):
            self.assertEqual(api.set_feature("ai", "on-demand"), {"ok": True})
        guard.assert_not_called()
        command.assert_called_once_with(["nas-feature-control", "set", "ai", "on-demand"])

    def test_optional_actions_fail_before_spawning_when_not_installed(self):
        cases = [
            ("backup", "BACKUP_INSTALLED", "Backup support"),
            ("zfs-replicate", "ZFS_REPLICATION_INSTALLED", "ZFS replication"),
            ("syncthing-reconcile", "SYNCTHING_INSTALLED", "Syncthing support"),
        ]
        for action, flag, message in cases:
            with self.subTest(action=action), mock.patch.object(api, flag, False), mock.patch.object(api, "run") as run:
                with self.assertRaisesRegex(api.ApiError, message):
                    api.safe_action(action)
                run.assert_not_called()

    def test_action_failure_is_redacted_and_stops_dispatch(self):
        with (
            mock.patch.object(api, "diagnostic") as diagnostic,
            mock.patch.object(api, "run", return_value=self.completed(returncode=1, stderr="denied")),
            mock.patch.object(api, "operation_guard", side_effect=lambda *_args: __import__("contextlib").nullcontext()),
        ):
            with self.assertRaisesRegex(api.ApiError, r"Operation failed \(reference [0-9a-f]{12}\)") as raised:
                api.safe_action("scrub")
        self.assertNotIn("denied", str(raised.exception))
        self.assertIn("denied", diagnostic.call_args.args[0])

    def test_action_timeout_uses_declared_limit(self):
        with (
            mock.patch.object(api, "run", return_value=self.completed()) as run,
            mock.patch.object(api, "operation_guard", side_effect=lambda *_args: __import__("contextlib").nullcontext()),
        ):
            api.safe_action("scrub")
        run.assert_called_once_with(
            ("systemctl", "start", "nas-zfs-manual-scrub.service"),
            check=False,
            timeout_seconds=api.ACTIONS["scrub"].timeout_seconds,
        )

    def test_unknown_action_is_rejected_without_subprocess(self):
        with mock.patch.object(api, "run") as run:
            with self.assertRaisesRegex(api.ApiError, "Unknown action"):
                api.safe_action("reboot")
            run.assert_not_called()

    def test_feature_identifier_is_validated_before_subprocess(self):
        with mock.patch.object(api, "json_command") as command:
            with self.assertRaises(api.ApiError):
                api.set_feature("../root", "always")
            command.assert_not_called()

    def test_validate_argument_rejects_path_metacharacters_and_oversized_values(self):
        for value in ("../root", "bad value", "feature;reboot", "x" * (api.MAX_ARGUMENT_LENGTH + 1)):
            with self.subTest(value=value):
                with self.assertRaisesRegex(api.ApiError, "Invalid feature identifier"):
                    api.validate_argument(value, api.FEATURE_RE, "feature identifier")

    def test_validate_argument_accepts_only_the_documented_feature_shape(self):
        for value in ("ai", "ai-runtime", "feature_2", "ZfsTools"):
            with self.subTest(value=value):
                self.assertEqual(api.validate_argument(value, api.FEATURE_RE, "feature identifier"), value)

    def test_action_specs_use_only_literal_allowlisted_programs(self):
        allowed = {"systemctl"}
        for name, spec in api.ACTIONS.items():
            with self.subTest(action=name):
                self.assertTrue(spec.commands)
                for command in spec.commands:
                    self.assertIsInstance(command, tuple)
                    self.assertGreater(len(command), 0)
                    self.assertIn(command[0], allowed)
                    self.assertTrue(all(isinstance(argument, str) and argument for argument in command))

    def test_capabilities_route_behaviorally_through_identity_sync(self):
        with mock.patch.object(api, "json_command", return_value={"users": []}) as command:
            self.assertEqual(api.capability_status(), {"users": []})
        command.assert_called_once_with(["nas-identity-sync", "capabilities"], optional=True)

    def test_endpoint_links_use_only_available_registry_entries(self):
        with mock.patch.object(
            api.pathlib.Path,
            "read_text",
            return_value=json.dumps(
                {
                    "schemaVersion": 1,
                    "endpoints": {
                        "identity": {"available": True, "linkKey": "identity", "publicPath": "/identity/"},
                        "disabled": {"available": False, "linkKey": "disabled", "publicPath": "/disabled/"},
                        "internal": {"available": True, "linkKey": None, "publicPath": "/internal/"},
                    },
                }
            ),
        ):
            self.assertEqual({"identity": "/identity/"}, api.endpoint_links())

    def test_endpoint_links_fail_closed_on_invalid_registry(self):
        path = mock.Mock()
        path.read_text.return_value = '{"schemaVersion":2,"endpoints":{}}'
        self.assertEqual({}, api.endpoint_links(path))

    def test_optional_warning_file_disappearing_is_safe(self):
        path = mock.Mock()
        path.read_text.side_effect = FileNotFoundError
        self.assertIsNone(api.read_optional_text(path))

    def test_service_states_accepts_crlf_and_blank_line_whitespace(self):
        output = (
            "Id=one.service\r\nActiveState=active\r\nUnitFileState=enabled\r\n\r\n"
            "  \r\nId=two.service\r\nActiveState=inactive\r\nUnitFileState=disabled\r\n"
        )
        with mock.patch.object(api, "run", return_value=self.completed(stdout=output)):
            states = api.service_states(["one.service", "two.service"])
        self.assertEqual([state["active"] for state in states], ["active", "inactive"])


    def test_ai_provider_update_keeps_secrets_on_stdin_and_uses_parent_coordination(self):
        active = mock.Mock(coordination_token="coord-token")
        request = {
            "id": "openrouter",
            "url": "https://openrouter.ai/api",
            "models": ["qwen/qwen3"],
            "apiKey": "sk-provider-secret",
            "keepassPassword": "db-password",
            "timeouts": {"connect": 30},
            "filters": {"stripParams": "top_k", "setParams": {}},
        }
        with (
            mock.patch.object(api, "acquire_operation", return_value=__import__("contextlib").nullcontext(active)) as lock,
            mock.patch.object(api, "run", return_value=self.completed()) as run,
            mock.patch.object(api.ai_config, "set_provider", return_value={"ok": True}) as configure,
        ):
            result = api.set_ai_provider(request)
        self.assertTrue(result["ok"])
        lock.assert_called_once_with("ai-provider-set", ("secrets", "runtime"))
        # Find the credential staging call among possibly multiple run invocations (fetch old key, stage, restart)
        secret_calls = [
            call for call in run.call_args_list if call.args and call.args[0][:2] == ["nas-secrets", "set-ai-provider-key-stdin"]
        ]
        self.assertTrue(secret_calls, "expected nas-secrets staging call")
        secret_call = secret_calls[0]
        command = secret_call.args[0]
        self.assertEqual(command, ["nas-secrets", "set-ai-provider-key-stdin", "openrouter"])
        self.assertNotIn("sk-provider-secret", " ".join(command))
        self.assertNotIn("db-password", " ".join(command))
        self.assertEqual(secret_call.kwargs["input_text"], "db-password\nsk-provider-secret\n")
        self.assertEqual(secret_call.kwargs["env"]["NAS_OPERATION_COORDINATION_TOKEN"], "coord-token")
        self.assertEqual(secret_call.kwargs["env"]["NAS_SKIP_LLAMA_SWAP_RESTART"], "1")
        configure.assert_called_once()
        # Ensure a single restart occurs after both credential and config are committed (deferred, not intermediate)
        restart_calls = [c for c in run.call_args_list if c.args and c.args[0] == ["systemctl", "restart", "nas-llama-swap.service"]]
        self.assertTrue(restart_calls)

    def test_ai_provider_without_new_key_does_not_prompt_or_spawn_secret_writer(self):
        request = {"id": "cloud", "url": "https://cloud.example", "models": ["coder"], "apiKey": "", "keepassPassword": ""}
        active = mock.Mock(coordination_token="coord-token")
        with (
            mock.patch.object(api, "acquire_operation", return_value=__import__("contextlib").nullcontext(active)),
            mock.patch.object(api, "run", return_value=self.completed()) as run,
            mock.patch.object(api.ai_config, "set_provider", return_value={"ok": True}) as configure,
        ):
            self.assertTrue(api.set_ai_provider(request)["ok"])
        # No KeePass mutation should occur when no apiKey is provided.
        secret_calls = [c for c in (run.call_args_list or []) if c.args and c.args[0] and c.args[0][0] == "nas-secrets"]
        self.assertEqual(secret_calls, [])
        self.assertFalse(configure.call_args.kwargs["credential"])

    def test_ai_local_model_update_is_runtime_coordinated(self):
        request = {
            "id": "local-qwen",
            "path": "/tank/ai/models/qwen.gguf",
            "context": 32768,
            "ttl": 300,
            "tools": True,
            "extraArgs": ["--flash-attn=on"],
        }
        with (
            mock.patch.object(api, "operation_guard", return_value=__import__("contextlib").nullcontext()) as guard,
            mock.patch.object(api.ai_config, "set_local_model", return_value={"ok": True}) as setter,
        ):
            self.assertTrue(api.set_ai_local_model(request)["ok"])
        guard.assert_called_once_with("ai-local-model-set", ("runtime",))
        setter.assert_called_once_with(
            "local-qwen",
            "/tank/ai/models/qwen.gguf",
            context=32768,
            ttl=300,
            tools=True,
            extra_args=["--flash-attn=on"],
        )

    def test_ai_local_model_delete_is_runtime_coordinated(self):
        with (
            mock.patch.object(api, "operation_guard", return_value=__import__("contextlib").nullcontext()) as guard,
            mock.patch.object(api.ai_config, "delete_local_model", return_value={"ok": True}) as deleter,
        ):
            self.assertTrue(api.delete_ai_local_model({"id": "local-qwen"})["ok"])
        guard.assert_called_once_with("ai-local-model-delete", ("runtime",))
        deleter.assert_called_once_with("local-qwen")

    def test_ai_role_update_is_runtime_coordinated(self):
        request = {"role": "coding/default", "targets": ["cloud/coder"], "strategy": "pin", "spillover": 1}
        with (
            mock.patch.object(api, "operation_guard", return_value=__import__("contextlib").nullcontext()) as guard,
            mock.patch.object(api.ai_config, "set_role", return_value={"ok": True}) as setter,
        ):
            self.assertTrue(api.set_ai_role(request)["ok"])
        guard.assert_called_once_with("ai-role-set", ("runtime",))
        setter.assert_called_once_with("coding/default", ["cloud/coder"], strategy="pin", spillover=1)

    def test_ai_json_request_is_bounded_and_object_only(self):
        with mock.patch.object(api.sys, "stdin", mock.Mock(buffer=io.BytesIO(b'{"id":"x"}'))):
            self.assertEqual(api.read_json_request(), {"id": "x"})
        with mock.patch.object(api.sys, "stdin", mock.Mock(buffer=io.BytesIO(b'[]'))):
            with self.assertRaisesRegex(api.ApiError, "JSON object"):
                api.read_json_request()

    def test_first_start_uses_server_side_device_plan_and_password_stdin(self):
        status = {
            "status": "ready",
            "requiresDestructiveConfirmation": True,
            "storage": {"devices": ["/dev/disk/by-id/a", "/dev/disk/by-id/b"]},
            "planDigest": "a" * 64,
        }
        with (
            mock.patch.object(api, "json_command", return_value=status) as prepare,
            mock.patch.object(api.sys, "stdin", io.StringIO("keepass-password\n")),
            mock.patch.object(
                api, "start_first_start_unit", return_value={"status": "started", "operationId": "1" * 24}
            ) as start_unit,
        ):
            result = api.run_first_start(plan_digest="a" * 64, allow_destructive_storage=True)
        self.assertEqual(result["status"], "started")
        prepare.assert_called_once_with(
            ["nas-setup", "prepare-first-start", "--config", api.FIRST_RUN_CONFIG],
            optional=False,
        )
        command, password = start_unit.call_args.args
        self.assertEqual(
            command[:7],
            [
                "nas-setup",
                "first-run",
                "--config",
                api.FIRST_RUN_CONFIG,
                "--keepass-password-stdin",
                "--confirm-plan-digest",
                "a" * 64,
            ],
        )
        self.assertEqual(command.count("--confirm-storage-device"), 2)
        self.assertIn("--allow-destructive-storage", command)
        self.assertEqual(password, "keepass-password")

    def test_first_start_refuses_destructive_plan_before_reading_password(self):
        status = {
            "status": "ready",
            "requiresDestructiveConfirmation": True,
            "storage": {"devices": ["/dev/disk/by-id/a"]},
            "planDigest": "b" * 64,
        }
        with (
            mock.patch.object(api, "json_command", return_value=status),
            mock.patch.object(api, "read_secret_line") as read_secret,
        ):
            with self.assertRaisesRegex(api.ApiError, "Confirm destructive storage"):
                api.run_first_start(plan_digest="b" * 64, allow_destructive_storage=False)
        read_secret.assert_not_called()

    def test_incomplete_first_start_launch_command_does_not_reserve(self):
        with mock.patch.object(api, "reserve_operation") as reserve:
            with self.assertRaisesRegex(api.ApiError, "launch command is incomplete"):
                api.start_first_start_unit(["nas-setup", "first-run"], "master-password")
        reserve.assert_not_called()

    def test_first_start_reservation_is_persisted_before_systemd_launch(self):
        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch.dict(api.os.environ, {"NAS_OPERATION_ROOT": temporary}),
            mock.patch.dict(
                api.reserve_operation.__globals__,
                {"OPERATION_ROOT": pathlib.Path(temporary)},
            ),
            mock.patch.object(api, "run", return_value=self.completed()) as run,
        ):
            result = api.start_first_start_unit(
                [
                    "nas-setup",
                    "first-run",
                    "--confirm-plan-digest",
                    "a" * 64,
                    "--confirm-storage-device",
                    "/dev/disk/by-id/a",
                ],
                "master-password",
            )
            self.assertEqual("started", result["status"])
            request_files = list(pathlib.Path(temporary).glob("first-start-*.json"))
            self.assertEqual(1, len(request_files))
            request = json.loads(request_files[0].read_text())
            self.assertRegex(request["reservationToken"], r"^[0-9a-f]{32}$")
            self.assertTrue((pathlib.Path(temporary) / f"reservation-{request['reservationToken']}.json").is_file())
            launch = run.call_args.args[0]
            self.assertIn("run-first-start-job", launch)
            self.assertIn("--setenv=NAS_SETUP_ALLOW_ROOT=1", launch)
            self.assertNotIn("env", run.call_args.kwargs)

    def test_failed_systemd_launch_cancels_reservation_and_private_files(self):
        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch.dict(api.os.environ, {"NAS_OPERATION_ROOT": temporary}),
            mock.patch.dict(
                api.reserve_operation.__globals__,
                {"OPERATION_ROOT": pathlib.Path(temporary)},
            ),
            mock.patch.object(api, "run", return_value=self.completed(returncode=1, stderr="failed")),
        ):
            with self.assertRaises(api.ApiError):
                api.start_first_start_unit(
                    ["nas-setup", "first-run", "--confirm-plan-digest", "b" * 64],
                    "master-password",
                )
            names = {path.name for path in pathlib.Path(temporary).iterdir()}
            self.assertFalse(any(name.startswith("reservation-") for name in names))
            self.assertFalse(any(name.startswith("first-start-") for name in names))

    def test_endpoint_links_reject_scheme_relative_and_control_character_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "endpoints.json"
            path.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "endpoints": {
                            "good": {"available": True, "linkKey": "good", "publicPath": "/safe/"},
                            "schemeRelative": {"available": True, "linkKey": "bad1", "publicPath": "//evil.example/"},
                            "newline": {"available": True, "linkKey": "bad2", "publicPath": "/safe\nInjected"},
                        },
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(api.endpoint_links(path), {"good": "/safe/"})


if __name__ == "__main__":
    unittest.main()
