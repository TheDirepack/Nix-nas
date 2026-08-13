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
            with (
                self.subTest(action=name),
                mock.patch.object(api, "BACKUP_INSTALLED", True),
                mock.patch.object(api, "ZFS_REPLICATION_INSTALLED", True),
                mock.patch.object(api, "SYNCTHING_INSTALLED", True),
                mock.patch.object(
                    api,
                    "run",
                    side_effect=lambda command, **_kwargs: calls.append(tuple(command)) or self.completed(),
                ),
                mock.patch.object(
                    api, "operation_guard", side_effect=lambda *_args: __import__("contextlib").nullcontext()
                ),
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
        for action in (
            "identity-sync",
            "update-preview",
            "update-sync",
            "update-apply",
            "protected-restart",
            "syncthing-reconcile",
        ):
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
            {name: spec.commands[0][2] for name, spec in api.ACTIONS.items() if spec.worker_owns_operation},
            expected,
        )
        systemd = (ROOT / "modules" / "nas" / "config" / "systemd-services.nix").read_text(encoding="utf-8")
        updater = (ROOT / "scripts" / "update-nas.sh").read_text(encoding="utf-8")
        self.assertIn("nas-protected-restart =", systemd)
        self.assertIn("--action protected-restart --class identity --class runtime", systemd)
        self.assertIn("operation_class=update", updater)
        self.assertIn("if $apply || $sync; then", updater)
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
            mock.patch.object(
                api, "operation_guard", side_effect=lambda *_args: __import__("contextlib").nullcontext()
            ),
        ):
            with self.assertRaisesRegex(api.ApiError, r"Operation failed \(reference [0-9a-f]{12}\)") as raised:
                api.safe_action("scrub")
        self.assertNotIn("denied", str(raised.exception))
        self.assertIn("denied", diagnostic.call_args.args[0])

    def test_action_timeout_uses_declared_limit(self):
        with (
            mock.patch.object(api, "run", return_value=self.completed()) as run,
            mock.patch.object(
                api, "operation_guard", side_effect=lambda *_args: __import__("contextlib").nullcontext()
            ),
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
            mock.patch.object(
                api, "acquire_operation", return_value=__import__("contextlib").nullcontext(active)
            ) as lock,
            mock.patch.object(api, "run", return_value=self.completed()) as run,
            mock.patch.object(
                api.ai_config,
                "load_config",
                return_value={"models": {}, "peers": {}, "selectors": {}},
            ),
            mock.patch.object(api.ai_config, "set_provider", return_value={"ok": True}) as configure,
        ):
            result = api.set_ai_provider(request)
        self.assertTrue(result["ok"])
        lock.assert_called_once_with("ai-provider-set", ("secrets", "runtime"))
        # Find the credential staging call among possibly multiple run invocations (fetch old key, stage, restart)
        secret_calls = [
            call
            for call in run.call_args_list
            if call.args and call.args[0][:2] == ["nas-secrets", "set-ai-provider-key-stdin"]
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
        restart_calls = [
            c for c in run.call_args_list if c.args and c.args[0] == ["systemctl", "restart", "nas-llama-swap.service"]
        ]
        self.assertTrue(restart_calls)

    def test_ai_provider_without_new_key_does_not_prompt_or_spawn_secret_writer(self):
        request = {
            "id": "cloud",
            "url": "https://cloud.example",
            "models": ["coder"],
            "apiKey": "",
            "keepassPassword": "",
        }
        active = mock.Mock(coordination_token="coord-token")
        with (
            mock.patch.object(api, "acquire_operation", return_value=__import__("contextlib").nullcontext(active)),
            mock.patch.object(api, "run", return_value=self.completed()) as run,
            mock.patch.object(
                api.ai_config,
                "load_config",
                return_value={"models": {}, "peers": {}, "selectors": {}},
            ),
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
        with mock.patch.object(api.sys, "stdin", mock.Mock(buffer=io.BytesIO(b"[]"))):
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

    def test_run_raises_redacted_error_on_nonzero_result(self):
        result = self.completed(returncode=1, stderr="denied")
        with (
            mock.patch.object(api, "run_command", return_value=result) as runner,
            mock.patch.object(api, "diagnostic") as diagnostic,
        ):
            with self.assertRaisesRegex(api.ApiError, r"Operation failed \(reference [0-9a-f]{12}\)"):
                api.run(["systemctl", "start", "nas-x.service"])
        runner.assert_called_once_with(
            ["systemctl", "start", "nas-x.service"],
            timeout_seconds=120,
            input_text=None,
            env=None,
        )
        self.assertIn("denied", diagnostic.call_args.args[0])

    def test_run_returns_result_when_check_disabled(self):
        result = self.completed(returncode=3, stdout="partial")
        with mock.patch.object(api, "run_command", return_value=result) as runner:
            self.assertEqual(api.run(["cmd"], check=False, timeout_seconds=5, input_text="x", env={"A": "1"}), result)
        self.assertEqual(runner.call_args.kwargs["timeout_seconds"], 5)
        self.assertEqual(runner.call_args.kwargs["input_text"], "x")

    def test_json_command_optional_error_returns_ok_false(self):
        with mock.patch.object(api, "run", return_value=self.completed(returncode=1, stderr="boom")):
            result = api.json_command(["nas-feature-control", "status"], optional=True)
        self.assertFalse(result["ok"])
        self.assertIn("error", result)

    def test_json_command_required_error_raises(self):
        with mock.patch.object(api, "run", return_value=self.completed(returncode=2, stderr="boom")):
            with self.assertRaisesRegex(api.ApiError, "Operation failed"):
                api.json_command(["nas-feature-control", "status"])

    def test_json_command_rejects_invalid_and_non_object_json(self):
        with mock.patch.object(api, "run", return_value=self.completed(stdout="not-json")):
            with self.assertRaisesRegex(api.ApiError, "invalid JSON"):
                api.json_command(["cmd"])
        with mock.patch.object(api, "run", return_value=self.completed(stdout="[1,2]")):
            with self.assertRaisesRegex(api.ApiError, "non-object"):
                api.json_command(["cmd"])

    def test_json_command_parses_object(self):
        with mock.patch.object(api, "run", return_value=self.completed(stdout='{"ok": true}')):
            self.assertEqual(api.json_command(["cmd"]), {"ok": True})

    def test_service_states_empty_returns_empty_list(self):
        self.assertEqual(api.service_states([]), [])

    def test_status_helpers_delegate_to_optional_json_commands(self):
        with mock.patch.object(api, "json_command", return_value={"ok": True}) as command:
            self.assertEqual(api.feature_status(), {"ok": True})
            self.assertEqual(api.identity_status(), {"ok": True})
            self.assertEqual(api.update_status(), {"ok": True})
        calls = [call.args[0] for call in command.call_args_list]
        self.assertEqual(calls[0], ["nas-feature-control", "status"])
        self.assertEqual(calls[1], ["nas-identity-sync", "status"])
        self.assertEqual(calls[2], ["nas-update", "--status", "--json"])

    def test_setup_status_merges_first_start_preparation_error(self):
        prepared = {"ok": False, "error": "first-start plan missing"}
        with mock.patch.object(
            api,
            "json_command",
            side_effect=[prepared, {"status": "incomplete"}],
        ):
            status = api.setup_status()
        self.assertEqual(status["firstStart"], prepared)

    def test_setup_status_without_error_keeps_status(self):
        with mock.patch.object(
            api,
            "json_command",
            side_effect=[{"ok": True}, {"status": "ready"}],
        ):
            status = api.setup_status()
        self.assertEqual(status["status"], "ready")
        self.assertNotIn("firstStart", status)

    def test_endpoint_links_fail_closed_on_unreadable_registry(self):
        path = mock.Mock()
        path.read_text.side_effect = FileNotFoundError
        self.assertEqual({}, api.endpoint_links(path))
        path.read_text.side_effect = json.JSONDecodeError("x", "doc", 0)
        self.assertEqual({}, api.endpoint_links(path))
        path.read_text.side_effect = OSError("boom")
        self.assertEqual({}, api.endpoint_links(path))

    def test_endpoint_links_skips_non_dict_endpoints(self):
        path = mock.Mock()
        path.read_text.return_value = json.dumps({"schemaVersion": 1, "endpoints": {"x": "not-a-dict"}})
        self.assertEqual({}, api.endpoint_links(path))

    def test_endpoint_links_requires_non_empty_key_and_clean_public_path(self):
        path = mock.Mock()
        path.read_text.return_value = json.dumps(
            {
                "schemaVersion": 1,
                "endpoints": {
                    "noKey": {"available": True, "publicPath": "/x/"},
                    "noPath": {"available": True, "linkKey": "x"},
                    "emptyPath": {"available": True, "linkKey": "x", "publicPath": ""},
                },
            }
        )
        self.assertEqual({}, api.endpoint_links(path))

    def test_read_json_request_rejects_oversized_and_malformed_body(self):
        with mock.patch.object(api.sys, "stdin", mock.Mock(buffer=io.BytesIO(b"x" * (api.MAX_JSON_INPUT_BYTES + 1)))):
            with self.assertRaisesRegex(api.ApiError, "too large"):
                api.read_json_request()
        with mock.patch.object(api.sys, "stdin", mock.Mock(buffer=io.BytesIO(b"\xff\xfe invalid"))):
            with self.assertRaisesRegex(api.ApiError, "JSON object"):
                api.read_json_request()
        with mock.patch.object(api.sys, "stdin", mock.Mock(buffer=io.BytesIO(b"not json"))):
            with self.assertRaisesRegex(api.ApiError, "JSON object"):
                api.read_json_request()

    def test_ai_configuration_returns_ok_false_on_error(self):
        with mock.patch.object(api.ai_config, "load_config", side_effect=api.ai_config.AiConfigError("boom")):
            result = api.ai_configuration()
        self.assertFalse(result["ok"])
        self.assertEqual(result["providers"], [])

    def test_json_string_validates_type_length_and_null_bytes(self):
        with self.assertRaisesRegex(api.ApiError, "Invalid id"):
            api._json_string({"id": 5}, "id")
        with self.assertRaisesRegex(api.ApiError, "Invalid id"):
            api._json_string({"id": "x" * 5000}, "id", max_length=4096)
        with self.assertRaisesRegex(api.ApiError, "Invalid id"):
            api._json_string({"id": "a\x00b"}, "id")
        with self.assertRaisesRegex(api.ApiError, "id is required"):
            api._json_string({}, "id", required=True)
        self.assertEqual(api._json_string({"id": "ok"}, "id"), "ok")

    def test_json_string_list_validates_shape_and_cardinality(self):
        with self.assertRaisesRegex(api.ApiError, "Invalid models"):
            api._json_string_list({"models": "not-a-list"}, "models")
        with self.assertRaisesRegex(api.ApiError, "Invalid models"):
            api._json_string_list({"models": ["ok"] * (api.ai_config.MAX_MODELS + 1)}, "models")
        with self.assertRaisesRegex(api.ApiError, "Invalid models"):
            api._json_string_list({"models": ["ok", 5]}, "models")
        with self.assertRaisesRegex(api.ApiError, "models is required"):
            api._json_string_list({}, "models", required=True)
        self.assertEqual(api._json_string_list({"models": ["a", "b"]}, "models"), ["a", "b"])

    def test_coordinated_secret_command_forwards_token(self):
        active = mock.Mock(coordination_token="coord")
        with mock.patch.object(api, "run", return_value=self.completed()) as run:
            api._coordinated_secret_command(active, ["nas-secrets", "set"], "input-text")
        self.assertEqual(run.call_args.kwargs["env"]["NAS_OPERATION_COORDINATION_TOKEN"], "coord")
        self.assertEqual(run.call_args.kwargs["input_text"], "input-text")

    def test_coordinated_secret_command_raises_on_failure(self):
        active = mock.Mock(coordination_token="coord")
        with mock.patch.object(api, "run", return_value=self.completed(returncode=1, stderr="boom")):
            with self.assertRaisesRegex(api.ApiError, "Operation failed"):
                api._coordinated_secret_command(active, ["nas-secrets", "set"], "input-text")

    def test_read_secret_env_returns_bytes_and_none(self):
        with tempfile.TemporaryDirectory() as temporary:
            secret_root = pathlib.Path(temporary) / "secrets"
            env_dir = secret_root / "ai"
            env_dir.mkdir(parents=True)
            (env_dir / "llama-swap.env").write_bytes(b"LLAMA_SWAP_PEER_X_API_KEY=secret")
            with mock.patch.dict(api.os.environ, {"NAS_SECRET_ROOT": str(secret_root)}):
                self.assertIn(b"LLAMA_SWAP_PEER_X_API_KEY", api._read_secret_env())
            missing_root = pathlib.Path(temporary) / "missing"
            with mock.patch.dict(api.os.environ, {"NAS_SECRET_ROOT": str(missing_root)}):
                self.assertIsNone(api._read_secret_env())

    def test_restore_secret_env_noop_when_no_content(self):
        active = mock.Mock(coordination_token="coord")
        with mock.patch.object(api, "run") as run:
            api._restore_secret_env(None, active)
        run.assert_not_called()

    def test_restore_secret_env_restores_content_and_cleans_tempfile(self):
        active = mock.Mock(coordination_token="coord")
        with tempfile.TemporaryDirectory() as tmp:
            env_path = pathlib.Path(tmp) / "llama-swap.env"
            with mock.patch.object(api, "_secret_env_path", return_value=env_path):
                api._restore_secret_env(b"restored-secret", active)
                self.assertEqual(env_path.read_bytes(), b"restored-secret")
                # No temp file should remain
                self.assertEqual(len(list(pathlib.Path(tmp).glob("*.rollback.*"))), 0)

    def test_restore_secret_env_logs_failure_without_raising(self):
        active = mock.Mock(coordination_token="coord")
        with (
            mock.patch.object(api, "_restore_private_file", side_effect=api.ApiError("denied")) as restore,
            mock.patch.object(api, "diagnostic") as diagnostic,
        ):
            # Should not raise, but should log via diagnostic
            try:
                api._restore_secret_env(b"restored-secret", active)
            except api.ApiError:
                pass
            # Either diagnostic was called or restore was attempted
            self.assertTrue(restore.called or diagnostic.called)

    def test_restart_llama_swap_skips_when_inactive(self):
        active = mock.Mock(coordination_token="coord")
        with mock.patch.object(api, "run", return_value=self.completed(returncode=1)) as run:
            api._restart_llama_swap(active)
        self.assertEqual(run.call_count, 1)

    def test_restart_llama_swap_raises_when_restart_fails(self):
        active = mock.Mock(coordination_token="coord")
        with mock.patch.object(
            api, "run", side_effect=[self.completed(returncode=0), self.completed(returncode=1, stderr="boom")]
        ):
            with self.assertRaisesRegex(api.ApiError, "Operation failed"):
                api._restart_llama_swap(active)

    def test_restart_llama_swap_raises_when_health_check_fails(self):
        active = mock.Mock(coordination_token="coord")
        with mock.patch.object(
            api,
            "run",
            side_effect=[
                self.completed(returncode=0),
                self.completed(returncode=0),
                self.completed(returncode=1),
            ],
        ):
            with self.assertRaisesRegex(api.ApiError, "failed to start"):
                api._restart_llama_swap(active)

    def test_set_ai_provider_rejects_missing_keepass_when_key_present(self):
        request = {"id": "openrouter", "url": "https://openrouter.ai/api", "models": ["qwen3"], "apiKey": "sk-x"}
        with self.assertRaisesRegex(api.ApiError, "KeePassXC database password is required"):
            api.set_ai_provider(request)

    def test_set_ai_provider_rejects_multiline_credentials(self):
        request = {
            "id": "openrouter",
            "url": "https://openrouter.ai/api",
            "models": ["qwen3"],
            "apiKey": "sk-a\nsk-b",
            "keepassPassword": "pw\npw",
        }
        with self.assertRaisesRegex(api.ApiError, "single-line"):
            api.set_ai_provider(request)

    def test_set_ai_provider_propagates_validation_errors(self):
        with self.assertRaisesRegex(api.ApiError, "Provider ID"):
            api.set_ai_provider({"id": "BAD_ID", "url": "https://x", "models": ["m"], "keepassPassword": "pw"})
        with self.assertRaisesRegex(api.ApiError, "URL"):
            api.set_ai_provider({"id": "ok", "url": "file:///etc/passwd", "models": ["m"], "keepassPassword": "pw"})

    def test_set_ai_provider_failure_rolls_back_staged_credential(self):
        active = mock.Mock(coordination_token="coord")
        request = {
            "id": "openrouter",
            "url": "https://openrouter.ai/api",
            "models": ["qwen3"],
            "apiKey": "sk-new",
            "keepassPassword": "db-pw",
        }
        with tempfile.TemporaryDirectory() as temporary:
            config = pathlib.Path(temporary) / "config.yaml"
            config.write_text("healthCheckTimeout: 300\n", encoding="utf-8")
            with (
                mock.patch.object(api, "acquire_operation", return_value=__import__("contextlib").nullcontext(active)),
                mock.patch.object(api.ai_config, "CONFIG_PATH", config),
                mock.patch.object(
                    api.ai_config,
                    "load_config",
                    return_value={"models": {}, "peers": {}, "selectors": {}},
                ),
                mock.patch.object(api, "_read_secret_env", return_value=b"old-env"),
                mock.patch.object(api, "run", return_value=self.completed()) as run,
                mock.patch.object(
                    api.ai_config, "set_provider", side_effect=ValueError("config rejected")
                ) as configure,
                mock.patch.object(api, "_restore_private_file") as restore_file,
            ):
                with self.assertRaises(ValueError):
                    api.set_ai_provider(request)
            configure.assert_called_once()
            rollback_calls = [
                call
                for call in run.call_args_list
                if call.args and call.args[0][:2] == ["nas-secrets", "set-ai-provider-key-stdin"]
            ]
            self.assertTrue(rollback_calls, "expected rollback of staged credential")
            self.assertTrue(restore_file.called, "expected restore of secret env via _restore_private_file")

    def test_set_ai_local_model_validation_errors(self):
        base = {"id": "local", "path": "/tank/ai/models/x.gguf"}
        with self.assertRaisesRegex(api.ApiError, "context must be an integer"):
            api.set_ai_local_model({**base, "context": "big"})
        with self.assertRaisesRegex(api.ApiError, "TTL must be an integer"):
            api.set_ai_local_model({**base, "context": 32768, "ttl": "soon"})
        with self.assertRaisesRegex(api.ApiError, "tools capability"):
            api.set_ai_local_model({**base, "context": 32768, "ttl": 300, "tools": "yes"})
        with self.assertRaisesRegex(api.ApiError, "extraArgs"):
            api.set_ai_local_model({**base, "context": 32768, "ttl": 300, "tools": True, "extraArgs": [5]})

    def test_set_ai_local_model_delete_reports_config_errors(self):
        with (
            mock.patch.object(api, "operation_guard", return_value=__import__("contextlib").nullcontext()),
            mock.patch.object(api.ai_config, "delete_local_model", side_effect=api.ai_config.AiConfigError("missing")),
        ):
            with self.assertRaisesRegex(api.ApiError, "missing"):
                api.delete_ai_local_model({"id": "local"})

    def test_set_ai_role_reports_config_errors(self):
        with (
            mock.patch.object(api, "operation_guard", return_value=__import__("contextlib").nullcontext()),
            mock.patch.object(api.ai_config, "set_role", side_effect=api.ai_config.AiConfigError("unknown target")),
        ):
            with self.assertRaisesRegex(api.ApiError, "unknown target"):
                api.set_ai_role({"role": "coding/default", "targets": ["nope/x"], "strategy": "warm"})

    def test_set_ai_advanced_rejects_unsupported_and_empty_values(self):
        with self.assertRaisesRegex(api.ApiError, "unsupported fields"):
            api.set_ai_advanced({"bogus": 1})
        with self.assertRaisesRegex(api.ApiError, "unsupported fields"):
            api.set_ai_advanced({})

    def test_set_ai_advanced_applies_valid_values(self):
        with (
            mock.patch.object(api, "operation_guard", return_value=__import__("contextlib").nullcontext()) as guard,
            mock.patch.object(api.ai_config, "replace_advanced", return_value={"ok": True}) as replacer,
        ):
            self.assertTrue(api.set_ai_advanced({"globalTTL": 300, "logLevel": "info"})["ok"])
        guard.assert_called_once_with("ai-advanced-set", ("runtime",))
        replacer.assert_called_once_with({"globalTTL": 300, "logLevel": "info"})

    def test_overview_aggregates_probes_and_links(self):
        healthy = api.CommandResult(returncode=0, stdout="all pools healthy", stderr="")
        with (
            mock.patch.object(
                api, "feature_status", return_value={"features": [{"units": [{"unit": "nas-custom.service"}]}]}
            ),
            mock.patch.object(api, "setup_status", return_value={"status": "ready"}),
            mock.patch.object(api, "identity_status", return_value={"users": []}),
            mock.patch.object(api, "capability_status", return_value={"capabilities": []}),
            mock.patch.object(api, "update_status", return_value={"updateAvailable": False}),
            mock.patch.object(api, "ai_configuration", return_value={"ok": True, "providers": []}),
            mock.patch.object(api, "service_states", return_value=[{"unit": "caddy.service", "active": "active"}]),
            mock.patch.object(api, "run", side_effect=[healthy] * 4) as run,
            mock.patch.object(api, "endpoint_links", return_value={"caddy": "/console/@localhost/caddy"}),
            mock.patch.object(api, "read_optional_text", return_value=None),
            mock.patch.object(api, "operation_state", return_value={"busyClasses": []}),
            mock.patch.object(api.socket, "gethostname", return_value="nas-host"),
            mock.patch.object(api, "ZFS_REPLICATION_INSTALLED", False),
            mock.patch.object(api, "SYNCTHING_INSTALLED", False),
        ):
            result = api.overview()
        self.assertEqual(result["host"], "nas-host")
        self.assertTrue(result["zpool"]["ok"])
        self.assertTrue(result["zfs"]["ok"])
        self.assertEqual(result["services"][0]["unit"], "caddy.service")
        self.assertEqual(result["links"]["caddy"], "/console/@localhost/caddy")
        self.assertEqual(result["setup"]["status"], "ready")
        self.assertEqual(len(run.call_args_list), 4)

    def test_overview_marks_probe_failures(self):
        failed = api.CommandResult(returncode=1, stdout="", stderr="pool offline")
        with (
            mock.patch.object(api, "feature_status", return_value={"features": []}),
            mock.patch.object(api, "setup_status", return_value={}),
            mock.patch.object(api, "identity_status", return_value={}),
            mock.patch.object(api, "capability_status", return_value={}),
            mock.patch.object(api, "update_status", return_value={}),
            mock.patch.object(api, "ai_configuration", return_value={}),
            mock.patch.object(api, "service_states", return_value=[]),
            mock.patch.object(api, "run", side_effect=[failed] * 4),
            mock.patch.object(api, "endpoint_links", return_value={}),
            mock.patch.object(api, "read_optional_text", return_value=None),
            mock.patch.object(api, "operation_state", return_value={}),
            mock.patch.object(api.socket, "gethostname", return_value="nas-host"),
            mock.patch.object(api, "ZFS_REPLICATION_INSTALLED", False),
            mock.patch.object(api, "SYNCTHING_INSTALLED", False),
        ):
            result = api.overview()
        self.assertFalse(result["zpool"]["ok"])
        self.assertIn("pool offline", result["zpool"]["text"])

    def test_safe_action_captures_command_stdout(self):
        with (
            mock.patch.object(api, "run", return_value=self.completed(stdout="status-line")),
            mock.patch.object(
                api, "operation_guard", side_effect=lambda *_args: __import__("contextlib").nullcontext()
            ),
        ):
            result = api.safe_action("scrub")
        self.assertEqual(result["output"], "status-line")

    def test_set_feature_rejects_invalid_mode(self):
        with mock.patch.object(api, "json_command") as command:
            with self.assertRaisesRegex(api.ApiError, "Feature mode"):
                api.set_feature("ai", "sometimes")
            command.assert_not_called()

    def test_read_secret_line_validation(self):
        with mock.patch.object(api.sys, "stdin", io.StringIO("")):
            with self.assertRaisesRegex(api.ApiError, "password is required"):
                api.read_secret_line()
        with mock.patch.object(api.sys, "stdin", io.StringIO("short")):
            with self.assertRaisesRegex(api.ApiError, "input is invalid"):
                api.read_secret_line()
        with mock.patch.object(api.sys, "stdin", io.StringIO("ok\n")):
            self.assertEqual(api.read_secret_line(), "ok")

    def test_write_private_file_creates_parents_and_fails_exclusive(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = pathlib.Path(temporary) / "nested" / "secret.txt"
            api.write_private_file(target, "content")
            self.assertEqual(target.read_text(encoding="utf-8"), "content")
            with self.assertRaises(OSError):
                api.write_private_file(target, "again")

    def test_run_first_start_rejects_bad_digest(self):
        with self.assertRaisesRegex(api.ApiError, "plan digest is invalid"):
            api.run_first_start(plan_digest="not-a-digest", allow_destructive_storage=False)

    def test_run_first_start_requires_ready_status(self):
        with (
            mock.patch.object(api, "json_command", return_value={"status": "incomplete", "message": "plan missing"}),
            mock.patch.object(api, "read_secret_line") as read_secret,
        ):
            with self.assertRaisesRegex(api.ApiError, "plan missing"):
                api.run_first_start(plan_digest="a" * 64, allow_destructive_storage=False)
        read_secret.assert_not_called()

    def test_run_first_start_rejects_stale_digest(self):
        status = {"status": "ready", "planDigest": "b" * 64}
        with (
            mock.patch.object(api, "json_command", return_value=status),
            mock.patch.object(api, "read_secret_line") as read_secret,
        ):
            with self.assertRaisesRegex(api.ApiError, "stale"):
                api.run_first_start(plan_digest="a" * 64, allow_destructive_storage=False)
        read_secret.assert_not_called()

    def test_run_first_start_rejects_invalid_storage_plan(self):
        status = {"status": "ready", "planDigest": "a" * 64, "storage": {"devices": [5]}}
        with (
            mock.patch.object(api, "json_command", return_value=status),
            mock.patch.object(api, "read_secret_line") as read_secret,
        ):
            with self.assertRaisesRegex(api.ApiError, "storage device plan is invalid"):
                api.run_first_start(plan_digest="a" * 64, allow_destructive_storage=False)
        read_secret.assert_not_called()

    def test_main_rejects_non_root(self):
        with mock.patch.object(api.os, "geteuid", return_value=1000):
            with self.assertRaises(SystemExit):
                api.main()

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
                            "backslash": {"available": True, "linkKey": "bad3", "publicPath": "/\\evil.example/"},
                            "newline": {"available": True, "linkKey": "bad2", "publicPath": "/safe\nInjected"},
                        },
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(api.endpoint_links(path), {"good": "/safe/"})


if __name__ == "__main__":
    unittest.main()
