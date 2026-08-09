from __future__ import annotations

import contextlib
import importlib.util
import os
import pathlib
import stat
import sys
import tempfile
import unittest
from unittest import mock
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

SPEC = importlib.util.spec_from_file_location("nas_cockpit_api_secret_tx", SERVICES / "nas_cockpit_api.py")
assert SPEC and SPEC.loader
api = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = api
SPEC.loader.exec_module(api)


class AiSecretTransactionTests(unittest.TestCase):
    def completed(self, *, returncode: int = 0, stdout: str = "", stderr: str = ""):
        return mock.Mock(returncode=returncode, stdout=stdout, stderr=stderr)

    def active(self):
        return mock.Mock(coordination_token="coord-token")

    def request(self, *, api_key: str = "new-provider-key", password: str = "database-password") -> dict[str, object]:
        return {
            "id": "cloud",
            "url": "https://cloud.example/v1",
            "models": ["coder"],
            "apiKey": api_key,
            "keepassPassword": password,
            "timeouts": {},
            "filters": {},
        }

    def snapshots(self):
        config = api.PrivateFileSnapshot(True, b"old config\n", 0o640, os.geteuid(), os.getegid())
        env = api.PrivateFileSnapshot(True, b"OLD=value\n", 0o400, os.geteuid(), os.getegid())
        return config, env

    def test_secret_operation_error_never_logs_child_output(self) -> None:
        sentinel = "SECRET-CHILD-OUTPUT"
        with mock.patch.object(api, "diagnostic") as diagnostic:
            error = api.operation_error(
                ["nas-secrets", "show-ai-provider-key-stdin", "cloud"],
                self.completed(returncode=1, stderr=sentinel),
            )
        self.assertNotIn(sentinel, str(error))
        rendered = diagnostic.call_args.args[0]
        self.assertNotIn(sentinel, rendered)
        self.assertIn("secret command output redacted", rendered)

    def test_existing_provider_snapshot_sends_exactly_one_password_line(self) -> None:
        active = self.active()
        with mock.patch.object(
            api,
            "run",
            return_value=self.completed(returncode=0, stdout="old-provider-key\n"),
        ) as runner:
            value = api._fetch_existing_provider_key(active, "cloud", "database-password")
        self.assertEqual(value, "old-provider-key")
        self.assertEqual(runner.call_args.kwargs["input_text"], "database-password\n")
        self.assertNotIn("\n\n", runner.call_args.kwargs["input_text"])

    def test_private_snapshot_rejects_symlink_and_preserves_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            target = root / "secret.env"
            target.write_bytes(b"TOKEN=value\n")
            target.chmod(0o400)
            snapshot = api._snapshot_private_file(target, "test secret")
            self.assertTrue(snapshot.exists)
            self.assertEqual(snapshot.content, b"TOKEN=value\n")
            self.assertEqual(snapshot.mode, 0o400)
            link = root / "link.env"
            link.symlink_to(target)
            with self.assertRaisesRegex(api.ApiError, "unsafe"):
                api._snapshot_private_file(link, "test secret")

    def test_private_restore_is_atomic_and_preserves_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "secret.env"
            path.write_bytes(b"new\n")
            path.chmod(0o600)
            snapshot = api.PrivateFileSnapshot(True, b"old\n", 0o400, os.geteuid(), os.getegid())
            api._restore_private_file(path, snapshot, "test secret")
            self.assertEqual(path.read_bytes(), b"old\n")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)
            self.assertEqual(list(path.parent.glob(".secret.env.rollback.*")), [])

    def test_existing_credential_fetch_failure_aborts_before_any_mutation(self) -> None:
        config, env = self.snapshots()
        before = {"peers": {"cloud": {"apiKey": "${env.LLAMA_SWAP_PEER_CLOUD_API_KEY}"}}}
        active = self.active()
        with (
            mock.patch.object(api, "acquire_operation", return_value=contextlib.nullcontext(active)),
            mock.patch.object(api, "_snapshot_private_file", side_effect=[config, env]),
            mock.patch.object(api.ai_config, "load_config", return_value=before),
            mock.patch.object(api, "_llama_swap_active", return_value=False),
            mock.patch.object(api, "run", return_value=self.completed(returncode=1, stderr="vault unavailable")),
            mock.patch.object(api, "_write_provider_key") as writer,
            mock.patch.object(api.ai_config, "set_provider") as setter,
        ):
            with self.assertRaisesRegex(api.ApiError, "snapshot the existing provider credential"):
                api.set_ai_provider(self.request())
        writer.assert_not_called()
        setter.assert_not_called()

    def test_failed_secret_stage_is_rolled_back_even_when_command_reports_failure(self) -> None:
        config, env = self.snapshots()
        active = self.active()
        writes: list[str | None] = []

        def write(_active, _provider, _password, value):
            writes.append(value)
            if len(writes) == 1:
                raise api.ApiError("stage failed after partial mutation")

        with (
            mock.patch.object(api, "acquire_operation", return_value=contextlib.nullcontext(active)),
            mock.patch.object(api, "_snapshot_private_file", side_effect=[config, env]),
            mock.patch.object(api.ai_config, "load_config", return_value={"peers": {}}),
            mock.patch.object(api, "_llama_swap_active", return_value=False),
            mock.patch.object(api, "_write_provider_key", side_effect=write),
            mock.patch.object(api, "_restore_private_file"),
            mock.patch.object(api.ai_config, "set_provider") as setter,
        ):
            with self.assertRaisesRegex(api.ApiError, "stage failed"):
                api.set_ai_provider(self.request())
        self.assertEqual(writes, ["new-provider-key", None])
        setter.assert_not_called()

    def test_config_failure_restores_old_key_runtime_env_and_config(self) -> None:
        config, env = self.snapshots()
        active = self.active()
        before = {"peers": {"cloud": {"apiKey": "${env.LLAMA_SWAP_PEER_CLOUD_API_KEY}"}}}
        writes: list[str | None] = []
        restored: list[tuple[pathlib.Path, Any, str]] = []

        def restore(path, snapshot, label):
            restored.append((path, snapshot, label))

        with (
            mock.patch.object(api, "acquire_operation", return_value=contextlib.nullcontext(active)),
            mock.patch.object(api, "_snapshot_private_file", side_effect=[config, env]),
            mock.patch.object(api.ai_config, "load_config", return_value=before),
            mock.patch.object(api, "_llama_swap_active", return_value=False),
            mock.patch.object(api, "_fetch_existing_provider_key", return_value="old-provider-key"),
            mock.patch.object(api, "_write_provider_key", side_effect=lambda _a, _p, _pw, value: writes.append(value)),
            mock.patch.object(api, "_restore_private_file", side_effect=restore),
            mock.patch.object(api.ai_config, "set_provider", side_effect=RuntimeError("config exploded")),
        ):
            with self.assertRaisesRegex(RuntimeError, "config exploded"):
                api.set_ai_provider(self.request())
        self.assertEqual(writes, ["new-provider-key", "old-provider-key"])
        self.assertEqual([entry[1] for entry in restored], [env, config])

    def test_restart_failure_rolls_back_all_mutated_state_and_restarts_old_service(self) -> None:
        config, env = self.snapshots()
        active = self.active()
        writes: list[str | None] = []
        restarts: list[bool | None] = []

        def restart(_active, *, was_active=None):
            restarts.append(was_active)
            if len(restarts) == 1:
                raise api.ApiError("new service failed health check")

        with (
            mock.patch.object(api, "acquire_operation", return_value=contextlib.nullcontext(active)),
            mock.patch.object(api, "_snapshot_private_file", side_effect=[config, env]),
            mock.patch.object(api.ai_config, "load_config", return_value={"peers": {}}),
            mock.patch.object(api, "_llama_swap_active", return_value=True),
            mock.patch.object(api, "_write_provider_key", side_effect=lambda _a, _p, _pw, value: writes.append(value)),
            mock.patch.object(api, "_restore_private_file"),
            mock.patch.object(api.ai_config, "set_provider", return_value={"ok": True}),
            mock.patch.object(api, "_restart_llama_swap", side_effect=restart),
        ):
            with self.assertRaisesRegex(api.ApiError, "health check"):
                api.set_ai_provider(self.request())
        self.assertEqual(writes, ["new-provider-key", None])
        self.assertEqual(restarts, [True, True])

    def test_rollback_failure_is_never_swallowed(self) -> None:
        config, env = self.snapshots()
        active = self.active()
        calls = 0

        def write(_active, _provider, _password, _value):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise api.ApiError("rollback write failed")

        with (
            mock.patch.object(api, "acquire_operation", return_value=contextlib.nullcontext(active)),
            mock.patch.object(api, "_snapshot_private_file", side_effect=[config, env]),
            mock.patch.object(api.ai_config, "load_config", return_value={"peers": {}}),
            mock.patch.object(api, "_llama_swap_active", return_value=False),
            mock.patch.object(api, "_write_provider_key", side_effect=write),
            mock.patch.object(api, "_restore_private_file"),
            mock.patch.object(api.ai_config, "set_provider", side_effect=RuntimeError("primary failure")),
            mock.patch.object(api, "diagnostic"),
        ):
            with self.assertRaisesRegex(api.ApiError, "manual recovery"):
                api.set_ai_provider(self.request())

    def test_delete_existing_credential_fetch_failure_aborts_before_config_delete(self) -> None:
        config, env = self.snapshots()
        active = self.active()
        before = {"peers": {"cloud": {"apiKey": "${env.LLAMA_SWAP_PEER_CLOUD_API_KEY}"}}}
        with (
            mock.patch.object(api, "acquire_operation", return_value=contextlib.nullcontext(active)),
            mock.patch.object(api, "_snapshot_private_file", side_effect=[config, env]),
            mock.patch.object(api.ai_config, "load_config", return_value=before),
            mock.patch.object(api, "_fetch_existing_provider_key", side_effect=api.ApiError("vault read failed")),
            mock.patch.object(api.ai_config, "delete_provider") as deleter,
        ):
            with self.assertRaisesRegex(api.ApiError, "vault read failed"):
                api.delete_ai_provider({"id": "cloud", "keepassPassword": "database-password"})
        deleter.assert_not_called()

    def test_delete_clear_failure_restores_old_credential_and_config(self) -> None:
        config, env = self.snapshots()
        active = self.active()
        before = {"peers": {"cloud": {"apiKey": "${env.LLAMA_SWAP_PEER_CLOUD_API_KEY}"}}}
        writes: list[str | None] = []

        def write(_active, _provider, _password, value):
            writes.append(value)
            if len(writes) == 1:
                raise api.ApiError("clear failed after partial mutation")

        with (
            mock.patch.object(api, "acquire_operation", return_value=contextlib.nullcontext(active)),
            mock.patch.object(api, "_snapshot_private_file", side_effect=[config, env]),
            mock.patch.object(api.ai_config, "load_config", return_value=before),
            mock.patch.object(api, "_fetch_existing_provider_key", return_value="old-provider-key"),
            mock.patch.object(api, "_llama_swap_active", return_value=False),
            mock.patch.object(api.ai_config, "delete_provider", return_value={"ok": True}),
            mock.patch.object(api, "_write_provider_key", side_effect=write),
            mock.patch.object(api, "_restore_private_file"),
        ):
            with self.assertRaisesRegex(api.ApiError, "clear failed"):
                api.delete_ai_provider({"id": "cloud", "keepassPassword": "database-password"})
        self.assertEqual(writes, [None, "old-provider-key"])


if __name__ == "__main__":
    unittest.main()
