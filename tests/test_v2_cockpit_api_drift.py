from __future__ import annotations

import contextlib
import io
import json
import os
import pathlib
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_cockpit_api as api  # noqa: E402
from nas_common import CommandResult  # noqa: E402
from nas_operation_lock import OperationBusyError  # noqa: E402


class CockpitApiDriftTests(unittest.TestCase):
    def active(self) -> types.SimpleNamespace:
        return types.SimpleNamespace(coordination_token="coord-token", token="reservation-token")

    def test_diagnostic_falls_back_to_stderr(self) -> None:
        with (
            mock.patch.object(api.syslog, "syslog", side_effect=OSError("syslog down")),
            mock.patch.dict(os.environ, {"NAS_DIAGNOSTICS_STDERR": "1"}),
            mock.patch("sys.stderr", new_callable=io.StringIO) as stderr,
        ):
            api.diagnostic("x" * 2100)
        self.assertEqual(len(stderr.getvalue().strip()), 2000)

    def test_operation_error_redacts_secret_command_output(self) -> None:
        with mock.patch.object(api, "diagnostic") as diagnostic:
            error = api.operation_error(
                ["/run/current-system/sw/bin/nas-secrets", "show"], CommandResult(1, "secret", "secret")
            )
        self.assertRegex(str(error), r"Operation failed \(reference [0-9a-f]{12}\)")
        rendered = diagnostic.call_args.args[0]
        self.assertIn("secret command output redacted", rendered)
        self.assertNotIn("'secret'", rendered)

    def test_run_raises_for_checked_failure_and_returns_unchecked_result(self) -> None:
        failure = CommandResult(3, "partial", "denied")
        with mock.patch.object(api, "run_command", return_value=failure):
            with self.assertRaises(api.ApiError):
                api.run(["tool"])
            self.assertEqual(api.run(["tool"], check=False), failure)

    def test_static_and_status_helpers_use_v2_commands(self) -> None:
        links = api.static_links()
        self.assertEqual(links["scheduler"], "/console/system/services#/timers")
        self.assertEqual(links["accountSettings"], "/settings/")
        self.assertEqual(links["docs"], "/console/cockpit/@localhost/nas/docs/index.html")
        self.assertNotIn("files", links)
        with mock.patch.object(api, "_json_command", return_value={"ok": True}) as command:
            self.assertEqual(api.identity_status(), {"ok": True})
            self.assertEqual(api.capability_status(), {"ok": True})
            self.assertEqual(api.update_status(), {"ok": True})
            self.assertEqual(api.first_start_status(), {"ok": True})
        calls = [call.args[0] for call in command.call_args_list]
        self.assertIn(["nas-identity-sync", "status"], calls)
        self.assertIn(["nas-identity-sync", "capabilities"], calls)
        self.assertIn(["nas-update", "--status", "--json"], calls)
        self.assertTrue(any(call[:2] == ["nas-setup", "prepare-first-start"] for call in calls))

    def test_setup_status_merges_prepare_error_only_when_needed(self) -> None:
        prepared = {"ok": False, "error": "missing plan"}
        with mock.patch.object(api, "_json_command", side_effect=[prepared, {"status": "incomplete"}]):
            result = api.setup_status()
        self.assertEqual(result["firstStart"], prepared)
        with mock.patch.object(api, "_json_command", side_effect=[prepared, {"firstStart": {"status": "known"}}]):
            result = api.setup_status()
        self.assertEqual(result["firstStart"]["status"], "known")

    def test_ai_configuration_fails_closed(self) -> None:
        with mock.patch.object(api.ai_config, "load_config", side_effect=api.ai_config.AiConfigError("bad")):
            result = api.ai_configuration()
        self.assertFalse(result["ok"])
        self.assertEqual(result["providers"], [])
        self.assertEqual(result["codingRoles"], {})

    def test_operation_state_adds_action_conflicts_and_handles_io_error(self) -> None:
        with (
            mock.patch.object(api, "shared_operation_state", return_value={"busyClasses": ["runtime"], "active": []}),
            mock.patch.object(
                api,
                "managed_services_status",
                return_value={
                    "services": [
                        {
                            "id": "identity-sync",
                            "label": "Identity sync",
                            "managed": True,
                            "effective": True,
                            "workloadKind": "job",
                            "units": [{"unit": "nas-identity-sync.service", "role": "owner"}],
                        }
                    ]
                },
            ),
        ):
            result = api.operation_state()
        self.assertEqual(result["conflictsByAction"]["identity-sync"], ["runtime"])
        self.assertEqual(result["managedServicesConflicts"], ["runtime"])
        self.assertNotIn("identity-sync", result["workerOwnedActions"])
        with mock.patch.object(api, "shared_operation_state", side_effect=OSError("denied")):
            result = api.operation_state()
        self.assertEqual(result["busyClasses"], [])
        self.assertIn("denied", result["error"])

    def test_first_start_job_status_validates_id_missing_and_payload(self) -> None:
        with self.assertRaisesRegex(api.ApiError, "Invalid first-start job identifier"):
            api.first_start_job_status("bad")
        job_id = "a" * 24
        with mock.patch.object(pathlib.Path, "read_text", side_effect=FileNotFoundError):
            self.assertEqual(api.first_start_job_status(job_id)["status"], "pending")
        with mock.patch.object(pathlib.Path, "read_text", return_value="{"):
            with self.assertRaisesRegex(api.ApiError, "Unable to read"):
                api.first_start_job_status(job_id)
        with mock.patch.object(pathlib.Path, "read_text", return_value=json.dumps({"jobId": "b" * 24})):
            with self.assertRaisesRegex(api.ApiError, "status is invalid"):
                api.first_start_job_status(job_id)
        payload = {"jobId": job_id, "status": "running"}
        with mock.patch.object(pathlib.Path, "read_text", return_value=json.dumps(payload)):
            self.assertEqual(api.first_start_job_status(job_id), payload)

    def test_write_private_new_is_exclusive_and_cleans_partial_write(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = pathlib.Path(raw) / "secret"
            api._write_private_new(path, "value")
            self.assertEqual(path.read_text(encoding="utf-8"), "value")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                api._write_private_new(path, "again")

    def test_start_first_start_unit_uses_hardened_transient_unit_and_reports_failure(self) -> None:
        with mock.patch.object(api, "run", return_value=CommandResult(0, "", "")) as run:
            api._start_first_start_unit(
                "a" * 24,
                pathlib.Path("/request"),
                pathlib.Path("/password"),
                ["/dev/disk/by-id/test-disk"],
            )
        command = run.call_args.args[0]
        self.assertEqual(command[:3], ["systemd-run", "--unit", f"nas-first-start-{'a' * 24}.service"])
        self.assertIn("--property=ProtectSystem=strict", command)
        self.assertIn("--property=ProtectHome=yes", command)
        self.assertIn(
            "--property=RuntimeDirectory=nas-secrets nas-secret-staging nas-secret-transactions",
            command,
        )
        self.assertIn("--property=RuntimeDirectoryMode=0700", command)
        self.assertIn("--property=RuntimeDirectoryPreserve=yes", command)
        self.assertNotIn("--property=PrivateDevices=yes", command)
        self.assertIn("--property=DevicePolicy=closed", command)
        self.assertIn("--property=DeviceAllow=/dev/zfs rw", command)
        self.assertIn("--property=DeviceAllow=/dev/disk/by-id/test-disk rw", command)
        write_paths = next(value for value in command if value.startswith("--property=ReadWritePaths="))
        self.assertIn("/run/nas-secrets", write_paths)
        self.assertIn("/run/nas-secret-staging", write_paths)
        self.assertIn("/run/nas-secret-transactions", write_paths)
        self.assertIn("/var/lib/nas-first-start", write_paths)
        self.assertIn("/var/lib/nas-bootstrap", write_paths)
        self.assertIn("/etc", write_paths.split("=")[-1].split())
        self.assertNotIn("/home", write_paths.split("=")[-1].split())
        self.assertIn(f"--property=ReadWritePaths=-{api.ZFS_ROOT}", command)
        self.assertIn("--property=Environment=NAS_SETUP_ALLOW_ROOT=1", command)
        self.assertTrue(any(item.startswith("--property=Environment=NAS_PUBLIC_HOST=") for item in command))
        self.assertIn("--property=Environment=NAS_AUTHENTIK_BOOTSTRAP_TOKEN_FILE=/run/nas-authentik/api-token", command)
        self.assertEqual(command[command.index("--") + 1], api._setup_entry())
        self.assertIn("--password-file", command)
        with mock.patch.object(api, "run", return_value=CommandResult(1, "", "failed")):
            with self.assertRaises(api.ApiError):
                api._start_first_start_unit("b" * 24, pathlib.Path("/r"), pathlib.Path("/p"), ["/dev/test"])

    def test_device_allow_paths_include_only_partitions_of_confirmed_disks(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            dev_root = root / "dev"
            by_id = dev_root / "disk" / "by-id"
            by_id.mkdir(parents=True)
            (dev_root / "vdb").touch()
            confirmed = by_id / "confirmed-disk"
            confirmed.symlink_to(pathlib.Path("../../vdb"))
            sys_root = root / "sys" / "class" / "block"
            (sys_root / "vdb" / "vdb1").mkdir(parents=True)
            (sys_root / "vdb" / "vdb1" / "partition").touch()
            (sys_root / "vdb" / "holders").mkdir()
            (sys_root / "vdc" / "vdc1").mkdir(parents=True)
            (sys_root / "vdc" / "vdc1" / "partition").touch()

            allowed = api._device_allow_paths(
                [str(confirmed)],
                sys_class_root=sys_root,
                dev_root=dev_root,
            )

        self.assertEqual(allowed, ["/dev/zfs", str(confirmed), str(dev_root / "vdb1")])

    def prepared_first_start(self) -> dict[str, object]:
        return {
            "status": "ready",
            "planDigest": "a" * 64,
            "requiresDestructiveConfirmation": True,
            "storage": {"devices": ["/dev/a", "/dev/b"]},
        }

    def administrator(self) -> dict[str, str]:
        return {
            "username": "nasadmin",
            "name": "NAS Administrator",
            "email": "admin@example.test",
            "password": "admin-password",
        }

    def test_start_first_start_rejects_bad_inputs_before_reservation(self) -> None:
        cases = [
            ({"password": "x\ny", "administrator": self.administrator(), "planDigest": "a" * 64}, "single line"),
            (
                {
                    "password": "pw",
                    "administrator": {**self.administrator(), "email": "not-an-email"},
                    "planDigest": "a" * 64,
                },
                "email is invalid",
            ),
            (
                {
                    "password": "pw",
                    "administrator": {**self.administrator(), "password": "too-short"},
                    "planDigest": "a" * 64,
                },
                "at least 12",
            ),
            (
                {
                    "password": "pw",
                    "administrator": {**self.administrator(), "username": "nas-bootstrap"},
                    "planDigest": "a" * 64,
                },
                "reserved bootstrap",
            ),
            ({"password": "pw", "administrator": self.administrator(), "planDigest": "bad"}, "plan digest"),
            (
                {
                    "password": "pw",
                    "administrator": self.administrator(),
                    "planDigest": "a" * 64,
                    "devices": ["/dev/a", "/dev/a"],
                },
                "duplicates",
            ),
            (
                {
                    "password": "pw",
                    "administrator": self.administrator(),
                    "planDigest": "a" * 64,
                    "allowDestructiveStorage": "yes",
                },
                "flags must be boolean",
            ),
        ]
        with mock.patch.object(api, "reserve_operation") as reserve:
            for request, message in cases:
                with self.subTest(request=request), self.assertRaisesRegex(api.ApiError, message):
                    api.start_first_start(request)
        reserve.assert_not_called()

    def test_start_first_start_rejects_status_digest_device_and_destructive_mismatches(self) -> None:
        request = {
            "password": "pw",
            "administrator": self.administrator(),
            "planDigest": "a" * 64,
            "devices": ["/dev/a", "/dev/b"],
        }
        with mock.patch.object(api, "first_start_status", return_value={"status": "complete"}):
            self.assertEqual(api.start_first_start(request)["status"], "complete")
        with mock.patch.object(api, "first_start_status", return_value={"status": "blocked", "message": "not ready"}):
            with self.assertRaisesRegex(api.ApiError, "not ready"):
                api.start_first_start(request)
        bad = self.prepared_first_start()
        bad["planDigest"] = "b" * 64
        with mock.patch.object(api, "first_start_status", return_value=bad):
            with self.assertRaisesRegex(api.ApiError, "stale"):
                api.start_first_start(request)
        bad = self.prepared_first_start()
        bad["storage"] = {"devices": [5]}
        with mock.patch.object(api, "first_start_status", return_value=bad):
            with self.assertRaisesRegex(api.ApiError, "device plan is invalid"):
                api.start_first_start(request)
        with mock.patch.object(api, "first_start_status", return_value=self.prepared_first_start()):
            with self.assertRaisesRegex(api.ApiError, "Confirm destructive"):
                api.start_first_start(request)

    def test_start_first_start_submits_private_job_and_cancels_on_failure(self) -> None:
        request = {
            "password": "db-password",
            "administrator": self.administrator(),
            "planDigest": "a" * 64,
            "devices": ["/dev/a", "/dev/b"],
            "allowDestructiveStorage": True,
            "confirmPasswordReapply": True,
        }
        active = self.active()
        writes: list[tuple[pathlib.Path, str]] = []
        with (
            mock.patch.object(api, "first_start_status", return_value=self.prepared_first_start()),
            mock.patch.object(api, "reserve_operation", return_value=active),
            mock.patch.object(api.secrets, "token_hex", return_value="c" * 24),
            mock.patch.object(pathlib.Path, "mkdir"),
            mock.patch.object(api.os, "chmod"),
            mock.patch.object(api, "_write_private_new", side_effect=lambda path, text: writes.append((path, text))),
            mock.patch.object(api, "_start_first_start_unit"),
        ):
            result = api.start_first_start(request)
        self.assertEqual(result, {"schemaVersion": 1, "jobId": "c" * 24, "status": "submitted"})
        self.assertEqual(len(writes), 2)
        self.assertIn("reservation-token", writes[0][1])
        self.assertNotIn("db-password", writes[0][1])
        self.assertEqual(json.loads(writes[1][1])["keepass"], "db-password")
        self.assertEqual(json.loads(writes[1][1])["administrator"]["password"], "admin-password")

        with (
            mock.patch.object(api, "first_start_status", return_value=self.prepared_first_start()),
            mock.patch.object(api, "reserve_operation", return_value=active),
            mock.patch.object(api.secrets, "token_hex", return_value="d" * 24),
            mock.patch.object(pathlib.Path, "mkdir"),
            mock.patch.object(pathlib.Path, "unlink"),
            mock.patch.object(api.os, "chmod"),
            mock.patch.object(api, "_write_private_new"),
            mock.patch.object(api, "_start_first_start_unit", side_effect=api.ApiError("launch failed")),
            mock.patch.object(api, "cancel_reservation") as cancel,
        ):
            with self.assertRaisesRegex(api.ApiError, "launch failed"):
                api.start_first_start(request)
        cancel.assert_called_once_with("reservation-token")

    def test_reconcile_first_start_parses_object_and_fallback_and_errors(self) -> None:
        with mock.patch.object(api, "run", return_value=CommandResult(0, '{"ok":true}', "")):
            self.assertTrue(api.reconcile_first_start({"note": "fixed"})["ok"])
        with mock.patch.object(api, "run", return_value=CommandResult(0, "[]", "")):
            self.assertEqual(api.reconcile_first_start({"note": "fixed"}), {"ok": True})
        with mock.patch.object(api, "run", return_value=CommandResult(0, "{", "")):
            with self.assertRaisesRegex(api.ApiError, "invalid recovery JSON"):
                api.reconcile_first_start({"note": "fixed"})
        with mock.patch.object(api, "run", return_value=CommandResult(2, "", "bad")):
            with self.assertRaises(api.ApiError):
                api.reconcile_first_start({"note": "fixed"})

    def test_operation_guard_translates_busy_error(self) -> None:
        manager = mock.MagicMock()
        manager.__enter__.side_effect = OperationBusyError("busy")
        with mock.patch.object(api, "acquire_operation", return_value=manager):
            with self.assertRaisesRegex(api.ApiError, "busy"):
                with api.operation_guard("x", ("runtime",)):
                    pass

    def test_run_action_discovers_v2_jobs_and_rejects_unknown_actions(self) -> None:
        with mock.patch.object(api, "managed_services_status", return_value={"services": []}):
            with self.assertRaisesRegex(api.ApiError, "Unknown action"):
                api.run_action("missing")
        with (
            mock.patch.object(
                api,
                "managed_services_status",
                return_value={
                    "services": [
                        {
                            "id": "identity-sync",
                            "label": "Identity sync",
                            "managed": True,
                            "effective": True,
                            "workloadKind": "job",
                            "units": [{"unit": "nas-identity-sync.service", "role": "owner"}],
                        }
                    ]
                },
            ),
            mock.patch.object(api, "run", return_value=CommandResult(0, "ok", "")) as run,
        ):
            result = api.run_action("identity-sync")
        self.assertTrue(result["ok"])
        self.assertEqual(result["commands"][0]["stdout"], "ok")
        run.assert_called_once_with(
            ("systemctl", "start", "nas-identity-sync.service"),
            check=False,
            timeout_seconds=21600,
        )

    def test_host_action_uses_guard_and_stops_on_failure(self) -> None:
        with (
            mock.patch.object(api, "operation_guard", return_value=contextlib.nullcontext()) as guard,
            mock.patch.object(api, "run", return_value=CommandResult(1, "", "failed")),
        ):
            with self.assertRaises(api.ApiError):
                api.run_action("protected-restart")
        guard.assert_called_once_with("protected-restart", ("identity", "runtime"))

    def test_set_managed_service_validates_and_propagates_coordination(self) -> None:
        with self.assertRaisesRegex(api.ApiError, "service identifier"):
            api.set_managed_service("BAD", "always")
        with self.assertRaisesRegex(api.ApiError, "Invalid service mode"):
            api.set_managed_service("demo", "sometimes")
        active = self.active()
        with (
            mock.patch.object(api, "acquire_operation", return_value=contextlib.nullcontext(active)),
            mock.patch.object(api, "run", return_value=CommandResult(0, '{"ok":true}', "")) as run,
        ):
            self.assertTrue(api.set_managed_service("demo", "always")["ok"])
        self.assertEqual(run.call_args.kwargs["env"]["NAS_OPERATION_COORDINATION_TOKEN"], "coord-token")
        with (
            mock.patch.object(api, "acquire_operation", return_value=contextlib.nullcontext(active)),
            mock.patch.object(api, "run", return_value=CommandResult(0, "[]", "")),
        ):
            self.assertEqual(api.set_managed_service("demo", "off"), {"ok": True})
        with (
            mock.patch.object(api, "acquire_operation", return_value=contextlib.nullcontext(active)),
            mock.patch.object(api, "run", return_value=CommandResult(0, "{", "")),
        ):
            with self.assertRaisesRegex(api.ApiError, "invalid JSON"):
                api.set_managed_service("demo", "off")
        with mock.patch.object(api, "acquire_operation", side_effect=OperationBusyError("busy")):
            with self.assertRaisesRegex(api.ApiError, "busy"):
                api.set_managed_service("demo", "off")

    def test_private_file_snapshot_and_restore_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            path = root / "secret"
            self.assertFalse(api._snapshot_private_file(path, "secret").exists)
            path.write_bytes(b"before")
            os.chmod(path, 0o640)
            snap = api._private_file_snapshot(path, "secret")
            self.assertTrue(snap.exists)
            self.assertEqual(snap.content, b"before")
            path.write_bytes(b"after")
            with mock.patch.object(api.os, "geteuid", return_value=1000):
                api._restore_private_file(path, snap, "secret")
            self.assertEqual(path.read_bytes(), b"before")
            api._restore_private_file(path, api.PrivateFileSnapshot(False), "secret")
            self.assertFalse(path.exists())

    def test_private_file_snapshot_rejects_unsafe_and_large_paths(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            directory = root / "directory"
            directory.mkdir()
            with self.assertRaisesRegex(api.ApiError, "unsafe"):
                api._snapshot_private_file(directory, "config")
            path = root / "large"
            path.write_bytes(b"xx")
            with mock.patch.object(api, "MAX_PRIVATE_SNAPSHOT_BYTES", 1):
                with self.assertRaisesRegex(api.ApiError, "unexpectedly large"):
                    api._snapshot_private_file(path, "config")

    def test_provider_reference_and_existing_key_validation(self) -> None:
        expected = "${env." + api.ai_config.provider_env_name("cloud") + "}"
        self.assertTrue(api._provider_reference_configured({"peers": {"cloud": {"apiKey": expected}}}, "cloud"))
        self.assertFalse(api._provider_reference_configured({}, "cloud"))
        self.assertFalse(api._provider_reference_configured({"peers": {"cloud": "bad"}}, "cloud"))
        active = self.active()
        with mock.patch.object(api, "run", return_value=CommandResult(0, "old-key\n", "")):
            self.assertEqual(api._fetch_existing_provider_key(active, "cloud", "db"), "old-key")
        with mock.patch.object(api, "run", return_value=CommandResult(1, "", "denied")):
            with self.assertRaisesRegex(api.ApiError, "snapshot the existing"):
                api._fetch_existing_provider_key(active, "cloud", "db")
        for value in ("", "bad\nkey", "x" * 4097):
            with mock.patch.object(api, "run", return_value=CommandResult(0, value, "")):
                with self.assertRaisesRegex(api.ApiError, "missing or malformed"):
                    api._fetch_existing_provider_key(active, "cloud", "db")

    def test_write_provider_key_sets_or_clears_through_secret_stdin(self) -> None:
        active = self.active()
        with mock.patch.object(api, "run", return_value=CommandResult(0, "", "")) as run:
            api._write_provider_key(active, "cloud", "db", "new-key")
            api._write_provider_key(active, "cloud", "db", None)
        first, second = run.call_args_list
        self.assertEqual(first.args[0], ["nas-secrets", "set-ai-provider-key-stdin", "cloud"])
        self.assertEqual(first.kwargs["input_text"], "db\nnew-key\n")
        self.assertEqual(second.args[0], ["nas-secrets", "clear-ai-provider-key-stdin", "cloud"])
        self.assertEqual(second.kwargs["input_text"], "db\n")
        self.assertEqual(first.kwargs["env"]["NAS_SKIP_LLAMA_SWAP_RESTART"], "1")

    def test_restart_llama_swap_inactive_restart_failure_and_health_failure(self) -> None:
        active = self.active()
        with mock.patch.object(api, "run", return_value=CommandResult(1, "", "")) as run:
            api._restart_llama_swap(active)
        self.assertEqual(run.call_count, 1)
        with mock.patch.object(api, "run", return_value=CommandResult(1, "", "failed")):
            with self.assertRaises(api.ApiError):
                api._restart_llama_swap(active, was_active=True)
        with mock.patch.object(api, "run", side_effect=[CommandResult(0, "", ""), CommandResult(1, "", "")]):
            with self.assertRaisesRegex(api.ApiError, "failed to start"):
                api._restart_llama_swap(active, was_active=True)

    def test_set_ai_provider_happy_paths_and_validation(self) -> None:
        active = self.active()
        base = {"id": "cloud", "url": "https://cloud.example/v1", "models": ["coder"]}
        with self.assertRaisesRegex(api.ApiError, "KeePassXC database password"):
            api.set_ai_provider({**base, "apiKey": "secret"})
        with self.assertRaisesRegex(api.ApiError, "single-line"):
            api.set_ai_provider({**base, "apiKey": "a\nb", "keepassPassword": "db"})
        with (
            mock.patch.object(api, "acquire_operation", return_value=contextlib.nullcontext(active)),
            mock.patch.object(api, "_snapshot_private_file", return_value=api.PrivateFileSnapshot(False)),
            mock.patch.object(api.ai_config, "load_config", return_value={"peers": {}}),
            mock.patch.object(api, "_llama_swap_active", return_value=False),
            mock.patch.object(api, "_write_provider_key") as write_key,
            mock.patch.object(api.ai_config, "set_provider", return_value={"ok": True}) as setter,
            mock.patch.object(api, "_restart_llama_swap"),
        ):
            self.assertTrue(api.set_ai_provider({**base, "apiKey": "secret", "keepassPassword": "db"})["ok"])
        write_key.assert_called_once_with(active, "cloud", "db", "secret")
        self.assertTrue(setter.call_args.kwargs["credential"])

        with (
            mock.patch.object(api, "acquire_operation", return_value=contextlib.nullcontext(active)),
            mock.patch.object(api, "_snapshot_private_file", return_value=api.PrivateFileSnapshot(False)),
            mock.patch.object(api.ai_config, "load_config", return_value={"peers": {}}),
            mock.patch.object(api, "_llama_swap_active", return_value=False),
            mock.patch.object(api.ai_config, "set_provider", return_value={"ok": True}) as setter,
            mock.patch.object(api, "_restart_llama_swap"),
        ):
            self.assertTrue(api.set_ai_provider(base)["ok"])
        self.assertFalse(setter.call_args.kwargs["credential"])

    def test_set_ai_provider_rolls_back_failed_config(self) -> None:
        active = self.active()
        base = {
            "id": "cloud",
            "url": "https://cloud.example/v1",
            "models": ["coder"],
            "apiKey": "new",
            "keepassPassword": "db",
        }
        snap = api.PrivateFileSnapshot(True, b"old", 0o600, 1, 1)
        with (
            mock.patch.object(api, "acquire_operation", return_value=contextlib.nullcontext(active)),
            mock.patch.object(api, "_snapshot_private_file", return_value=snap),
            mock.patch.object(api.ai_config, "load_config", return_value={"peers": {}}),
            mock.patch.object(api, "_llama_swap_active", return_value=True),
            mock.patch.object(api, "_write_provider_key"),
            mock.patch.object(api.ai_config, "set_provider", side_effect=ValueError("bad config")),
            mock.patch.object(api, "_rollback_provider_mutation") as rollback,
        ):
            with self.assertRaisesRegex(ValueError, "bad config"):
                api.set_ai_provider(base)
        self.assertTrue(rollback.called)
        self.assertTrue(rollback.call_args.kwargs["config_attempted"])

    def test_delete_ai_provider_requires_password_for_stored_key_and_happy_path(self) -> None:
        active = self.active()
        expected = "${env." + api.ai_config.provider_env_name("cloud") + "}"
        config = {"peers": {"cloud": {"apiKey": expected}}}
        snap = api.PrivateFileSnapshot(False)
        with (
            mock.patch.object(api, "acquire_operation", return_value=contextlib.nullcontext(active)),
            mock.patch.object(api, "_snapshot_private_file", return_value=snap),
            mock.patch.object(api.ai_config, "load_config", return_value=config),
        ):
            with self.assertRaisesRegex(api.ApiError, "password is required"):
                api.delete_ai_provider({"id": "cloud"})
        with (
            mock.patch.object(api, "acquire_operation", return_value=contextlib.nullcontext(active)),
            mock.patch.object(api, "_snapshot_private_file", return_value=snap),
            mock.patch.object(api.ai_config, "load_config", return_value={"peers": {}}),
            mock.patch.object(api, "_llama_swap_active", return_value=False),
            mock.patch.object(api.ai_config, "delete_provider", return_value={"ok": True}),
            mock.patch.object(api, "_restart_llama_swap"),
        ):
            self.assertTrue(api.delete_ai_provider({"id": "cloud"})["ok"])

    def test_local_model_role_and_advanced_validation_and_success(self) -> None:
        base = {"id": "local", "path": "/models/x.gguf"}
        for request, message in [
            ({**base, "context": True}, "context must be an integer"),
            ({**base, "context": 1, "ttl": True}, "TTL must be an integer"),
            ({**base, "context": 1, "tools": "yes"}, "tools capability"),
            ({**base, "context": 1, "extraArgs": [1]}, "Invalid extraArgs"),
        ]:
            with self.subTest(request=request), self.assertRaisesRegex(api.ApiError, message):
                api.set_ai_local_model(request)
        with (
            mock.patch.object(api, "operation_guard", return_value=contextlib.nullcontext()),
            mock.patch.object(api.ai_config, "set_local_model", return_value={"ok": True}),
        ):
            self.assertTrue(api.set_ai_local_model({**base, "context": 1024})["ok"])
        with (
            mock.patch.object(api, "operation_guard", return_value=contextlib.nullcontext()),
            mock.patch.object(api.ai_config, "delete_local_model", side_effect=api.ai_config.AiConfigError("missing")),
        ):
            with self.assertRaisesRegex(api.ApiError, "missing"):
                api.delete_ai_local_model({"id": "local"})
        with (
            mock.patch.object(api, "operation_guard", return_value=contextlib.nullcontext()),
            mock.patch.object(api.ai_config, "set_role", return_value={"ok": True}),
        ):
            self.assertTrue(
                api.set_ai_role({"role": "coding/default", "targets": ["cloud/coder"], "strategy": "pin"})["ok"]
            )
        with self.assertRaisesRegex(api.ApiError, "unsupported fields"):
            api.set_ai_advanced({})
        with (
            mock.patch.object(api, "operation_guard", return_value=contextlib.nullcontext()),
            mock.patch.object(api.ai_config, "replace_advanced", return_value={"ok": True}),
        ):
            self.assertTrue(api.set_ai_advanced({"globalTTL": 300})["ok"])

    def test_overview_aggregates_v2_services_and_probe_failures(self) -> None:
        managed = {"services": [{"id": "demo", "units": [{"unit": "demo.service"}, {"bad": True}]}]}
        healthy = CommandResult(0, "healthy", "")
        with (
            mock.patch.object(api, "managed_services_status", return_value=managed),
            mock.patch.object(api, "setup_status", return_value={"status": "ready"}),
            mock.patch.object(api, "identity_status", return_value={"users": []}),
            mock.patch.object(api, "capability_status", return_value={"capabilities": []}),
            mock.patch.object(api, "update_status", return_value={"ok": True}),
            mock.patch.object(api, "ai_configuration", return_value={"ok": True}),
            mock.patch.object(
                api, "service_states", return_value={"demo.service": {"activeState": "active"}}
            ) as states,
            mock.patch.object(api, "run", return_value=healthy),
            mock.patch.object(api, "operation_state", return_value={"busyClasses": []}),
            mock.patch.object(api, "portal_entries", return_value=[{"url": "/demo"}]),
            mock.patch.object(api, "read_optional_text", return_value=None),
            mock.patch.object(api.socket, "gethostname", return_value="nas-host"),
            mock.patch.object(pathlib.Path, "exists", return_value=True),
        ):
            result = api.overview()
        self.assertEqual(result["host"], "nas-host")
        self.assertTrue(result["zfs"]["healthy"])
        self.assertEqual(result["managedServices"], managed)
        self.assertIn("demo.service", states.call_args.args[0])

        with (
            mock.patch.object(api, "managed_services_status", return_value={"services": []}),
            mock.patch.object(api, "setup_status", side_effect=RuntimeError("probe failed")),
            mock.patch.object(api, "identity_status", return_value={}),
            mock.patch.object(api, "capability_status", return_value={}),
            mock.patch.object(api, "update_status", return_value={}),
            mock.patch.object(api, "ai_configuration", return_value={}),
            mock.patch.object(api, "service_states", return_value={}),
            mock.patch.object(api, "run", return_value=CommandResult(1, "", "offline")),
            mock.patch.object(api, "operation_state", return_value={}),
            mock.patch.object(api, "portal_entries", return_value=[]),
            mock.patch.object(api, "read_optional_text", return_value=None),
            mock.patch.object(api.secrets, "token_hex", return_value="f" * 12),
        ):
            result = api.overview()
        self.assertFalse(result["setup"]["ok"])
        self.assertIn("reference", result["setup"]["error"])
        self.assertFalse(result["zfs"]["healthy"])

    def test_read_optional_text_missing_empty_and_value(self) -> None:
        path = mock.Mock()
        path.read_text.side_effect = OSError("gone")
        self.assertIsNone(api.read_optional_text(path))
        path.read_text.side_effect = None
        path.read_text.return_value = "  "
        self.assertIsNone(api.read_optional_text(path))
        path.read_text.return_value = " warning \n"
        self.assertEqual(api.read_optional_text(path), "warning")

    def test_source_control_read_operations_and_mutations(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            with (
                mock.patch.object(api, "CONFIG_DIR", root),
                mock.patch.object(api, "run", return_value=CommandResult(0, "ok", "")) as run,
            ):
                for operation in ("status", "diff", "log"):
                    result = api.source_control({"operation": operation})
                    self.assertTrue(result["ok"])
                self.assertEqual(run.call_count, 3)

            active = self.active()
            with (
                mock.patch.object(api, "CONFIG_DIR", root),
                mock.patch.object(api, "acquire_operation", return_value=contextlib.nullcontext(active)),
                mock.patch.object(api, "run", return_value=CommandResult(0, "ok", "")) as run,
            ):
                result = api.source_control({"operation": "pull-rebuild"})
            self.assertTrue(result["ok"])
            self.assertEqual(len(result["commands"]), 2)
            self.assertEqual(run.call_args_list[0].kwargs["env"]["NAS_OPERATION_COORDINATION_TOKEN"], "coord-token")

    def test_source_control_rejects_unknown_missing_directory_busy_and_failed_mutation(self) -> None:
        with self.assertRaisesRegex(api.ApiError, "Unsupported source-control"):
            api.source_control({"operation": "reset"})
        with mock.patch.object(api, "CONFIG_DIR", pathlib.Path("/definitely/missing")):
            with self.assertRaisesRegex(api.ApiError, "does not exist"):
                api.source_control({"operation": "status"})
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            with (
                mock.patch.object(api, "CONFIG_DIR", root),
                mock.patch.object(api, "acquire_operation", side_effect=OperationBusyError("busy")),
            ):
                with self.assertRaisesRegex(api.ApiError, "busy"):
                    api.source_control({"operation": "pull"})
            active = self.active()
            with (
                mock.patch.object(api, "CONFIG_DIR", root),
                mock.patch.object(api, "acquire_operation", return_value=contextlib.nullcontext(active)),
                mock.patch.object(api, "run", return_value=CommandResult(1, "", "failed")),
            ):
                with self.assertRaises(api.ApiError):
                    api.source_control({"operation": "rebuild"})

    def test_build_parser_exposes_v2_managed_service_surface(self) -> None:
        parser = api.build_parser()
        args = parser.parse_args(["managed-service", "demo", "on-demand"])
        self.assertEqual((args.command, args.service, args.mode), ("managed-service", "demo", "on-demand"))
        args = parser.parse_args(["first-start-job-status", "a" * 24])
        self.assertEqual(args.job_id, "a" * 24)

    def test_main_dispatches_read_and_json_commands_and_handles_errors(self) -> None:
        cases = [
            (["nas-cockpit-api", "overview"], "overview", {"ok": True}),
            (["nas-cockpit-api", "operations"], "operation_state", {"ok": True}),
            (["nas-cockpit-api", "first-start-status"], "first_start_status", {"ok": True}),
        ]
        for argv, function, value in cases:
            with (
                self.subTest(argv=argv),
                mock.patch.object(api.os, "geteuid", return_value=0),
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(api, function, return_value=value),
                mock.patch("sys.stdout", new_callable=io.StringIO) as stdout,
            ):
                self.assertEqual(api.main(), 0)
                self.assertEqual(json.loads(stdout.getvalue()), value)

        with (
            mock.patch.object(api.os, "geteuid", return_value=1000),
            mock.patch.object(sys, "argv", ["nas-cockpit-api", "overview"]),
        ):
            self.assertEqual(api.main(), 1)
        with (
            mock.patch.object(api.os, "geteuid", return_value=0),
            mock.patch.object(sys, "argv", ["nas-cockpit-api", "overview"]),
            mock.patch.object(api, "overview", side_effect=api.ApiError("bad")),
        ):
            self.assertEqual(api.main(), 1)


if __name__ == "__main__":
    unittest.main()
