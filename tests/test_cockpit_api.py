from __future__ import annotations

import contextlib
import grp
import importlib.util
import io
import json
import os
import pathlib
import pwd
import socket
import sys
import tempfile
import threading
import time
import unittest
from email.message import Message
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
                            "available": True,
                            "runtimeAvailable": True,
                            "verified": True,
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

    def test_first_start_reboot_requires_completed_setup_and_matching_job_capability(self) -> None:
        completed = self.completed()
        with (
            mock.patch.object(api, "_setup_complete", return_value=False),
            mock.patch.object(api, "first_start_job_status") as job_status,
            mock.patch.object(api, "run") as run,
        ):
            with self.assertRaisesRegex(api.ApiError, "after first-start setup completes"):
                api.reboot_after_first_start({"jobId": "a" * 24})
        job_status.assert_not_called()
        run.assert_not_called()

        rejected = (
            {},
            {"jobId": "short"},
            {"jobId": "a" * 24, "extra": True},
        )
        for request in rejected:
            with (
                self.subTest(request=request),
                mock.patch.object(api, "_setup_complete", return_value=True),
                mock.patch.object(api, "first_start_job_status") as job_status,
                mock.patch.object(api, "run") as run,
            ):
                with self.assertRaisesRegex(api.ApiError, "completed first-start job"):
                    api.reboot_after_first_start(request)
            job_status.assert_not_called()
            run.assert_not_called()

        with (
            mock.patch.object(api, "_setup_complete", return_value=True),
            mock.patch.object(api, "first_start_job_status", return_value={"status": "running"}),
            mock.patch.object(api, "run") as run,
        ):
            with self.assertRaisesRegex(api.ApiError, "completed first-start job"):
                api.reboot_after_first_start({"jobId": "a" * 24})
        run.assert_not_called()

        with (
            mock.patch.object(api, "_setup_complete", return_value=True),
            mock.patch.object(api, "first_start_job_status", return_value={"status": "complete"}) as job_status,
            mock.patch.object(api, "run", return_value=completed) as run,
        ):
            self.assertEqual(api.reboot_after_first_start({"jobId": "a" * 24}), {"rebooting": True})
        job_status.assert_called_once_with("a" * 24)
        run.assert_called_once_with(["systemctl", "reboot"], check=False, timeout_seconds=30)

    def test_first_start_reboot_reports_systemd_failure(self) -> None:
        with (
            mock.patch.object(api, "_setup_complete", return_value=True),
            mock.patch.object(api, "first_start_job_status", return_value={"status": "complete-unverified"}),
            mock.patch.object(api, "run", return_value=self.completed(returncode=1)),
        ):
            with self.assertRaisesRegex(api.ApiError, "Unable to schedule"):
                api.reboot_after_first_start({"jobId": "b" * 24})

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


class SetupApiTransportTests(unittest.TestCase):
    """A04/A06: the setup API listens on a permissioned Unix socket with bounded requests."""

    def fake_handler(self, *, command="POST", headers=None, body=b""):
        handler = api.SetupApiHandler.__new__(api.SetupApiHandler)
        handler.command = command
        message = Message()
        for name, value in (headers or {}).items():
            if isinstance(value, list):
                for item in value:
                    message[name] = item
            else:
                message[name] = value
        handler.headers = message
        handler.rfile = io.BytesIO(body)
        return handler

    def test_serve_listens_on_unix_socket_not_loopback_tcp(self) -> None:
        parsed = api.build_parser().parse_args(["serve", "--socket-path", "/run/nas-setup-api/setup.sock"])
        self.assertEqual(parsed.socket_path, "/run/nas-setup-api/setup.sock")
        help_text = api.build_parser().format_help()
        self.assertNotIn("--bind", help_text)
        self.assertNotIn("--port", help_text)
        self.assertNotIn("127.0.0.1", api.SETUP_SOCKET_DOC)

    def test_request_framing_rejects_abusive_bodies(self) -> None:
        cases = [
            ("negative length", {"Content-Length": "-1"}, b"", 400),
            ("missing length", {}, b'{"a":1}', 411),
            ("conflicting lengths", {"Content-Length": ["5", "6"]}, b"", 411),
            ("malformed length", {"Content-Length": "many"}, b"", 400),
            ("oversized body", {"Content-Length": str(api.MAX_JSON_INPUT_BYTES + 1)}, b"", 413),
            ("truncated body", {"Content-Length": "100"}, b'{"a":', 400),
            ("chunked framing", {"Content-Length": "4", "Transfer-Encoding": "chunked"}, b"true", 400),
            ("malformed json", {"Content-Length": "3"}, b"{{{", 400),
            ("non-object json", {"Content-Length": "3"}, b"[1]", 400),
        ]
        for label, headers, body, status in cases:
            with self.subTest(label=label):
                with self.assertRaises(api.SetupApiError) as raised:
                    self.fake_handler(headers=headers, body=body)._read_bounded_json()
                self.assertEqual(raised.exception.status, status, label)

    def test_valid_and_empty_posts_pass_framing(self) -> None:
        valid = json.dumps({"jobId": "a" * 24}).encode()
        request = self.fake_handler(headers={"Content-Length": str(len(valid))}, body=valid)._read_bounded_json()
        self.assertEqual(request, {"jobId": "a" * 24})
        self.assertEqual(self.fake_handler(headers={"Content-Length": "0"}, body=b"")._read_bounded_json(), {})

    def test_get_with_body_indicators_is_rejected(self) -> None:
        for headers in ({"Content-Length": "5"}, {"Transfer-Encoding": "chunked"}):
            with self.subTest(headers=headers):
                with self.assertRaises(api.SetupApiError):
                    self.fake_handler(command="GET", headers=headers, body=b"")._read_bounded_json()

    def test_logs_never_carry_paths_queries_or_capabilities(self) -> None:
        capability = "f" * 48
        handler = api.SetupApiHandler.__new__(api.SetupApiHandler)
        handler.command = "GET"
        handler.path = f"/setup/api/first-start/job?capability={capability}"
        records: list[str] = []
        with mock.patch.object(api.syslog, "syslog", side_effect=lambda *args: records.append(args[-1])):
            handler.log_message('"%s" %s %s', f"/setup/api/first-start/job?capability={capability}", "200", "-")
        self.assertTrue(records)
        for record in records:
            self.assertNotIn(capability, record)
            self.assertNotIn("?", record)
            self.assertIn("nas-setup-api GET /setup/api/first-start/job", record)

    def live_server(self, directory: str):
        socket_path = str(pathlib.Path(directory) / "setup.sock")
        current_user = pwd.getpwuid(os.getuid()).pw_name
        current_group = grp.getgrgid(os.getgid()).gr_name
        patches = (
            mock.patch.object(api, "SETUP_CADDY_USER", current_user),
            mock.patch.object(api, "SETUP_CADDY_GROUP", current_group),
        )
        for patch in patches:
            patch.start()
        self.addCleanup(lambda: [patch.stop() for patch in patches])
        server = api._bind_setup_socket(pathlib.Path(socket_path))
        api._permission_setup_socket(pathlib.Path(socket_path))
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, 5)
        self.addCleanup(server.shutdown)
        return server, socket_path

    def raw_exchange(self, socket_path: str, payload: bytes, *, timeout: int = 10) -> bytes:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(timeout)
        try:
            client.connect(socket_path)
            try:
                client.sendall(payload)
            except (ConnectionResetError, BrokenPipeError):
                return b""
            chunks = []
            try:
                while True:
                    chunk = client.recv(65536)
                    if not chunk:
                        break
                    chunks.append(chunk)
            except (socket.timeout, ConnectionResetError, BrokenPipeError):
                pass
            return b"".join(chunks)
        finally:
            client.close()

    def test_socket_is_caddy_only_and_serves_without_tcp(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            server, socket_path = self.live_server(directory)
            mode = oct(pathlib.Path(socket_path).stat().st_mode & 0o777)
            self.assertEqual(mode, "0o770")
            self.assertEqual(pathlib.Path(socket_path).stat().st_gid, os.getgid())
            response = self.raw_exchange(socket_path, b"GET /setup/api/unknown HTTP/1.0\r\n\r\n")
            self.assertIn(b"404", response.split(b"\r\n", 1)[0])
            self.assertNotIn(b"8980", response)

    def test_unauthorized_peer_is_disconnected_without_response(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            server, socket_path = self.live_server(directory)
            with mock.patch.object(api.SetupApiUnixServer, "_peer_allowed", return_value=False):
                response = self.raw_exchange(socket_path, b"GET /setup/api/unknown HTTP/1.0\r\n\r\n")
            self.assertEqual(response, b"")

    def test_concurrency_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            current_user = pwd.getpwuid(os.getuid()).pw_name
            with mock.patch.object(api, "SETUP_CADDY_USER", current_user):
                server = api.SetupApiUnixServer(str(pathlib.Path(directory) / "setup.sock"), api.SetupApiHandler)
            self.addCleanup(server.server_close)
            for _ in range(api.SETUP_MAX_CONNECTIONS):
                self.assertTrue(server._connection_gate.acquire(blocking=False))
            closed: list[object] = []
            request = mock.Mock()
            request.close.side_effect = lambda: closed.append(request)
            with (
                mock.patch.object(server, "_peer_allowed", return_value=True),
                mock.patch.object(server, "finish_request") as finish,
            ):
                server.process_request(request, None)
            finish.assert_not_called()
            self.assertEqual(closed, [request])

    def test_slow_body_is_cut_off_by_connection_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(api, "SETUP_SOCKET_TIMEOUT_SECONDS", 1):
                server, socket_path = self.live_server(directory)
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                client.settimeout(10)
                try:
                    client.connect(socket_path)
                    client.sendall(b"POST /setup/api/nope HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n{")
                    started = time.monotonic()
                    try:
                        while client.recv(65536):
                            pass
                    except (socket.timeout, ConnectionResetError, BrokenPipeError):
                        pass
                    self.assertLess(time.monotonic() - started, 9)
                finally:
                    client.close()

    def test_trickle_headers_and_body_cannot_hold_connection_slots_past_wall_clock_deadline(self) -> None:
        prefixes = (
            b"POST /setup/api/nope HTTP/1.1\r\nHost: x\r\nX-Trickle: ",
            b"POST /setup/api/nope HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n{",
        )
        for prefix in prefixes:
            with self.subTest(prefix=prefix), tempfile.TemporaryDirectory() as directory:
                with mock.patch.object(api, "SETUP_SOCKET_TIMEOUT_SECONDS", 0.4):
                    server, socket_path = self.live_server(directory)
                    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    client.settimeout(2)
                    client.connect(socket_path)
                    client.sendall(prefix)
                    stopped = threading.Event()

                    def trickle() -> None:
                        while not stopped.wait(0.08):
                            try:
                                client.sendall(b"a")
                            except (ConnectionResetError, BrokenPipeError, OSError):
                                return

                    sender = threading.Thread(target=trickle, daemon=True)
                    sender.start()
                    deadline = time.monotonic() + 1.2
                    acquired: list[bool] = []
                    while time.monotonic() < deadline:
                        acquired = [
                            server._connection_gate.acquire(blocking=False) for _ in range(api.SETUP_MAX_CONNECTIONS)
                        ]
                        for held in acquired:
                            if held:
                                server._connection_gate.release()
                        if all(acquired):
                            break
                        time.sleep(0.02)
                    self.assertTrue(all(acquired), "trickle connection retained a semaphore slot past its deadline")
                    stopped.set()
                    client.close()
                    sender.join(1)

    def test_live_framing_statuses(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            _, socket_path = self.live_server(directory)
            oversized = (
                f"POST /setup/api/nope HTTP/1.0\r\nContent-Length: {api.MAX_JSON_INPUT_BYTES + 1}\r\n\r\n".encode()
            )
            self.assertIn(b"413", self.raw_exchange(socket_path, oversized).split(b"\r\n", 1)[0])
            negative = b"POST /setup/api/nope HTTP/1.0\r\nContent-Length: -5\r\n\r\n"
            self.assertIn(b"400", self.raw_exchange(socket_path, negative).split(b"\r\n", 1)[0])
            missing = b"POST /setup/api/nope HTTP/1.0\r\n\r\n{}"
            self.assertIn(b"411", self.raw_exchange(socket_path, missing).split(b"\r\n", 1)[0])
            get_body = b"GET /setup/api/unknown HTTP/1.0\r\nContent-Length: 2\r\n\r\n{}"
            self.assertIn(b"400", self.raw_exchange(socket_path, get_body).split(b"\r\n", 1)[0])


class SetupApiCapabilityTests(unittest.TestCase):
    """A05/A13: header capability lifecycle, resume, and reboot authorization."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = pathlib.Path(self.temporary.name)
        self.capability_dir = root / "capabilities"
        self.active_job = root / "active-job.json"
        patches = (
            mock.patch.object(api, "SETUP_CAPABILITY_DIR", self.capability_dir),
            mock.patch.object(api, "SETUP_ACTIVE_JOB_PATH", self.active_job),
            mock.patch.object(api, "SETUP_STATE_PATH", root / "state.json"),
        )
        for patch in patches:
            patch.start()
        self.addCleanup(lambda: [patch.stop() for patch in patches])

    def test_capability_roundtrip_and_format(self) -> None:
        with mock.patch.object(api, "first_start_job_status", return_value={"status": "running"}):
            token = api.issue_setup_capability("a" * 24, now=1000.0)
            self.assertRegex(token, r"^[0-9a-f]{48}$")
            self.assertEqual(api.lookup_setup_capability(token, now=1000.0), "a" * 24)
            self.assertIsNone(api.lookup_setup_capability("b" * 48, now=1000.0))
            self.assertIsNone(api.lookup_setup_capability("not-a-capability", now=1000.0))
            self.assertIsNone(api.lookup_setup_capability("", now=1000.0))

    def test_capability_expires_after_inactivity_and_absolute_lifetime(self) -> None:
        with mock.patch.object(api, "first_start_job_status", return_value={"status": "running"}):
            token = api.issue_setup_capability("a" * 24, now=1000.0)
            self.assertEqual(api.lookup_setup_capability(token, now=1000.0 + 1700.0), "a" * 24)
            self.assertEqual(api.lookup_setup_capability(token, now=1000.0 + 3400.0), "a" * 24)
            self.assertIsNone(api.lookup_setup_capability(token, now=1000.0 + 3400.0 + 1801.0))
            self.assertEqual(list(self.capability_dir.glob("*.json")), [])
            fresh = api.issue_setup_capability("a" * 24, now=2000.0)
            self.assertIsNone(api.lookup_setup_capability(fresh, now=2000.0 + 86401.0))
            self.assertEqual(list(self.capability_dir.glob("*.json")), [])

    def test_invalid_job_state_revokes_capability(self) -> None:
        with mock.patch.object(api, "first_start_job_status", return_value={"status": "running"}):
            token = api.issue_setup_capability("a" * 24, now=1000.0)
        with mock.patch.object(api, "first_start_job_status", side_effect=api.ApiError("gone")):
            self.assertIsNone(api.lookup_setup_capability(token, now=1000.0))
        self.assertEqual(list(self.capability_dir.glob("*.json")), [])

    def test_cancelled_job_state_revokes_capability(self) -> None:
        with mock.patch.object(api, "first_start_job_status", return_value={"status": "running"}):
            token = api.issue_setup_capability("a" * 24, now=1000.0)
        with mock.patch.object(api, "first_start_job_status", return_value={"status": "cancelled"}):
            self.assertIsNone(api.lookup_setup_capability(token, now=1001.0))
        self.assertEqual(list(self.capability_dir.glob("*.json")), [])

    def test_failed_job_remains_authorized_for_terminal_status_delivery(self) -> None:
        with mock.patch.object(api, "first_start_job_status", return_value={"status": "running"}):
            token = api.issue_setup_capability("a" * 24, now=1000.0)
        with mock.patch.object(api, "first_start_job_status", return_value={"status": "failed"}):
            self.assertEqual(api.lookup_setup_capability(token, now=1001.0), "a" * 24)
        self.assertTrue(api._capability_record_path(token).is_file())

    def test_lookup_cannot_recreate_a_concurrently_revoked_capability(self) -> None:
        with mock.patch.object(api, "first_start_job_status", return_value={"status": "running"}):
            token = api.issue_setup_capability("a" * 24, now=1000.0)
        original_write = api._write_private_replace
        lookup_writing = threading.Event()
        allow_lookup_write = threading.Event()

        def delayed_write(path, content):
            if path == api._capability_record_path(token) and '"lastUsedAt": 1001.0' in content:
                lookup_writing.set()
                allow_lookup_write.wait(2)
            return original_write(path, content)

        lookup_result: list[object] = []
        revoke_done = threading.Event()
        with (
            mock.patch.object(api, "_write_private_replace", side_effect=delayed_write),
            mock.patch.object(api, "first_start_job_status", return_value={"status": "running"}),
        ):
            lookup = threading.Thread(
                target=lambda: lookup_result.append(api.lookup_setup_capability(token, now=1001.0)), daemon=True
            )
            lookup.start()
            self.assertTrue(lookup_writing.wait(1))
            revoke = threading.Thread(
                target=lambda: (api.revoke_setup_capability(token), revoke_done.set()), daemon=True
            )
            revoke.start()
            time.sleep(0.1)
            self.assertFalse(revoke_done.is_set(), "revocation was not serialized with capability refresh")
            allow_lookup_write.set()
            lookup.join(2)
            revoke.join(2)
        self.assertTrue(revoke_done.is_set())
        self.assertFalse(api._capability_record_path(token).exists())

    def test_active_job_record_roundtrip_and_invalid_clearing(self) -> None:
        self.assertIsNone(api.read_active_setup_job())
        api.record_active_setup_job("a" * 24)
        self.assertEqual(api.read_active_setup_job(), "a" * 24)
        self.active_job.write_text(json.dumps({"jobId": "bogus"}), encoding="utf-8")
        self.assertIsNone(api.read_active_setup_job())
        api.record_active_setup_job("b" * 24)
        api.clear_active_setup_job()
        self.assertIsNone(api.read_active_setup_job())

    def test_revocation_scopes(self) -> None:
        with mock.patch.object(api, "first_start_job_status", return_value={"status": "running"}):
            first = api.issue_setup_capability("a" * 24, now=1000.0)
            second = api.issue_setup_capability("a" * 24, now=1000.0)
            other = api.issue_setup_capability("b" * 24, now=1000.0)
            api.revoke_setup_capability(first)
            self.assertIsNone(api.lookup_setup_capability(first, now=1000.0))
            self.assertEqual(api.lookup_setup_capability(second, now=1000.0), "a" * 24)
            api.revoke_job_capabilities("a" * 24)
            self.assertIsNone(api.lookup_setup_capability(second, now=1000.0))
            self.assertEqual(api.lookup_setup_capability(other, now=1000.0), "b" * 24)
            api.revoke_all_setup_capabilities()
            self.assertIsNone(api.lookup_setup_capability(other, now=1000.0))

    def live_server(self, directory: str):
        socket_path = str(pathlib.Path(directory) / "setup.sock")
        current_user = pwd.getpwuid(os.getuid()).pw_name
        current_group = grp.getgrgid(os.getgid()).gr_name
        patches = (
            mock.patch.object(api, "SETUP_CADDY_USER", current_user),
            mock.patch.object(api, "SETUP_CADDY_GROUP", current_group),
        )
        for patch in patches:
            patch.start()
        self.addCleanup(lambda: [patch.stop() for patch in patches])
        server = api._bind_setup_socket(pathlib.Path(socket_path))
        api._permission_setup_socket(pathlib.Path(socket_path))
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, 5)
        self.addCleanup(server.shutdown)
        return server, socket_path

    def exchange(self, socket_path, method, target, *, headers=None, body=None):
        lines = [f"{method} {target} HTTP/1.0", "Host: setup"]
        payload = b"" if body is None else json.dumps(body).encode()
        if method == "POST":
            lines.append(f"Content-Length: {len(payload)}")
        for name, value in (headers or {}).items():
            lines.append(f"{name}: {value}")
        raw = ("\r\n".join(lines) + "\r\n\r\n").encode() + payload
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(10)
        try:
            client.connect(socket_path)
            client.sendall(raw)
            chunks = []
            try:
                while True:
                    chunk = client.recv(65536)
                    if not chunk:
                        break
                    chunks.append(chunk)
            except (socket.timeout, ConnectionResetError, BrokenPipeError):
                pass
            head, _, response_body = b"".join(chunks).partition(b"\r\n\r\n")
            return head.split(b"\r\n", 1)[0], json.loads(response_body.decode() or "{}")
        finally:
            client.close()

    def test_job_id_in_url_no_longer_authorizes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            _, socket_path = self.live_server(directory)
            status, _ = self.exchange(socket_path, "GET", f"/setup/api/first-start/job/{'a' * 24}")
            self.assertIn(b"404", status)

    def test_status_requires_capability_header(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            _, socket_path = self.live_server(directory)
            status, _ = self.exchange(socket_path, "GET", "/setup/api/first-start/job")
            self.assertIn(b"401", status)
            status, _ = self.exchange(
                socket_path, "GET", "/setup/api/first-start/job", headers={"X-NAS-Setup-Capability": "short"}
            )
            self.assertIn(b"401", status)

    def test_submit_mints_capability_and_supersedes_previous(self) -> None:
        submitted = {"schemaVersion": 1, "jobId": "a" * 24, "status": "submitted"}
        with tempfile.TemporaryDirectory() as directory:
            _, socket_path = self.live_server(directory)
            with (
                mock.patch.object(api, "start_first_start", return_value=dict(submitted)) as submit,
                mock.patch.object(api, "first_start_job_status", return_value={"status": "running"}),
            ):
                _, first = self.exchange(socket_path, "POST", "/setup/api/first-run", body={})
                _, second = self.exchange(socket_path, "POST", "/setup/api/first-run", body={})
                self.assertEqual(submit.call_count, 2)
                for response in (first, second):
                    self.assertRegex(response["capability"], r"^[0-9a-f]{48}$")
                    self.assertNotEqual(response["capability"], "a" * 24)
                old_status, _ = self.exchange(
                    socket_path,
                    "GET",
                    "/setup/api/first-start/job",
                    headers={"X-NAS-Setup-Capability": first["capability"]},
                )
                self.assertIn(b"401", old_status)
                new_status, body = self.exchange(
                    socket_path,
                    "GET",
                    "/setup/api/first-start/job",
                    headers={"X-NAS-Setup-Capability": second["capability"]},
                )
                self.assertIn(b"200", new_status)
                self.assertEqual(body["status"], "running")
            self.assertEqual(api.read_active_setup_job(), "a" * 24)

    def test_completed_submission_returns_no_capability(self) -> None:
        prepared = {
            "schemaVersion": 1,
            "status": "complete",
            "planDigest": "c" * 64,
            "completedAt": 1234,
        }
        api.SETUP_STATE_PATH.write_text(json.dumps(prepared), encoding="utf-8")
        with tempfile.TemporaryDirectory() as directory:
            _, socket_path = self.live_server(directory)
            with mock.patch.object(api, "start_first_start", return_value=dict(prepared)):
                status, body = self.exchange(socket_path, "POST", "/setup/api/first-run", body={})
            self.assertIn(b"200", status)
            self.assertRegex(body["capability"], r"^[0-9a-f]{48}$")
            self.assertIsNone(api.read_active_setup_job())
            poll_status, _ = self.exchange(
                socket_path,
                "GET",
                "/setup/api/first-start/job",
                headers={"X-NAS-Setup-Capability": body["capability"]},
            )
            self.assertIn(b"401", poll_status)

    def test_completed_association_is_plan_bound_and_expires(self) -> None:
        completed = {"schemaVersion": 2, "status": "complete", "planDigest": "c" * 64, "completedAt": 1234}
        api.SETUP_STATE_PATH.write_text(json.dumps(completed), encoding="utf-8")
        token = api.issue_completed_setup_capability(completed, now=1000.0)
        self.assertTrue(api.lookup_completed_setup_capability(token, now=1000.0 + 1700.0))
        self.assertFalse(api.lookup_completed_setup_capability(token, now=1000.0 + 1700.0 + 1801.0))
        token = api.issue_completed_setup_capability(completed, now=2000.0)
        changed = {**completed, "planDigest": "d" * 64}
        api.SETUP_STATE_PATH.write_text(json.dumps(changed), encoding="utf-8")
        self.assertFalse(api.lookup_completed_setup_capability(token, now=2001.0))
        self.assertEqual(list(self.capability_dir.glob("*.json")), [])

    def test_completed_association_authorizes_reboot_without_a_job_and_is_revoked(self) -> None:
        completed = {"schemaVersion": 2, "status": "complete", "planDigest": "c" * 64, "completedAt": 1234}
        api.SETUP_STATE_PATH.write_text(json.dumps(completed), encoding="utf-8")
        token = api.issue_completed_setup_capability(completed)
        with tempfile.TemporaryDirectory() as directory:
            _, socket_path = self.live_server(directory)
            with (
                mock.patch.object(api, "first_start_job_status") as job_status,
                mock.patch.object(api, "run", return_value=mock.Mock(returncode=0)),
            ):
                status, body = self.exchange(
                    socket_path,
                    "POST",
                    "/setup/api/reboot",
                    headers={"X-NAS-Setup-Capability": token},
                    body={},
                )
            self.assertIn(b"200", status)
            self.assertEqual(body, {"rebooting": True})
            job_status.assert_not_called()
            self.assertFalse(api.lookup_completed_setup_capability(token))

    def test_resume_recovers_active_job_with_fresh_capability(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            _, socket_path = self.live_server(directory)
            status, _ = self.exchange(socket_path, "POST", "/setup/api/first-start/resume", body={})
            self.assertIn(b"404", status)
            with mock.patch.object(api, "first_start_job_status", return_value={"status": "running"}):
                stale = api.issue_setup_capability("a" * 24)
                api.record_active_setup_job("a" * 24)
            with mock.patch.object(
                api, "first_start_job_status", return_value={"status": "running", "jobId": "a" * 24}
            ):
                status, body = self.exchange(socket_path, "POST", "/setup/api/first-start/resume", body={})
            self.assertIn(b"200", status)
            self.assertEqual(body["jobId"], "a" * 24)
            self.assertRegex(body["capability"], r"^[0-9a-f]{48}$")
            with mock.patch.object(api, "first_start_job_status", return_value={"status": "running"}):
                self.assertIsNone(api.lookup_setup_capability(stale))
                self.assertEqual(api.lookup_setup_capability(body["capability"]), "a" * 24)

    def test_reboot_revokes_capabilities_and_clears_active_job(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            _, socket_path = self.live_server(directory)
            with mock.patch.object(api, "first_start_job_status", return_value={"status": "running"}):
                running = api.issue_setup_capability("a" * 24)
                api.record_active_setup_job("a" * 24)
                status, _ = self.exchange(
                    socket_path, "POST", "/setup/api/reboot", headers={"X-NAS-Setup-Capability": running}, body={}
                )
                self.assertIn(b"400", status)
                self.assertEqual(api.lookup_setup_capability(running), "a" * 24)
            with (
                mock.patch.object(api, "_setup_complete", return_value=True),
                mock.patch.object(api, "first_start_job_status", return_value={"status": "complete"}),
                mock.patch.object(api, "run", return_value=mock.Mock(returncode=0)),
            ):
                status, body = self.exchange(
                    socket_path, "POST", "/setup/api/reboot", headers={"X-NAS-Setup-Capability": running}, body={}
                )
            self.assertIn(b"200", status)
            self.assertEqual(body, {"rebooting": True})
            self.assertIsNone(api.read_active_setup_job())
            with mock.patch.object(api, "first_start_job_status", return_value={"status": "complete"}):
                self.assertIsNone(api.lookup_setup_capability(running))

    def test_capability_bytes_never_reach_logs(self) -> None:
        submitted = {"schemaVersion": 1, "jobId": "a" * 24, "status": "submitted"}
        with tempfile.TemporaryDirectory() as directory:
            _, socket_path = self.live_server(directory)
            records: list[str] = []
            with (
                mock.patch.object(api, "start_first_start", return_value=dict(submitted)),
                mock.patch.object(api, "first_start_job_status", return_value={"status": "running"}),
                mock.patch.object(api.syslog, "syslog", side_effect=lambda *args: records.append(args[-1])),
            ):
                _, body = self.exchange(socket_path, "POST", "/setup/api/first-run", body={})
                token = body["capability"]
                self.exchange(
                    socket_path,
                    "GET",
                    "/setup/api/first-start/job",
                    headers={"X-NAS-Setup-Capability": token},
                )
                self.exchange(
                    socket_path, "POST", "/setup/api/reboot", headers={"X-NAS-Setup-Capability": token}, body={}
                )
            self.assertTrue(records)
            for record in records:
                self.assertNotIn(token, record)


if __name__ == "__main__":
    unittest.main()
