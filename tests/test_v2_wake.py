from __future__ import annotations

import json
import os
import pathlib
import socket
import stat
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_wake as wake  # noqa: E402


class V2WakeTests(unittest.TestCase):
    def effective(
        self,
        *,
        enabled: bool = True,
        managed: bool = True,
        activation: str = "on-demand",
        readiness: bool = False,
        dependencies: list[dict[str, str]] | None = None,
    ) -> dict:
        service = {
            "name": "Demo",
            "enabled": enabled,
            "managed": managed,
            "workload": {"kind": "daemon", "activation": activation, "idleSeconds": 60},
            "dependencies": dependencies or [],
        }
        if readiness:
            service["readiness"] = {"timeoutSeconds": 5, "probes": [{"type": "tcp", "port": 8000}]}
        return {
            "schemaVersion": 3,
            "services": {"demo": service},
            "derived": {"runtime": {"demo": {"ownerUnit": "nas-v2-demo.service"}}},
        }

    def make_systemctl(
        self,
        root: pathlib.Path,
        *,
        exit_code: int = 0,
        initially_active: bool = False,
    ) -> tuple[pathlib.Path, pathlib.Path]:
        log = root / "systemctl.log"
        script = root / "systemctl"
        active_code = 0 if initially_active else 3
        script.write_text(
            "#!/bin/sh\n"
            'printf "%s\\n" "$*" >> "$NAS_V2_WAKE_SYSTEMCTL_LOG"\n'
            f'if [ "$1" = "is-active" ]; then exit {active_code}; fi\n'
            f"exit {exit_code}\n",
            encoding="utf-8",
        )
        script.chmod(script.stat().st_mode | stat.S_IXUSR)
        return script, log

    def test_parse_request_accepts_only_service_identity(self):
        request = b"GET /wake?service=demo HTTP/1.1\r\nHost: localhost\r\n\r\n"
        self.assertEqual(wake.parse_request(request), "demo")

        for invalid in (
            b"POST /wake?service=demo HTTP/1.1\r\n\r\n",
            b"GET /wake?service=demo&user=alice HTTP/1.1\r\n\r\n",
            b"GET /wake?service=demo;rm HTTP/1.1\r\n\r\n",
            b"GET /other?service=demo HTTP/1.1\r\n\r\n",
        ):
            with self.subTest(request=invalid), self.assertRaises(wake.WakeError):
                wake.parse_request(invalid)

    def test_wake_acquires_lease_and_resets_native_idle_timer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            systemctl, log = self.make_systemctl(root)
            with mock.patch.dict(os.environ, {"NAS_V2_WAKE_SYSTEMCTL_LOG": str(log)}):
                wake.wake_service(self.effective(), "demo", systemctl=str(systemctl))
            self.assertEqual(
                log.read_text(encoding="utf-8").splitlines(),
                [
                    "is-active --quiet nas-v2-lease-demo.target",
                    "start nas-v2-lease-demo.target",
                    "restart nas-v2-idle-demo.timer",
                ],
            )

    def test_wake_with_readiness_still_uses_single_native_lease_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            systemctl, log = self.make_systemctl(root)
            with mock.patch.dict(os.environ, {"NAS_V2_WAKE_SYSTEMCTL_LOG": str(log)}):
                wake.wake_service(self.effective(readiness=True), "demo", systemctl=str(systemctl))
            commands = log.read_text(encoding="utf-8")
            self.assertIn("start nas-v2-lease-demo.target", commands)
            self.assertIn("restart nas-v2-idle-demo.timer", commands)
            self.assertNotIn("nas-v2-ready-demo.service", commands)

    def test_transitive_on_demand_dependencies_get_leases_first(self):
        effective = self.effective(dependencies=[{"service": "runtime", "condition": "started"}])
        effective["services"]["runtime"] = {
            "name": "Runtime",
            "enabled": True,
            "managed": True,
            "workload": {"kind": "daemon", "activation": "on-demand", "idleSeconds": 300},
            "dependencies": [],
        }
        effective["derived"]["runtime"]["runtime"] = {"ownerUnit": "nas-runtime.service"}

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            systemctl, log = self.make_systemctl(root)
            with mock.patch.dict(os.environ, {"NAS_V2_WAKE_SYSTEMCTL_LOG": str(log)}):
                wake.wake_service(effective, "demo", systemctl=str(systemctl))
            lines = log.read_text(encoding="utf-8").splitlines()
            self.assertLess(
                lines.index("start nas-v2-lease-runtime.target"),
                lines.index("start nas-v2-lease-demo.target"),
            )
            self.assertIn("restart nas-v2-idle-runtime.timer", lines)
            self.assertIn("restart nas-v2-idle-demo.timer", lines)

    def test_non_on_demand_or_unmanaged_services_are_not_started(self):
        cases = (
            self.effective(enabled=False),
            self.effective(managed=False),
            self.effective(activation="persistent"),
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            systemctl, log = self.make_systemctl(root)
            for effective in cases:
                with (
                    self.subTest(service=effective["services"]["demo"]),
                    mock.patch.dict(os.environ, {"NAS_V2_WAKE_SYSTEMCTL_LOG": str(log)}),
                    self.assertRaises(wake.WakeError),
                ):
                    wake.wake_service(effective, "demo", systemctl=str(systemctl))
            self.assertFalse(log.exists())

    def test_systemctl_failure_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            systemctl, log = self.make_systemctl(root, exit_code=7)
            with (
                mock.patch.dict(os.environ, {"NAS_V2_WAKE_SYSTEMCTL_LOG": str(log)}),
                self.assertRaisesRegex(wake.WakeError, "activation failed"),
            ):
                wake.wake_service(self.effective(), "demo", systemctl=str(systemctl))
            self.assertIn("start nas-v2-lease-demo.target", log.read_text(encoding="utf-8"))

    def test_failed_later_activation_releases_new_dependency_lease(self):
        effective = self.effective(dependencies=[{"service": "runtime", "condition": "started"}])
        effective["services"]["runtime"] = {
            "name": "Runtime",
            "enabled": True,
            "managed": True,
            "workload": {"kind": "daemon", "activation": "on-demand", "idleSeconds": 300},
            "dependencies": [],
        }
        effective["derived"]["runtime"]["runtime"] = {"ownerUnit": "nas-runtime.service"}

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            log = root / "systemctl.log"
            systemctl = root / "systemctl"
            systemctl.write_text(
                """#!/bin/sh
printf "%s\n" "$*" >> "$NAS_V2_WAKE_SYSTEMCTL_LOG"
if [ "$1" = "is-active" ]; then exit 3; fi
if [ "$*" = "start nas-v2-lease-demo.target" ]; then exit 7; fi
exit 0
""",
                encoding="utf-8",
            )
            systemctl.chmod(systemctl.stat().st_mode | stat.S_IXUSR)
            with (
                mock.patch.dict(os.environ, {"NAS_V2_WAKE_SYSTEMCTL_LOG": str(log)}),
                self.assertRaises(wake.WakeError),
            ):
                wake.wake_service(effective, "demo", systemctl=str(systemctl))
            commands = log.read_text(encoding="utf-8")
            self.assertIn("stop nas-v2-lease-runtime.target", commands)

    def test_socket_handler_returns_204_after_successful_native_start(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            effective_path = root / "effective.json"
            effective_path.write_text(json.dumps(self.effective(readiness=True)), encoding="utf-8")
            systemctl, log = self.make_systemctl(root)
            client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            self.addCleanup(client.close)
            self.addCleanup(server.close)
            client.sendall(b"GET /wake?service=demo HTTP/1.1\r\nHost: local\r\n\r\n")

            with mock.patch.dict(os.environ, {"NAS_V2_WAKE_SYSTEMCTL_LOG": str(log)}):
                result = wake.serve_connection(
                    effective_path=effective_path,
                    systemctl=str(systemctl),
                    fd=server.fileno(),
                )
            response = client.recv(4096)

            self.assertEqual(result, 0)
            self.assertTrue(response.startswith(b"HTTP/1.1 204 No Content\r\n"))
            self.assertIn("start nas-v2-lease-demo.target", log.read_text(encoding="utf-8"))

    def test_socket_handler_rejects_unknown_service_without_systemctl(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            effective_path = root / "effective.json"
            effective_path.write_text(json.dumps(self.effective()), encoding="utf-8")
            systemctl, log = self.make_systemctl(root)
            client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            self.addCleanup(client.close)
            self.addCleanup(server.close)
            client.sendall(b"GET /wake?service=missing HTTP/1.1\r\nHost: local\r\n\r\n")

            with mock.patch.dict(os.environ, {"NAS_V2_WAKE_SYSTEMCTL_LOG": str(log)}):
                result = wake.serve_connection(
                    effective_path=effective_path,
                    systemctl=str(systemctl),
                    fd=server.fileno(),
                )
            response = client.recv(4096)

            self.assertEqual(result, 0)
            self.assertTrue(response.startswith(b"HTTP/1.1 404 Not Found\r\n"))
            self.assertFalse(log.exists())


if __name__ == "__main__":
    unittest.main()
