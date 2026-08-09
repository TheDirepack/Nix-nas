#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import sys
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_caddy as caddy  # noqa: E402
import nas_v2_lifecycle as lifecycle  # noqa: E402
import nas_v2_schedules as schedules  # noqa: E402


class V2LifecycleTests(unittest.TestCase):
    def _document(self) -> dict:
        return {
            "schemaVersion": 3,
            "services": {
                "prepare": {
                    "name": "Prepare",
                    "enabled": True,
                    "managed": True,
                    "workload": {"kind": "job", "schedules": []},
                    "runtime": {"type": "systemd", "unit": "prepare.service"},
                    "dependencies": [],
                },
                "backend": {
                    "name": "Backend",
                    "enabled": True,
                    "managed": True,
                    "workload": {"kind": "daemon", "activation": "on-demand", "idleSeconds": 60},
                    "runtime": {"type": "systemd", "unit": "backend.service"},
                    "dependencies": [{"service": "prepare", "condition": "completed"}],
                    "readiness": {"timeoutSeconds": 2, "intervalMilliseconds": 100, "probes": [{"type": "systemd", "unit": "backend.service"}]},
                },
                "frontend": {
                    "name": "Frontend",
                    "enabled": True,
                    "managed": True,
                    "workload": {"kind": "daemon", "activation": "persistent"},
                    "runtime": {"type": "systemd", "unit": "frontend.service"},
                    "dependencies": [{"service": "backend", "condition": "ready"}],
                },
                "session": {
                    "name": "Session",
                    "enabled": True,
                    "managed": True,
                    "workload": {"kind": "session", "leaseIdleSeconds": 30},
                    "runtime": {"type": "systemd", "unit": "session.service"},
                    "dependencies": [{"service": "backend", "condition": "ready"}],
                },
            },
        }

    def test_dependency_order_is_runtime_independent(self) -> None:
        self.assertEqual(lifecycle.dependency_order("frontend", self._document()), ["prepare", "backend", "frontend"])

    def test_start_honors_completed_and_ready_edges(self) -> None:
        document = self._document()
        state = {"schemaVersion": 1, "services": {}, "sessions": {}}
        with mock.patch.object(lifecycle, "_read_state", return_value=state), mock.patch.object(
            lifecycle, "_write_state"
        ), mock.patch.object(lifecycle, "_run_job_runtime", return_value={"operation": "job"}) as run_job, mock.patch.object(
            lifecycle, "_start_runtime", side_effect=lambda sid, svc: {"operation": "start", "service": sid}
        ) as start, mock.patch.object(lifecycle, "wait_ready") as ready:
            result = lifecycle.start_service("frontend", document)
        run_job.assert_called_once_with("prepare", document["services"]["prepare"])
        self.assertEqual([call.args[0] for call in start.call_args_list], ["backend", "frontend"])
        ready.assert_called_once_with("backend", document["services"]["backend"])
        self.assertIn("backend", result["started"])
        self.assertIn("backend", state["services"])

    def test_session_lease_refreshes_on_demand_dependency(self) -> None:
        document = self._document()
        state = {"schemaVersion": 1, "services": {}, "sessions": {}}
        with mock.patch.object(lifecycle, "_read_state", return_value=state), mock.patch.object(
            lifecycle, "_write_state"
        ), mock.patch.object(lifecycle, "_run_job_runtime", return_value={}), mock.patch.object(
            lifecycle, "_start_runtime", return_value={"operation": "start"}
        ), mock.patch.object(lifecycle, "wait_ready"):
            lifecycle.session_begin("session", "abc", document)
        self.assertEqual(state["sessions"]["abc"]["service"], "session")
        self.assertIn("backend", state["services"])

    def test_schedule_renderer_supports_calendar_and_interval(self) -> None:
        calendar = schedules.render_timer("prepare", 1, {"calendar": "daily", "persistent": True})
        interval = schedules.render_timer("prepare", 2, {"intervalSeconds": 300, "persistent": False})
        self.assertIn("OnCalendar=daily", calendar)
        self.assertIn("OnUnitActiveSec=300s", interval)
        self.assertIn("Persistent=false", interval)

    def test_caddy_secret_route_uses_generic_gate_without_authentik(self) -> None:
        effective = {
            "services": {
                "demo": {
                    "enabled": True,
                    "routes": {
                        "api": {
                            "target": {"type": "http", "host": "127.0.0.1", "port": 8080},
                            "exposure": {"type": "path", "paths": ["/api-demo/"]},
                            "auth": {"mode": "secret", "credential": "token", "sources": ["bearer"]},
                        }
                    },
                }
            }
        }
        text = caddy.generate_caddyfile(effective)
        self.assertIn("scope=service:demo:api", text)
        self.assertNotIn("outpost.goauthentik.io", text)

    def test_caddy_identity_route_authenticates_then_gates(self) -> None:
        effective = {
            "services": {
                "demo": {
                    "enabled": True,
                    "routes": {
                        "ui": {
                            "target": {"type": "unix-http", "path": "/run/demo.sock"},
                            "exposure": {"type": "hostname", "hostname": "demo.example.test", "path": "/"},
                            "auth": {"mode": "identity", "capability": "application.demo.access"},
                        }
                    },
                }
            }
        }
        text = caddy.generate_caddyfile(effective)
        self.assertIn("outpost.goauthentik.io/auth/caddy", text)
        self.assertIn("scope=service:demo:ui", text)
        self.assertIn("reverse_proxy unix//run/demo.sock", text)


if __name__ == "__main__":
    unittest.main()
