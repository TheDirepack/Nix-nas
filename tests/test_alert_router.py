from __future__ import annotations

import http.client
import pathlib
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock
import urllib.request
from http.server import ThreadingHTTPServer

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_alert_router as router


class AlertRouterTests(unittest.TestCase):
    def test_normalize_and_resolve(self) -> None:
        now = datetime.now(timezone.utc)
        alert = router.normalize_alert(
            {
                "labels": {"alertname": "DiskHot", "instance": "nas", "severity": "critical"},
                "annotations": {"summary": "Disk is hot", "description": "Temperature exceeded"},
                "endsAt": (now - timedelta(seconds=1)).isoformat(),
            },
            now=now,
        )
        self.assertEqual(alert.status, "resolved")
        self.assertEqual(alert.severity, "critical")
        self.assertIn("Disk is hot", alert.title)

    def test_header_derived_alert_text_strips_control_characters(self) -> None:
        alert = router.normalize_alert(
            {
                "labels": {"alertname": "Disk\r\nX-Injected: yes", "severity": "warning", "instance": "nas\x00node"},
                "annotations": {"summary": "Summary\nInjected: yes", "description": "body\ntext"},
            }
        )
        self.assertNotRegex(alert.title, r"[\x00-\x1f\x7f]")
        self.assertNotRegex(alert.labels["alertname"], r"[\x00-\x1f\x7f]")
        self.assertNotRegex(alert.labels["instance"], r"[\x00-\x1f\x7f]")

    def test_ntfy_topic_is_path_encoded_and_header_text_is_safe(self) -> None:
        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as tmp:
            topic = pathlib.Path(tmp) / "topic"
            password = pathlib.Path(tmp) / "password"
            topic.write_text("ops/admin?token=secret\n", encoding="utf-8")
            password.write_text("pw\n", encoding="utf-8")
            alert = router.normalize_alert(
                {
                    "labels": {"alertname": "Disk\r\nInjected: yes", "severity": "warning"},
                    "annotations": {"summary": "Summary\nInjected: yes", "description": "body"},
                }
            )
            captured = []

            def fake_open(request, timeout):
                captured.append((request, timeout))
                return Response()

            with (
                mock.patch.object(router, "NTFY_ENABLED", True),
                mock.patch.object(router, "NTFY_BASE_URL", "https://ntfy.invalid"),
                mock.patch.object(router, "NTFY_TOPIC_FILE", topic),
                mock.patch.object(router, "NTFY_PASSWORD_FILE", password),
                mock.patch.object(urllib.request, "urlopen", side_effect=fake_open),
            ):
                router.publish_ntfy(alert)
            request, timeout = captured[0]
            self.assertEqual(request.full_url, "https://ntfy.invalid/ops%2Fadmin%3Ftoken%3Dsecret")
            self.assertNotRegex(request.headers["Title"], r"[\x00-\x1f\x7f]")
            self.assertEqual(timeout, router.REQUEST_TIMEOUT_SECONDS)

    def test_critical_inhibits_same_warning(self) -> None:
        labels = {"alertname": "Storage", "instance": "nas"}
        warning = router.normalize_alert({"labels": {**labels, "severity": "warning"}})
        critical = router.normalize_alert({"labels": {**labels, "severity": "critical"}})
        kept = router.inhibit_derivative_warnings([warning, critical])
        self.assertEqual(kept, [critical])

    def test_dedup_and_status_change(self) -> None:
        alert = router.normalize_alert({"labels": {"alertname": "Down", "severity": "warning"}})
        state = {alert.fingerprint: {"status": "firing", "lastSent": 100.0}}
        with mock.patch.object(router, "REPEAT_SECONDS", 1000):
            self.assertFalse(router.should_send(alert, state, now=200.0))
        resolved = router.RoutedAlert(
            alert.fingerprint, "resolved", alert.severity, alert.title, alert.message, alert.labels
        )
        self.assertTrue(router.should_send(resolved, state, now=200.0))

    def test_process_persists_queryable_successful_delivery(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_path = pathlib.Path(tmp) / "state.json"
            raw = [{"labels": {"alertname": "Down", "severity": "warning", "run": "123"}}]
            with (
                mock.patch.object(router, "STATE_PATH", state_path),
                mock.patch.object(router, "publish_ntfy") as publish,
                mock.patch.object(router, "log_event"),
            ):
                result = router.process_alerts(raw, now=123.0, operation_id="op-1")
            self.assertEqual(result["sent"], 1)
            self.assertEqual(publish.call_count, 1)
            alerts = router.public_alerts(router.load_state(state_path))
            self.assertEqual(alerts[0]["labels"]["run"], "123")
            self.assertEqual(alerts[0]["status"]["state"], "firing")

    def test_http_protocol_rejects_ambiguous_or_oversized_request_framing(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), router.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        host = str(server.server_address[0])
        port = int(server.server_address[1])
        try:
            cases = [
                ({"Transfer-Encoding": "chunked"}, 400),
                ({}, 411),
                ({"Content-Length": "not-a-number"}, 400),
                ({"Content-Length": "-1"}, 400),
                ({"Content-Length": str(router.MAX_BODY_BYTES + 1)}, 413),
            ]
            for headers, expected in cases:
                with self.subTest(headers=headers):
                    connection = http.client.HTTPConnection(host, port, timeout=2)
                    connection.putrequest("POST", "/api/v2/alerts")
                    for key, value in headers.items():
                        connection.putheader(key, value)
                    connection.endheaders()
                    response = connection.getresponse()
                    response.read()
                    self.assertEqual(response.status, expected)
                    connection.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_public_alerts_uses_rfc3339_updated_at(self) -> None:
        state = {
            "abc": {
                "status": "firing",
                "severity": "warning",
                "lastSent": 123.0,
                "title": "Down",
                "labels": {"alertname": "Down"},
            }
        }
        alert = router.public_alerts(state)[0]
        self.assertEqual(alert["updatedAt"], "1970-01-01T00:02:03Z")

    def test_atomic_state_write_fsyncs_file_and_parent_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "state.json"
            real_fsync = router.os.fsync
            fsync_calls: list[int] = []

            def tracking_fsync(fd: int) -> None:
                fsync_calls.append(fd)
                real_fsync(fd)

            with mock.patch.object(router.os, "fsync", side_effect=tracking_fsync):
                router.atomic_write_state({"x": {"status": "firing"}}, path)
            self.assertGreaterEqual(len(fsync_calls), 2)
            self.assertTrue(path.exists())

    def test_corrupt_state_is_quarantined_and_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "state.json"
            path.write_text("{broken", encoding="utf-8")
            with mock.patch.object(router, "log_event") as log_event:
                self.assertEqual(router.load_state(path), {})
            self.assertFalse(path.exists())
            quarantined = list(path.parent.glob("state.json.corrupt-*"))
            self.assertEqual(len(quarantined), 1)
            log_event.assert_called_once()
            self.assertEqual(log_event.call_args.kwargs["result"], "degraded")
            self.assertTrue(log_event.call_args.kwargs["recovery_required"])

    def test_partial_success_is_persisted_before_delivery_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_path = pathlib.Path(tmp) / "state.json"
            raw = [
                {"labels": {"alertname": "First", "severity": "warning"}},
                {"labels": {"alertname": "Second", "severity": "warning"}},
            ]
            delivery = [None, router.AlertDeliveryError("unavailable")]

            def publish(_alert: router.RoutedAlert) -> None:
                outcome = delivery.pop(0)
                if outcome is not None:
                    raise outcome

            with (
                mock.patch.object(router, "STATE_PATH", state_path),
                mock.patch.object(router, "publish_ntfy", side_effect=publish),
                mock.patch.object(router, "log_event"),
            ):
                with self.assertRaises(router.AlertDeliveryError):
                    router.process_alerts(raw, now=123.0, operation_id="op-2")
            state = router.load_state(state_path)
            first = router.normalize_alert(raw[0])
            second = router.normalize_alert(raw[1])
            self.assertIn(first.fingerprint, state)
            self.assertNotIn(second.fingerprint, state)
            self.assertEqual(state[first.fingerprint]["labels"]["alertname"], "First")

    def test_resolved_warning_is_not_inhibited_by_colocated_firing_critical(self) -> None:
        labels = {"alertname": "Storage", "instance": "nas"}
        resolved_warning = router.normalize_alert({"labels": {**labels, "severity": "warning"}, "status": "resolved"})
        firing_critical = router.normalize_alert({"labels": {**labels, "severity": "critical"}, "status": "firing"})
        kept = router.inhibit_derivative_warnings([resolved_warning, firing_critical])
        self.assertEqual(kept, [resolved_warning, firing_critical])


if __name__ == "__main__":
    unittest.main()
