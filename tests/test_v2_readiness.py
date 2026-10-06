from __future__ import annotations

import pathlib
import socket
import shutil
import sys
import tempfile
import threading
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_readiness as readiness  # noqa: E402


class V2ReadinessTests(unittest.TestCase):
    def test_http_readiness_uses_status_without_waiting_for_body(self):
        release = threading.Event()
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(5)

            def serve():
                connection, _address = listener.accept()
                with connection:
                    connection.recv(4096)
                    connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")
                    release.wait(5)

            worker = threading.Thread(target=serve)
            worker.start()
            try:
                port = listener.getsockname()[1]
                self.assertTrue(readiness._probe_http({"url": f"http://127.0.0.1:{port}/health"}))
            finally:
                release.set()
                worker.join(6)
            self.assertFalse(worker.is_alive())

    def test_http_probe_closes_connection_for_accepted_and_rejected_status(self):
        for status, expected in ((200, True), (503, False)):
            with self.subTest(status=status), mock.patch.object(readiness.http.client, "HTTPConnection") as factory:
                connection = factory.return_value
                connection.getresponse.return_value.status = status
                self.assertEqual(readiness._probe_http({"url": "http://127.0.0.1/health?q=1"}), expected)
                connection.request.assert_called_once_with("GET", "/health?q=1")
                connection.getresponse.return_value.read.assert_not_called()
                connection.close.assert_called_once_with()

    def test_existing_path_is_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "ready"
            path.write_text("ok", encoding="utf-8")
            self.assertTrue(readiness.probe_ready({"type": "path", "path": str(path)}, systemctl="/bin/false"))

    def test_systemd_probe_uses_fixed_argv(self):
        true_bin = shutil.which("true")
        false_bin = shutil.which("false")
        self.assertIsNotNone(true_bin)
        self.assertIsNotNone(false_bin)
        assert true_bin is not None
        assert false_bin is not None
        self.assertTrue(
            readiness.probe_ready(
                {"type": "systemd", "unit": "demo.service"},
                systemctl=true_bin,
            )
        )
        self.assertFalse(
            readiness.probe_ready(
                {"type": "systemd", "unit": "demo.service"},
                systemctl=false_bin,
            )
        )

    def test_wait_ready_completes_without_resident_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "ready"
            path.touch()
            readiness.wait_ready(
                {
                    "timeoutSeconds": 1,
                    "intervalMilliseconds": 50,
                    "probes": [{"type": "path", "path": str(path)}],
                }
            )

    def test_unsafe_readiness_path_is_rejected(self):
        with self.assertRaisesRegex(readiness.ReadinessError, "absolute"):
            readiness.probe_ready({"type": "path", "path": "../ready"}, systemctl="/bin/false")

    def test_retry_sleep_is_bounded_by_remaining_timeout(self):
        now = 0.0
        sleeps = []

        def sleep(seconds):
            nonlocal now
            sleeps.append(seconds)
            now += seconds

        with (
            mock.patch.object(readiness.time, "monotonic", side_effect=lambda: now),
            mock.patch.object(readiness.time, "sleep", side_effect=sleep),
            mock.patch.object(readiness, "probe_ready", return_value=False) as probe,
            self.assertRaises(readiness.ReadinessError),
        ):
            readiness.wait_ready(
                {"timeoutSeconds": 1, "intervalMilliseconds": 60000, "probes": [{"type": "path", "path": "/ready"}]}
            )
        self.assertEqual(sleeps, [1.0])
        self.assertEqual(probe.call_count, 1)

    def test_probe_success_after_deadline_does_not_pass_gate(self):
        now = 0.0

        def slow_probe(*args, **kwargs):
            nonlocal now
            now = 2.0
            return True

        with (
            mock.patch.object(readiness.time, "monotonic", side_effect=lambda: now),
            mock.patch.object(readiness, "probe_ready", side_effect=slow_probe),
            self.assertRaises(readiness.ReadinessError),
        ):
            readiness.wait_ready({"timeoutSeconds": 1, "probes": [{"type": "path", "path": "/ready"}]})

    def test_no_further_probes_start_after_deadline(self):
        now = 0.0

        def slow_probe(*args, **kwargs):
            nonlocal now
            now = 2.0
            return True

        with (
            mock.patch.object(readiness.time, "monotonic", side_effect=lambda: now),
            mock.patch.object(readiness, "probe_ready", side_effect=slow_probe) as probe,
            self.assertRaises(readiness.ReadinessError),
        ):
            readiness.wait_ready(
                {"timeoutSeconds": 1, "probes": [{"type": "path", "path": "/one"}, {"type": "path", "path": "/two"}]}
            )
        self.assertEqual(probe.call_count, 1)

    def test_http_probe_rejects_out_of_range_port(self):
        for url in ("http://127.0.0.1:99999/", "http://127.0.0.1:0/"):
            with self.subTest(url=url), self.assertRaises(readiness.ReadinessError) as ctx:
                readiness.probe_ready({"type": "http", "url": url}, systemctl="/bin/false")
            self.assertIn("port", str(ctx.exception).lower())
        with self.assertRaises(readiness.ReadinessError):
            readiness._probe_http({"url": "http://127.0.0.1:99999/"})

    def test_http_probe_rejects_malformed_url(self):
        for url in ("http:///nohost", "not-a-url", "http://127.0.0.1:99999/path?q=1"):
            with self.subTest(url=url), self.assertRaises(readiness.ReadinessError):
                readiness.probe_ready({"type": "http", "url": url}, systemctl="/bin/false")


if __name__ == "__main__":
    unittest.main()
