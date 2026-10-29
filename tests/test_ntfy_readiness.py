from __future__ import annotations

import http.server
import os
import re
import selectors
import shutil
import subprocess
import threading
import time
import unittest

from repo_test_utils import text


class NtfyReadinessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.requests: list[tuple[str, str]] = []
        self.release = threading.Event()
        self.addCleanup(self.release.set)

    def service(self) -> str:
        return (
            text("modules/nas/config/systemd-services.nix")
            .split("    ntfy-sh = lib.mkIf cfg.observability.ntfy.enable {", 1)[1]
            .split("\n    };", 1)[0]
        )

    def probe(self, port: int) -> str:
        match = re.search(r"postStart = (?:lib\.mkAfter )?''(.*?)'';", self.service(), re.S)
        script = match[1] if match else ""
        for package, command in (("coreutils", "timeout"), ("curl", "curl")):
            executable = shutil.which(command)
            self.assertIsNotNone(executable, f"{command} is required for the readiness behavior tests")
            script = script.replace(f"${{pkgs.{package}}}/bin/{command}", str(executable))
        script = script.replace("${toString cfg.observability.ntfy.port}", str(port))
        self.assertNotIn("${", script)
        return "set -euo pipefail\n" + script

    def server(self, *, status: int = 200, activate: bool = True, hang: bool = False):
        requests, release = self.requests, self.release

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                requests.append((self.command, self.path))
                if hang:
                    release.wait(25)
                    return
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"healthy":true}\n')

            def log_message(self, *_args) -> None:
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler, bind_and_activate=False)
        server.server_bind()
        self.addCleanup(server.server_close)
        if activate:
            self.activate(server)
        return server

    def activate(self, server) -> None:
        server.server_activate()
        worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        worker.start()
        self.addCleanup(worker.join, 5)
        self.addCleanup(server.shutdown)

    def run_probe(self, port: int):
        start = time.monotonic()
        result = subprocess.run(["bash", "-c", self.probe(port)], capture_output=True, timeout=25)
        return result, time.monotonic() - start

    def test_readiness_is_owned_by_ntfy_without_changing_notification_failure_handling(self) -> None:
        service = self.service()
        self.assertIn("postStart = ", service)
        self.assertIn('partOf = [ "nas-protected-services.target" ];', service)
        self.assertIn('ConditionPathExists = "${observabilitySecretDir}/ntfy-environment";', service)
        self.assertIn("onFailure = failureAlert;", service)
        self.assertNotIn("TimeoutStartSec", service)
        notifier = (
            text("modules/nas/config/systemd-services.nix")
            .split('    "nas-health-alert@" =', 1)[1]
            .split("\n    };", 1)[0]
        )
        self.assertIn('after = [ "ntfy-sh.service" ];', notifier)
        self.assertIn('wants = [ "ntfy-sh.service" ];', notifier)
        for block in (service, notifier):
            self.assertNotIn("reset-failed", block)
            self.assertNotIn("SuccessExitStatus", block)
            self.assertNotIn("|| true", block)
        alert = (
            text("modules/nas/internal/maintenance-tools.nix")
            .split("  nasAlert =", 1)[1]
            .split("  nasPreflight =", 1)[0]
        )
        self.assertIn("max-time = 15", alert)
        self.assertNotIn("retry", alert)

    def test_delayed_listener_is_retried_before_readiness_succeeds(self) -> None:
        server = self.server(activate=False)
        process = subprocess.Popen(
            ["bash", "-c", self.probe(server.server_port)], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        try:
            assert process.stderr is not None
            with selectors.DefaultSelector() as selector:
                selector.register(process.stderr, selectors.EVENT_READ)
                self.assertTrue(selector.select(5), "readiness never attempted a connection")
                first_error = os.read(process.stderr.fileno(), 4096)
            self.assertIn(b"curl: (7)", first_error, "readiness returned before ntfy was listening")
            self.assertIsNone(process.poll(), "readiness did not retry the refused connection")
            self.activate(server)
            stdout, stderr = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 0, first_error + stderr)
            self.assertEqual(stdout, b"")
            self.assertEqual(self.requests, [("GET", "/v1/health")])
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)

    def test_ready_server_is_probed_without_publishing_a_notification(self) -> None:
        server = self.server()
        result, _elapsed = self.run_probe(server.server_port)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(self.requests, [("GET", "/v1/health")])

    def test_client_errors_remain_fatal(self) -> None:
        for status in (400, 401, 403, 404):
            with self.subTest(status=status):
                server = self.server(status=status)
                result, _elapsed = self.run_probe(server.server_port)
                self.assertEqual(result.returncode, 22, result.stderr)

    def test_persistent_service_error_is_bounded_and_fatal(self) -> None:
        server = self.server(status=503)
        result, elapsed = self.run_probe(server.server_port)
        self.assertNotEqual(result.returncode, 0)
        self.assertLess(elapsed, 20)
        self.assertTrue(self.requests)
        self.assertTrue(all(request == ("GET", "/v1/health") for request in self.requests))

    def test_unavailable_listener_is_bounded_and_fatal(self) -> None:
        server = self.server(activate=False)
        result, elapsed = self.run_probe(server.server_port)
        self.assertNotEqual(result.returncode, 0)
        self.assertLess(elapsed, 20)
        self.assertIn(b"curl: (7)", result.stderr)
        self.assertEqual(self.requests, [])

    def test_unresponsive_listener_is_bounded_and_fatal(self) -> None:
        server = self.server(hang=True)
        result, elapsed = self.run_probe(server.server_port)
        self.assertNotEqual(result.returncode, 0)
        self.assertLess(elapsed, 20)
        self.assertTrue(self.requests)


if __name__ == "__main__":
    unittest.main()
