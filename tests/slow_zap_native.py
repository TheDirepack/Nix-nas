from __future__ import annotations

import http.server
import json
import os
import pathlib
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.parse
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
NATIVE = os.environ.get("NAS_ZAP_NATIVE_TEST") == "1"


@unittest.skipUnless(NATIVE, "set NAS_ZAP_NATIVE_TEST=1 to run the locked scanner controls")
class NativeZapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.image = subprocess.check_output(
            [
                sys.executable,
                str(ROOT / "scripts/lib/zap-addons.py"),
                "image",
                "--runtime",
                "docker",
                "--image",
                os.environ["NAS_ZAP_IMAGE"],
            ],
            text=True,
            timeout=910,
        ).strip()

    def test_cookie_transport_with_real_network_sender(self) -> None:
        driver = """
import os, pathlib, subprocess, tempfile, zipfile
with tempfile.TemporaryDirectory() as temporary:
    root = pathlib.Path(temporary)
    plugins = sorted(pathlib.Path('/opt/nas-zap/plugin').glob('*.zap'))
    classpath = ['/zap/zap-2.17.0.jar', *map(str, sorted(pathlib.Path('/zap/lib').glob('*.jar'))), *map(str, plugins)]
    for index, path in enumerate(plugins):
        with zipfile.ZipFile(path) as archive:
            for entry in archive.infolist():
                if entry.filename.endswith('.jar'):
                    target = root / (str(index) + '-' + pathlib.PurePosixPath(entry.filename).name)
                    target.write_bytes(archive.read(entry))
                    classpath.append(str(target))
    cp = os.pathsep.join(classpath)
    subprocess.run(['javac', '--release', '17', '-proc:none', '-implicit:none', '-cp', cp, '-d', str(root), '/fixture/CookieTransportTest.java'], check=True)
    subprocess.run(['java', '-cp', str(root) + os.pathsep + cp, 'org.zaproxy.addon.network.CookieTransportTest'], check=True)
"""
        subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "--hostname",
                "localhost",
                "--user",
                f"{os.getuid()}:{os.getgid()}",
                "-e",
                "HOME=/tmp",
                "-e",
                "JAVA_TOOL_OPTIONS=-Duser.home=/tmp",
                "-v",
                f"{ROOT / 'tests/fixtures/zap'}:/fixture:ro",
                "--entrypoint",
                "python3",
                self.image,
                "-c",
                driver,
            ],
            check=True,
            timeout=180,
        )

    def test_hardened_vulnerable_and_rejected_credential_controls(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            output = pathlib.Path(os.environ.get("NAS_ZAP_NATIVE_OUT", str(directory / "reports")))
            output.mkdir(parents=True, exist_ok=True)
            session = uuid.uuid4().hex
            results = []

            class Handler(http.server.BaseHTTPRequestHandler):
                hardened = True
                authenticated = False
                broken_session = False
                identity_status = 200
                successful_logins = 0
                private_requests = 0
                events: list[dict] = []

                def respond(self, status, body=b"", headers=(), content_type="text/html; charset=utf-8"):
                    valid_cookie = f"sessionid={session}" in self.headers.get("Cookie", "")
                    self.events.append(
                        {
                            "method": self.command,
                            "path": self.path,
                            "validCookie": valid_cookie,
                            "cookiePresent": bool(self.headers.get("Cookie")),
                            "status": status,
                        }
                    )
                    self.send_response_only(status)
                    self.send_header("Content-Type", content_type)
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Cache-Control", "no-store")
                    if self.hardened:
                        for name, value in {
                            "Content-Security-Policy": "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
                            "X-Frame-Options": "DENY",
                            "X-Content-Type-Options": "nosniff",
                            "Cross-Origin-Embedder-Policy": "require-corp",
                            "Cross-Origin-Opener-Policy": "same-origin",
                            "Cross-Origin-Resource-Policy": "same-origin",
                            "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
                            "Strict-Transport-Security": "max-age=31536000",
                        }.items():
                            self.send_header(name, value)
                    else:
                        self.send_header(
                            "Content-Security-Policy",
                            "script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src https: data:",
                        )
                    for name, value in headers:
                        self.send_header(name, value)
                    self.end_headers()
                    self.wfile.write(body)

                def do_GET(self):
                    valid_cookie = f"sessionid={session}" in self.headers.get("Cookie", "")
                    if self.path.startswith("/console/"):
                        if not self.authenticated or valid_cookie or self.broken_session:
                            type(self).private_requests += int(valid_cookie)
                            self.respond(
                                200,
                                b'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Private fixture</title></head><body><a href="/console/private-marker">Owned private marker</a><script src="/session.js"></script></body></html>',
                            )
                        else:
                            self.respond(302, headers=[("Location", "/identity/login/")])
                    elif self.path.startswith("/identity/login/"):
                        self.respond(
                            200,
                            b'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Sign in</title></head><body><form action="/identity/login/" method="post"><input type="hidden" name="csrfmiddlewaretoken" value="owned-fixture-token"><label for="username">Username</label><input id="username" name="username" autocomplete="username"><label for="password">Password</label><input id="password" type="password" name="password" autocomplete="current-password"><button type="submit">Sign in</button></form></body></html>',
                        )
                    elif self.path == "/session.js":
                        self.respond(
                            200,
                            b"fetch('/api/me').then(r => r.json()).then(u => { if (u.username) document.body.dataset.user = u.username; else location.replace('/identity/login/'); });",
                            content_type="text/javascript",
                        )
                    elif self.path in ("/api/me", "/identity/api/v3/core/users/me/"):
                        self.respond(
                            (self.identity_status if self.path == "/identity/api/v3/core/users/me/" else 200)
                            if valid_cookie
                            else 401,
                            json.dumps(
                                {"username": "fixture-user"} if valid_cookie else {"detail": "Not authenticated"}
                            ).encode(),
                            content_type="application/json",
                        )
                    elif self.path in ("/", "/robots.txt", "/sitemap.xml"):
                        self.respond(
                            200,
                            b'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Scan fixture</title></head><body>Owned disposable scanner fixture</body></html>',
                        )
                    else:
                        self.respond(404, b"Not found", content_type="text/plain")

                def do_POST(self):
                    fields = urllib.parse.parse_qs(
                        self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode(errors="replace")
                    )
                    if self.path == "/identity/login/" and fields == {
                        "username": ["fixture-user"],
                        "password": ["owned-fixture-password"],
                        "csrfmiddlewaretoken": ["owned-fixture-token"],
                    }:
                        type(self).successful_logins += 1
                        self.respond(
                            302,
                            headers=[
                                ("Location", "/console/"),
                                ("Set-Cookie", f"sessionid={session}; Path=/; HttpOnly; Secure; SameSite=Lax"),
                            ],
                        )
                    else:
                        self.respond(403, b"Invalid submission", content_type="text/plain")

                def log_message(self, *_args):
                    pass

            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-days",
                    "1",
                    "-subj",
                    "/CN=localhost",
                    "-keyout",
                    str(directory / "key.pem"),
                    "-out",
                    str(directory / "cert.pem"),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(directory / "cert.pem", directory / "key.pem")
            server.socket = tls.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                for name, script, mode, hardened, authenticated, broken, path in (
                    ("vulnerable-baseline", "zap-scan.sh", "baseline", False, False, False, "/"),
                    ("hardened-baseline", "zap-scan.sh", "baseline", True, False, False, "/"),
                    ("hardened-full", "zap-scan.sh", "full", True, False, False, "/"),
                    (
                        "vulnerable-login-boundary",
                        "zap-automation-scan.sh",
                        "unauthenticated",
                        False,
                        True,
                        False,
                        "/console/",
                    ),
                    ("hardened-automation", "zap-automation-scan.sh", "unauthenticated", True, False, False, "/"),
                    (
                        "hardened-authenticated",
                        "zap-automation-scan.sh",
                        "authenticated",
                        True,
                        True,
                        False,
                        "/console/",
                    ),
                    ("vulnerable-session", "zap-automation-scan.sh", "authenticated", True, True, True, "/console/"),
                    ("errored-identity", "zap-automation-scan.sh", "authenticated", True, True, False, "/console/"),
                    (
                        "rejected-authentication",
                        "zap-automation-scan.sh",
                        "authenticated",
                        True,
                        True,
                        False,
                        "/console/",
                    ),
                ):
                    with self.subTest(scan=name):
                        Handler.hardened, Handler.authenticated, Handler.broken_session = (
                            hardened,
                            authenticated,
                            broken,
                        )
                        Handler.successful_logins, Handler.private_requests, Handler.events = 0, 0, []
                        Handler.identity_status = 500 if name == "errored-identity" else 200
                        out = output / name
                        out.mkdir(exist_ok=True)
                        environment = {
                            **os.environ,
                            "NAS_CONTAINER_RUNTIME": "docker",
                            "NAS_ZAP_OUT_DIR": str(out),
                            "NAS_ZAP_MAX_MINUTES": "1",
                            "NAS_ZAP_AUTOMATION_MINUTES": "1",
                            "NAS_ZAP_CONFIRM_ACTIVE": "1",
                            "NAS_ZAP_AUTH_USER": "fixture-user",
                            "NAS_ZAP_AUTH_PASSWORD": "incorrect-password"
                            if name == "rejected-authentication"
                            else "owned-fixture-password",
                        }
                        with (out / "scan.log").open("w") as log:
                            result = subprocess.run(
                                [
                                    "bash",
                                    str(ROOT / "scripts" / script),
                                    mode,
                                    f"https://127.0.0.1:{server.server_port}{path}",
                                ],
                                env=environment,
                                stdout=log,
                                stderr=subprocess.STDOUT,
                                timeout=1800,
                            )
                        prefix = f"zap-scan-{mode}" if script == "zap-scan.sh" else f"zap-automation-{mode}"
                        report = out / f"{prefix}.json"
                        log = (out / "scan.log").read_text()
                        if name not in ("rejected-authentication", "errored-identity"):
                            self.assertTrue(report.is_file(), log)
                        alerts = {
                            str(alert["pluginid"])
                            for site in (json.loads(report.read_text()).get("site", []) if report.is_file() else [])
                            for alert in site.get("alerts", [])
                        }
                        evidence = out / f"{prefix}.addons.json"
                        inventory = json.loads(evidence.read_text())
                        row = {
                            "scan": name,
                            "status": result.returncode,
                            "alertRules": sorted(alerts),
                            "successfulLogins": Handler.successful_logins,
                            "privateRequests": Handler.private_requests,
                            "reportsProduced": report.is_file(),
                        }
                        results.append(row)
                        (out / "request-events.json").write_text(json.dumps(Handler.events, indent=2) + "\n")
                        (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
                        print(json.dumps(row), flush=True)
                        self.assertEqual(len(inventory["addons"]), 51)
                        self.assertTrue(inventory["runnableVerified"])
                        self.assertIsNotNone(inventory["sourceBuild"])
                        subprocess.run(
                            [
                                sys.executable,
                                str(ROOT / "scripts/lib/zap-addons.py"),
                                "verify-evidence",
                                "--image",
                                os.environ["NAS_ZAP_IMAGE"],
                                "--runtime-image",
                                self.image,
                                "--evidence",
                                str(evidence),
                            ],
                            check=True,
                            timeout=10,
                        )
                        expected = (
                            2
                            if name.startswith("vulnerable") or name in ("rejected-authentication", "errored-identity")
                            else 0
                        )
                        self.assertEqual(result.returncode, expected, log)
                        if not hardened:
                            self.assertTrue({"10055", "90004"} <= alerts, alerts)
                        if mode == "authenticated":
                            self.assertIn("private identity response verified", log)
                            self.assertIn("authenticated session verified", log)
                            if name == "errored-identity":
                                self.assertIn("test of type stats passed: authenticated session verified", log)
                                self.assertIn(
                                    "test type url has failed. Test Name: private identity response verified.", log
                                )
                                self.assertGreater(Handler.successful_logins, 0)
                                self.assertGreater(Handler.private_requests, 0)
                                self.assertTrue(
                                    any(
                                        event["path"] == "/identity/api/v3/core/users/me/"
                                        and event["validCookie"]
                                        and event["status"] == 500
                                        for event in Handler.events
                                    ),
                                    Handler.events,
                                )
                            elif name == "rejected-authentication":
                                self.assertIn("test of type stats failed: authenticated session verified", log)
                                self.assertIn(
                                    "test type url has failed. Test Name: private identity response verified.", log
                                )
                                self.assertEqual((Handler.successful_logins, Handler.private_requests), (0, 0))
                            else:
                                self.assertIn("test of type stats passed: authenticated session verified", log)
                                self.assertIn(
                                    "test type url has passed. Test Name: private identity response verified.", log
                                )
                                self.assertGreater(Handler.successful_logins, 0)
                                self.assertGreater(Handler.private_requests, 0)
                                self.assertEqual("90027" in alerts, broken)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
