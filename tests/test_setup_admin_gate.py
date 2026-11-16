from __future__ import annotations

import http.client
import json
import pathlib
import socket
import subprocess
import tempfile
import time
import unittest

from test_caddy_locked_notice import BOOTSTRAP_NIX, ROOT, nix_string
from test_v2_caddy_validate import _caddy_binary


class SetupAdministratorGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.caddy = _caddy_binary()
        if cls.caddy is None:
            raise unittest.SkipTest("caddy binary not available")

    def setUp(self) -> None:
        assert self.caddy is not None
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = pathlib.Path(temporary.name)
        ports = []
        for _ in range(3):
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                ports.append(listener.getsockname()[1])
        self.port, auth_port, backend_port = ports
        static = root / "share/nas-portal-wizard"
        static.mkdir(parents=True)
        (static / "index.html").write_text("setup wizard")
        helpers = (ROOT / "modules/nas/internal/caddy-helpers.nix").read_text()
        forward_auth = nix_string(helpers, "caddyForwardAuth =")
        identity_headers = json.loads((ROOT / "services/nas_policy/identity-headers.json").read_text())
        forward_auth = forward_auth.replace(
            '${args.lib.concatMapStringsSep "\\n" (header: "request_header -${header}") identityHeaders}',
            "\n".join(f"request_header -{header}" for header in identity_headers),
        )
        forward_auth = forward_auth.replace("${toString authentikOutpostPort}", str(auth_port))
        forward_auth = forward_auth.replace("${authentikOutpostPath}", "/outpost.goauthentik.io/auth/caddy")
        source = BOOTSTRAP_NIX.read_text()
        bootstrap = nix_string(source, 'writeShellScript "bootstrap-caddyfile-gen"')
        bootstrap = bootstrap.split("cat <<'EOCF'\n", 1)[1].rsplit("\nEOCF", 1)[0]
        substitutions = {
            "${caddyGlobalOptions}": "{\n admin off\n auto_https off\n}",
            "https://${lanHost}": f"http://127.0.0.1:{self.port}",
            "${caddySiteHeaders}": "",
            "${caddyForwardAuth}": forward_auth,
            "${cfg.identity.authentikPath}": "/identity/",
            "${authentikPathNoSlash}": "/identity",
            "${toString authentikPort}": str(auth_port),
            "${toString authentikOutpostPort}": str(auth_port),
            "${firstRunWizardStatic}": str(root),
            "unix//run/nas-setup-api/setup.sock": f"127.0.0.1:{backend_port}",
            "unix//run/nas-cockpit-sso/ws.sock": f"127.0.0.1:{backend_port}",
        }
        for key, value in substitutions.items():
            bootstrap = bootstrap.replace(key, value)
        self.assertNotIn("${", bootstrap)
        auth = (
            f"http://127.0.0.1:{auth_port} {{\n route {{\n"
            " @anonymous header X-Test-Anonymous yes\n respond @anonymous 401\n"
            " header X-Authentik-Username test-user\n"
            ' header X-Authentik-Groups "{http.request.header.X-Test-Groups}"\n'
            " respond 200\n }\n}\n"
        )
        backend = f'http://127.0.0.1:{backend_port} {{\n respond "setup-backend" 200\n}}\n'
        config = root / "Caddyfile"
        config.write_text(bootstrap + "\n" + auth + backend)
        log = open(root / "caddy.log", "w+")
        self.addCleanup(log.close)
        self.process = subprocess.Popen(
            [self.caddy, "run", "--config", str(config), "--adapter", "caddyfile"],
            stdout=log,
            stderr=log,
        )
        self.addCleanup(self.stop_caddy)
        for _ in range(100):
            if self.process.poll() is not None:
                log.seek(0)
                self.fail(log.read())
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.1):
                    return
            except OSError:
                time.sleep(0.02)
        self.fail("Caddy did not start")

    def stop_caddy(self) -> None:
        self.process.terminate()
        self.process.wait(timeout=5)

    def request(self, path: str, *, groups: str = "nas_users", method: str = "GET", **headers: str) -> int:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        try:
            connection.request(method, path, headers={"X-Test-Groups": groups, **headers})
            response = connection.getresponse()
            response.read()
            return response.status
        finally:
            connection.close()

    def test_authenticated_nonadministrators_cannot_reauthorize_or_submit_setup(self) -> None:
        for groups in ("nas_users", "application.cockpit.admin", "nas_admin-extra", "prefix-nas_admin"):
            for path, method in (
                ("/setup/", "GET"),
                ("/setup/api/first-start", "GET"),
                ("/setup/api/first-start/plan", "POST"),
                ("/setup/api/first-run", "POST"),
                ("/setup/api/first-start/resume", "POST"),
            ):
                with self.subTest(groups=groups, path=path):
                    self.assertEqual(
                        self.request(
                            path,
                            groups=groups,
                            method=method,
                            **{"Remote-Groups": "nas_admin", "X-Authentik-Groups": "nas_admin"},
                        ),
                        403,
                    )

    def test_explicit_administrators_keep_setup_access(self) -> None:
        for groups in ("nas_admin", "nas_users|nas_admin", "nas_users, nas_admin"):
            with self.subTest(groups=groups):
                self.assertEqual(self.request("/setup/", groups=groups), 200)
                self.assertEqual(self.request("/setup/api/first-start/resume", groups=groups, method="POST"), 200)

    def test_unauthenticated_setup_requests_remain_rejected(self) -> None:
        self.assertEqual(
            self.request("/setup/api/first-start/resume", method="POST", **{"X-Test-Anonymous": "yes"}), 401
        )

    def test_job_polling_and_reboot_still_reach_the_capability_verifier(self) -> None:
        for path, method in (("/setup/api/first-start/job", "GET"), ("/setup/api/reboot", "POST")):
            with self.subTest(path=path):
                self.assertEqual(self.request(path, method=method, **{"X-Test-Anonymous": "yes"}), 200)


if __name__ == "__main__":
    unittest.main()
