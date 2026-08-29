from __future__ import annotations

import email.message
import io
import pathlib
import sys
import unittest
import urllib.error
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_identity_sync as sync  # noqa: E402


class IdentityHttpSecurityTests(unittest.TestCase):
    def test_authentik_absolute_url_must_keep_configured_origin(self) -> None:
        with mock.patch.object(sync, "AUTHENTIK_URL", "http://127.0.0.1:9000/identity"):
            self.assertEqual(
                sync.authentik_api_url("http://127.0.0.1:9000/identity/api/v3/core/users/?page=2"),
                "http://127.0.0.1:9000/identity/api/v3/core/users/?page=2",
            )
            for url in (
                "http://127.0.0.1:9001/identity/api/v3/core/users/",
                "https://127.0.0.1:9000/identity/api/v3/core/users/",
                "http://example.test/identity/api/v3/core/users/",
            ):
                with self.subTest(url=url):
                    with self.assertRaisesRegex(sync.SyncError, "configured API origin"):
                        sync.authentik_api_url(url)

    def test_authentik_absolute_url_cannot_escape_api_prefix(self) -> None:
        with mock.patch.object(sync, "AUTHENTIK_URL", "http://127.0.0.1:9000/identity"):
            for url in (
                "http://127.0.0.1:9000/identity/if/user/",
                "http://127.0.0.1:9000/identity/api/v3/../if/user/",
                "http://127.0.0.1:9000/identity/api/v3/%2e%2e/if/user/",
                "http://user:pass@127.0.0.1:9000/identity/api/v3/core/users/",
                "http://127.0.0.1:9000/identity/api/v3/core/users/#secret",
            ):
                with self.subTest(url=url):
                    with self.assertRaises(sync.SyncError):
                        sync.authentik_api_url(url)

    def test_authentik_request_disables_redirects_and_keeps_bearer_local(self) -> None:
        with (
            mock.patch.object(sync, "AUTHENTIK_URL", "http://127.0.0.1:9000/identity"),
            mock.patch.object(sync, "http_json", return_value={"ok": True}) as http_json,
        ):
            self.assertEqual(sync.authentik_request("secret-token", "core/users/"), {"ok": True})
        http_json.assert_called_once_with(
            "http://127.0.0.1:9000/identity/api/v3/core/users/",
            method="GET",
            body=None,
            headers={"Authorization": "Bearer secret-token"},
            follow_redirects=False,
        )

    def test_no_redirect_opener_surfaces_redirect_as_failure(self) -> None:
        url = "http://127.0.0.1:9000/identity/api/v3/core/users/"
        headers = email.message.Message()
        headers["Location"] = "http://127.0.0.1:9999/steal"
        redirect = urllib.error.HTTPError(url, 302, "Found", headers, io.BytesIO(b""))
        with mock.patch.object(sync._NO_REDIRECT_OPENER, "open", side_effect=redirect):
            with self.assertRaisesRegex(sync.SyncError, "HTTP 302"):
                sync.http_json(
                    url,
                    headers={"Authorization": "Bearer secret-token"},
                    follow_redirects=False,
                )


if __name__ == "__main__":
    unittest.main()
