from __future__ import annotations

import pathlib
import sys
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_authentik as authentik  # noqa: E402


class V2AuthentikTests(unittest.TestCase):
    def effective(self) -> dict:
        return {
            "schemaVersion": 3,
            "derived": {
                "authorization": {
                    "demo": {
                        "capabilities": {
                            "access": "application.demo.access",
                            "admin": "application.demo.admin",
                        }
                    }
                }
            },
        }

    def test_desired_capabilities_are_taken_only_from_compiled_metadata(self):
        self.assertEqual(
            authentik.desired_capabilities(self.effective()),
            {
                "application.demo.access": "demo",
                "application.demo.admin": "demo",
            },
        )

    def test_missing_groups_are_created_without_assignment_fields(self):
        calls: list[tuple[str, str, dict | None]] = []

        def request(*, url: str, token: str, method: str = "GET", body: dict | None = None, timeout: float = 15.0):
            del token, timeout
            calls.append((method, url, body))
            if method == "GET":
                return {"results": [], "pagination": {"next": 0}}
            assert body is not None
            return {"pk": "group-pk", "name": body["name"], "is_superuser": False}

        with mock.patch.object(authentik, "_request_json", side_effect=request):
            result = authentik.reconcile_capabilities(
                self.effective(),
                token="token-value",
                authentik_url="http://127.0.0.1:9000/identity",
            )

        posts = [body for method, _url, body in calls if method == "POST"]
        self.assertEqual(len(posts), 2)
        for body in posts:
            assert body is not None
            self.assertEqual(set(body), {"name", "is_superuser", "attributes"})
            self.assertFalse(body["is_superuser"])
            self.assertNotIn("users", body)
            self.assertNotIn("roles", body)
            self.assertNotIn("parent", body)
        self.assertFalse(result["assignmentsChanged"])
        self.assertEqual(result["created"], ["application.demo.access", "application.demo.admin"])

    def test_existing_group_is_left_untouched_including_membership_and_roles(self):
        existing = {
            "pk": "one",
            "name": "application.demo.access",
            "is_superuser": False,
            "users": [123],
            "roles": ["role-1"],
            "attributes": {"operator": "kept"},
        }
        calls: list[tuple[str, dict | None]] = []

        def request(*, url: str, token: str, method: str = "GET", body: dict | None = None, timeout: float = 15.0):
            del url, token, timeout
            calls.append((method, body))
            if method == "GET":
                return {"results": [existing], "pagination": {"next": 0}}
            assert body is not None
            return {"pk": "new", "name": body["name"], "is_superuser": False}

        with mock.patch.object(authentik, "_request_json", side_effect=request):
            result = authentik.reconcile_capabilities(
                self.effective(),
                token="token-value",
                authentik_url="https://auth.example/identity",
            )

        self.assertEqual(result["preexisting"], ["application.demo.access"])
        self.assertEqual(result["created"], ["application.demo.admin"])
        self.assertFalse(any(method in {"PATCH", "PUT", "DELETE"} for method, _body in calls))

    def test_superuser_name_collision_fails_closed(self):
        with mock.patch.object(
            authentik,
            "_list_groups",
            return_value=[{"pk": "one", "name": "application.demo.access", "is_superuser": True}],
        ):
            with self.assertRaisesRegex(authentik.AuthentikProjectionError, "superuser"):
                authentik.reconcile_capabilities(
                    self.effective(),
                    token="token-value",
                    authentik_url="http://127.0.0.1:9000/identity",
                )

    def test_duplicate_group_names_fail_closed(self):
        duplicate = {"name": "application.demo.access", "is_superuser": False}
        with mock.patch.object(authentik, "_list_groups", return_value=[duplicate, dict(duplicate)]):
            with self.assertRaisesRegex(authentik.AuthentikProjectionError, "duplicate group name"):
                authentik.reconcile_capabilities(
                    self.effective(),
                    token="token-value",
                    authentik_url="http://127.0.0.1:9000/identity",
                )

    def test_url_rejects_embedded_credentials_query_and_unsupported_scheme(self):
        for value in (
            "ftp://auth.example/identity",
            "https://user:password@auth.example/identity",
            "https://auth.example/identity?token=bad",
        ):
            with self.subTest(value=value), self.assertRaises(authentik.AuthentikProjectionError):
                authentik._api_root(value)

    def test_canonical_capability_name_is_strict(self):
        value = self.effective()
        value["derived"]["authorization"]["demo"]["capabilities"]["access"] = "../../bad"
        with self.assertRaisesRegex(authentik.AuthentikProjectionError, "unsafe"):
            authentik.desired_capabilities(value)

    def test_bearer_token_not_leaked_on_redirect(self):
        import urllib.error
        import urllib.request

        handler = authentik._NoRedirectHandler()
        req = urllib.request.Request(
            "http://auth.example/api/v3/core/groups/", headers={"Authorization": "Bearer secret-token"}
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            handler.redirect_request(req, None, 302, "Found", {}, "http://evil.example/steal")
        self.assertEqual(ctx.exception.code, 302)
        self.assertIn("evil.example", str(ctx.exception))

        # Integration: _request_json surfaces redirect as failure and does not follow
        fake_error = urllib.error.HTTPError("http://auth.example/api/v3/core/groups/", 302, "Found", {}, None)  # pyright: ignore[reportArgumentType, reportCallIssue]
        opener_mock = mock.MagicMock()
        opener_mock.open.side_effect = fake_error
        opener_mock.__enter__ = mock.MagicMock(return_value=opener_mock)
        opener_mock.__exit__ = mock.MagicMock(return_value=False)
        with mock.patch.object(urllib.request, "build_opener", return_value=opener_mock) as build_mock:
            with self.assertRaisesRegex(authentik.AuthentikProjectionError, "HTTP 302"):
                authentik._request_json(url="http://auth.example/api/v3/core/groups/", token="secret-token")
            build_mock.assert_called_once()
            self.assertEqual(opener_mock.open.call_count, 1)
            called_req = opener_mock.open.call_args[0][0]
            self.assertEqual(called_req.full_url, "http://auth.example/api/v3/core/groups/")
            self.assertEqual(called_req.get_header("Authorization"), "Bearer secret-token")

    def test_desired_route_apps_collect_identity_hostname_routes(self):
        effective = {
            "schemaVersion": 3,
            "services": {
                "media": {
                    "runtime": {"unit": "jellyfin.service"},
                    "routes": {
                        "web": {
                            "exposure": {"type": "hostname", "hostnames": ["media.nas.local"], "path": "/"},
                            "auth": {"mode": "identity", "capability": "admin"},
                            "target": {"type": "http", "host": "127.0.0.1", "port": 8096},
                        },
                        "health": {
                            "exposure": {"type": "path", "paths": ["/health"]},
                            "auth": {"mode": "public"},
                            "target": {"type": "http", "host": "127.0.0.1", "port": 8096},
                        },
                    },
                }
            },
        }
        effective["derived"] = {
            "routes": [
                {
                    "service": "media",
                    "route": "web",
                    "authMode": "identity",
                    "exposure": {"type": "hostname", "hostnames": ["media.nas.local"], "path": "/"},
                    "target": {"type": "http", "host": "127.0.0.1", "port": 8096},
                    "portal": {"visible": True, "title": "Media Library"},
                }
            ]
        }
        apps = authentik.desired_route_apps(effective, public_host="nas.local")
        self.assertEqual(len(apps), 1)
        self.assertEqual(apps[0]["name"], "Media Library")
        self.assertEqual(apps[0]["slug"], "v2-media-web")
        self.assertEqual(apps[0]["hostname"], "media.nas.local")
        self.assertEqual(apps[0]["internalHost"], "http://127.0.0.1:8096")


if __name__ == "__main__":
    unittest.main()

    def test_desired_route_apps_projects_portal_visible_path_routes_as_providerless(self):
        effective = {
            "schemaVersion": 3,
            "derived": {
                "routes": [
                    {
                        "service": "vaultwarden",
                        "route": "web",
                        "authMode": "identity",
                        "exposure": {"type": "path", "paths": ["/vault"]},
                        "portal": {"visible": True, "title": "Vault"},
                        "target": {"type": "http", "host": "127.0.0.1", "port": 8222},
                    },
                    {
                        "service": "metrics",
                        "route": "grafana",
                        "authMode": "identity",
                        "exposure": {"type": "path", "paths": ["/metrics/"]},
                        "portal": {"visible": False},
                        "target": {"type": "http", "host": "127.0.0.1", "port": 3000},
                    },
                ]
            },
        }
        apps = authentik.desired_route_apps(effective, public_host="nas.local:8443")
        self.assertEqual(len(apps), 1)
        self.assertEqual(apps[0]["slug"], "v2-vaultwarden-web")
        self.assertEqual(apps[0]["name"], "Vault")
        self.assertTrue(apps[0]["providerless"])
        self.assertEqual(apps[0]["launchUrl"], "https://nas.local:8443/vault/")
