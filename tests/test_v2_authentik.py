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


if __name__ == "__main__":
    unittest.main()
