from __future__ import annotations

import io
import json
import pathlib
import sys
import tempfile
import unittest
import urllib.error
from email.message import Message
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_identity_model as identity_model  # noqa: E402
import nas_identity_sync as sync  # noqa: E402


class IdentitySyncCoverageTests(unittest.TestCase):
    def test_endpoint_label_and_error_payload_redaction(self) -> None:
        self.assertEqual(sync.endpoint_label("https://example.test/a?token=secret#x"), "https://example.test/a")
        payload = json.dumps({"token": "secret", "nested": {"password": "pw"}, "value": "ok"}).encode()
        rendered = sync.sanitize_error_payload(payload)
        self.assertNotIn("secret", rendered)
        self.assertNotIn("pw", rendered)
        self.assertIn("[redacted]", rendered)
        self.assertEqual(sync.sanitize_error_payload(b"not-json"), "non-JSON response")

    def test_retry_delay_honors_bounded_retry_after_and_falls_back(self) -> None:
        self.assertEqual(sync._retry_delay(1, "10"), 5.0)
        self.assertEqual(sync._retry_delay(1, "0"), 0.25)
        with mock.patch.object(sync.secrets, "randbelow", return_value=0):
            self.assertEqual(sync._retry_delay(2, "bad"), 0.5)

    def test_http_json_success_empty_and_invalid_json(self) -> None:
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b'{"ok":true}'
        with mock.patch.object(sync.urllib.request, "urlopen", return_value=response) as urlopen:
            self.assertEqual(sync.http_json("https://example.test/api", headers={"X-Test": "yes"}), {"ok": True})
        request = urlopen.call_args.args[0]
        self.assertEqual(request.headers["X-test"], "yes")

        empty = mock.MagicMock()
        empty.__enter__.return_value.read.return_value = b""
        with mock.patch.object(sync.urllib.request, "urlopen", return_value=empty):
            self.assertIsNone(sync.http_json("https://example.test/api"))

        invalid = mock.MagicMock()
        invalid.__enter__.return_value.read.return_value = b"{"
        with mock.patch.object(sync.urllib.request, "urlopen", return_value=invalid):
            with self.assertRaisesRegex(sync.SyncError, "invalid JSON"):
                sync.http_json("https://example.test/api")

    def test_http_json_retries_transient_reads_but_not_writes(self) -> None:
        headers = Message()
        headers["Retry-After"] = "0.25"
        transient = urllib.error.HTTPError("https://example.test", 503, "down", headers, io.BytesIO(b"{}"))
        success = mock.MagicMock()
        success.__enter__.return_value.read.return_value = b'{"ok":true}'
        with (
            mock.patch.object(sync.urllib.request, "urlopen", side_effect=[transient, success]) as urlopen,
            mock.patch.object(sync.time, "sleep") as sleep,
        ):
            self.assertEqual(sync.http_json("https://example.test/api"), {"ok": True})
        self.assertEqual(urlopen.call_count, 2)
        sleep.assert_called_once()

        denied = urllib.error.HTTPError("https://example.test", 503, "down", Message(), io.BytesIO(b"{}"))
        with mock.patch.object(sync.urllib.request, "urlopen", side_effect=denied) as urlopen:
            with self.assertRaisesRegex(sync.SyncError, "HTTP 503"):
                sync.http_json("https://example.test/api", method="POST", body={"x": 1})
        self.assertEqual(urlopen.call_count, 1)

    def test_http_json_retries_url_errors_and_reports_unreachable(self) -> None:
        error = urllib.error.URLError(OSError("offline"))
        with (
            mock.patch.object(sync.urllib.request, "urlopen", side_effect=error) as urlopen,
            mock.patch.object(sync.time, "sleep"),
        ):
            with self.assertRaisesRegex(sync.SyncError, "Unable to reach Authentik"):
                sync.http_json("https://example.test/api")
        self.assertEqual(urlopen.call_count, 3)

    def test_authentik_token_validation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            runtime = root / "runtime"
            bootstrap = root / "bootstrap"
            runtime.write_text("runtime\n", encoding="utf-8")
            bootstrap.write_text("bootstrap\n", encoding="utf-8")
            with (
                mock.patch.object(sync, "AUTHENTIK_TOKEN_FILE", runtime),
                mock.patch.object(sync, "AUTHENTIK_BOOTSTRAP_TOKEN_FILE", bootstrap),
            ):
                self.assertEqual(sync.authentik_token(), "runtime")
                self.assertEqual(sync.authentik_token(bootstrap=True), "bootstrap")
                runtime.write_text("", encoding="utf-8")
                with self.assertRaisesRegex(sync.SyncError, "empty or malformed"):
                    sync.authentik_token()
                runtime.unlink()
                with self.assertRaisesRegex(sync.SyncError, "token is missing"):
                    sync.authentik_token()

    def test_authentik_request_builds_api_url_and_list_paginates(self) -> None:
        with mock.patch.object(sync, "http_json", return_value={"ok": True}) as http:
            self.assertEqual(sync.authentik_request("token", "core/users/"), {"ok": True})
        self.assertIn("/api/v3/core/users/", http.call_args.args[0])
        self.assertEqual(http.call_args.kwargs["headers"]["Authorization"], "Bearer token")

        pages = [
            {"results": [{"pk": 1}], "pagination": {"next": 2}},
            {"results": [{"pk": 2}], "pagination": {"next": 0}},
        ]
        with mock.patch.object(sync, "authentik_request", side_effect=pages) as request:
            values = sync.authentik_list("token", "core/groups/")
        self.assertEqual([row["pk"] for row in values], [1, 2])
        self.assertEqual(request.call_count, 2)

    def test_authentik_list_accepts_plain_lists_and_rejects_bad_shapes(self) -> None:
        with mock.patch.object(sync, "authentik_request", return_value=[{"pk": 1}, "bad"]):
            self.assertEqual(sync.authentik_list("token", "core/users/"), [{"pk": 1}])
        with mock.patch.object(sync, "authentik_request", return_value={"wrong": []}):
            with self.assertRaisesRegex(sync.SyncError, "did not return a result list"):
                sync.authentik_list("token", "core/users/")

    def test_ensure_groups_creates_and_corrects_roles(self) -> None:
        existing = [
            {"pk": "admin", "name": identity_model.ADMIN_GROUP, "is_superuser": False},
            {"pk": "users", "name": identity_model.USER_GROUP, "is_superuser": True},
            {"pk": "guest", "name": identity_model.GUEST_GROUP, "is_superuser": False},
        ]
        refreshed = [
            {
                "pk": "admin",
                "name": identity_model.ADMIN_GROUP,
                "is_superuser": True,
                "users_obj": [{"username": "admin"}],
            },
            {"pk": "users", "name": identity_model.USER_GROUP, "is_superuser": False},
            {"pk": "guest", "name": identity_model.GUEST_GROUP, "is_superuser": False},
            {"pk": "disabled", "name": identity_model.DISABLED_GROUP, "is_superuser": False},
        ]
        calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
        with (
            mock.patch.object(sync, "authentik_list", side_effect=[existing, refreshed]),
            mock.patch.object(sync, "authentik_request", side_effect=lambda *a, **k: calls.append((a, k)) or {}),
        ):
            result = sync.ensure_groups("token")
        self.assertEqual(result["createdGroups"], [identity_model.DISABLED_GROUP])
        self.assertEqual(
            set(result["correctedSuperuserGroups"]), {identity_model.ADMIN_GROUP, identity_model.USER_GROUP}
        )
        self.assertTrue(any(call[1].get("method") == "POST" for call in calls))
        self.assertTrue(any(call[1].get("method") == "PATCH" for call in calls))

    def test_ensure_groups_bootstraps_akadmin_and_fails_without_it(self) -> None:
        groups = [{"pk": "admin", "name": identity_model.ADMIN_GROUP, "is_superuser": True}]
        refreshed = [{"pk": "admin", "name": identity_model.ADMIN_GROUP, "is_superuser": True, "users_obj": []}]
        users = [{"pk": 1, "username": "akadmin", "is_active": True}]
        with (
            mock.patch.object(sync, "RESERVED_GROUPS", (identity_model.ADMIN_GROUP,)),
            mock.patch.object(sync, "authentik_list", side_effect=[groups, refreshed, users]),
            mock.patch.object(sync, "authentik_request") as request,
        ):
            result = sync.ensure_groups("token")
        self.assertEqual(result["bootstrappedAdministrator"], "akadmin")
        request.assert_called_once_with("token", "core/groups/admin/add_user/", method="POST", body={"pk": 1})

        with (
            mock.patch.object(sync, "RESERVED_GROUPS", (identity_model.ADMIN_GROUP,)),
            mock.patch.object(sync, "authentik_list", side_effect=[groups, refreshed, []]),
        ):
            with self.assertRaisesRegex(sync.SyncError, "could not be found"):
                sync.ensure_groups("token")

    def test_provision_runtime_token_creates_service_account_binding_and_token(self) -> None:
        calls: list[tuple[str, dict[str, object]]] = []

        def listing(_token: str, path: str) -> list[dict[str, object]]:
            if path.startswith("core/users/"):
                return []
            if path.startswith("rbac/roles/"):
                return [{"pk": "role", "name": sync.AUTOMATION_ROLE}]
            if path.startswith("core/tokens/"):
                return []
            raise AssertionError(path)

        def request(_token: str, path: str, **kwargs: object) -> dict[str, object]:
            calls.append((path, kwargs))
            return {"user_pk": 42} if path == "core/users/service_account/" else {}

        with (
            mock.patch.object(sync, "authentik_list", side_effect=listing),
            mock.patch.object(sync, "authentik_request", side_effect=request),
            mock.patch.object(sync.secrets, "token_urlsafe", return_value="runtime-token"),
        ):
            result = sync.provision_runtime_token("bootstrap")
        self.assertTrue(result["createdServiceAccount"])
        self.assertEqual(result["token"], "runtime-token")
        self.assertTrue(any(path == "core/tokens/" for path, _ in calls))
        self.assertTrue(any(path.endswith("/set_key/") for path, _ in calls))

    def test_provision_runtime_token_rejects_missing_role_or_bad_user_key(self) -> None:
        with mock.patch.object(
            sync, "authentik_list", side_effect=[[{"pk": 42, "username": sync.AUTOMATION_USER}], []]
        ):
            with self.assertRaisesRegex(sync.SyncError, "automation role is missing"):
                sync.provision_runtime_token("token")
        with (
            mock.patch.object(sync, "authentik_list", return_value=[]),
            mock.patch.object(sync, "authentik_request", return_value={"user_pk": "bad"}),
        ):
            with self.assertRaisesRegex(sync.SyncError, "no numeric primary key"):
                sync.provision_runtime_token("token")

    def test_load_account_plan_and_fingerprint_validation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = pathlib.Path(raw) / "plan.json"
            path.write_text('{"schemaVersion":1,"accounts":[]}', encoding="utf-8")
            self.assertEqual(sync.load_account_plan(str(path))["accounts"], [])
            first = sync.account_plan_fingerprint({"accounts": [{"username": "a", "password": "one"}]})
            second = sync.account_plan_fingerprint({"accounts": [{"username": "a", "password": "two"}]})
            self.assertEqual(first, second)
            path.write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(sync.SyncError, "one JSON object"):
                sync.load_account_plan(str(path))
            path.write_text('{"schemaVersion":2,"accounts":[]}', encoding="utf-8")
            with self.assertRaisesRegex(sync.SyncError, "Unsupported"):
                sync.load_account_plan(str(path))

    def test_verify_syncthing_configuration_reports_non_convergence_and_retention(self) -> None:
        responses = [[{"id": "folder", "type": "sendonly"}], [{"deviceID": "device"}]]
        with mock.patch.object(sync, "syncthing_request", side_effect=responses):
            with self.assertRaisesRegex(sync.SyncError, "did not converge"):
                sync.verify_syncthing_configuration(
                    {"folder": {"id": "folder", "type": "receiveonly"}},
                    {"device": {"deviceID": "device"}},
                    removed_folders=set(),
                    removed_devices=set(),
                )
        responses = [[{"id": "old"}], []]
        with mock.patch.object(sync, "syncthing_request", side_effect=responses):
            with self.assertRaisesRegex(sync.SyncError, "retained removed managed folder"):
                sync.verify_syncthing_configuration({}, {}, removed_folders={"old"}, removed_devices=set())

    def test_ensure_syncthing_folder_rejects_paths_outside_expected_tree(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            with mock.patch.object(sync, "SHARE_ROOT", root):
                with self.assertRaisesRegex(sync.SyncError, "outside the managed share root"):
                    sync.ensure_syncthing_folder(pathlib.Path("/elsewhere/users/a/syncthing"))
                with self.assertRaisesRegex(sync.SyncError, "Unexpected managed Syncthing folder"):
                    sync.ensure_syncthing_folder(root / "wrong" / "a" / "syncthing")

    def test_reconcile_syncthing_disabled_is_side_effect_free(self) -> None:
        identity = identity_model.IdentityModel((), (), ("admin",))
        with (
            mock.patch.object(sync, "SYNCTHING_ENABLED", False),
            mock.patch.object(sync, "desired_syncthing") as desired,
        ):
            self.assertEqual(
                sync.reconcile_syncthing(identity),
                {"folders": 0, "devices": 0, "removedFolders": 0, "removedDevices": 0},
            )
        desired.assert_not_called()

    def test_load_account_plan_from_stdin_rejects_unknown_fields_and_types(self) -> None:
        with mock.patch.object(sync.sys, "stdin", io.StringIO('{"accounts":[],"extra":1}')):
            with self.assertRaisesRegex(sync.SyncError, "unknown field"):
                sync.load_account_plan("-")
        with mock.patch.object(
            sync.sys, "stdin", io.StringIO('{"accounts":{},"deactivateMissingManagedAccounts":false}')
        ):
            with self.assertRaisesRegex(sync.SyncError, "accounts must be a list"):
                sync.load_account_plan("-")
        with mock.patch.object(
            sync.sys, "stdin", io.StringIO('{"accounts":[],"deactivateMissingManagedAccounts":"no"}')
        ):
            with self.assertRaisesRegex(sync.SyncError, "must be true or false"):
                sync.load_account_plan("-")


if __name__ == "__main__":
    unittest.main()
