from __future__ import annotations

import datetime
from email.utils import formatdate
import pathlib
import shutil
import subprocess
import tempfile
import types
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
PATCH = ROOT / "authentik/patches/authentik-known-device-cookie.patch"


class AuthentikCookiePatchTests(unittest.TestCase):
    def patched_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            tree = pathlib.Path(directory)
            stage_path = tree / "authentik/stages/user_login/stage.py"
            stage_path.parent.mkdir(parents=True)
            shutil.copyfile(ROOT / "tests/fixtures/authentik-known-device-stage.py.txt", stage_path)
            if PATCH.exists():
                subprocess.run(
                    ["git", "apply", "--include=authentik/stages/user_login/stage.py", str(PATCH)],
                    cwd=tree,
                    check=True,
                    capture_output=True,
                )
            source = stage_path.read_text()
        namespace = {
            "User": object,
            "datetime": datetime.datetime,
            "timedelta_from_string": lambda value: datetime.timedelta(days=0 if value == "disabled" else 30),
            "encode": lambda payload, key: "signed-device",
            "COOKIE_NAME_KNOWN_DEVICE": "authentik_device",
            "settings": types.SimpleNamespace(
                SESSION_COOKIE_PATH="/identity/", SESSION_COOKIE_DOMAIN=None, SESSION_COOKIE_SAMESITE="Lax"
            ),
        }
        exec(compile(source, "upstream-known-device-stage", "exec"), namespace)
        return namespace["UserLoginStageView"]()

    def test_remembered_device_cookie_is_private_and_transport_bound(self):
        for secure in (True, False):
            with self.subTest(secure=secure):
                stage = self.patched_stage()
                response = mock.Mock()
                stage.request = mock.Mock()
                stage.request.is_secure.return_value = secure
                stage.executor = mock.Mock()
                stage.executor.stage_ok.return_value = response
                stage.cookie_jwt_key = "signing-key"
                self.assertIs(stage.set_known_device_cookie(types.SimpleNamespace(uid="user-id")), response)
                args, flags = response.set_cookie.call_args
                self.assertEqual(args, ("authentik_device", "signed-device"))
                self.assertIs(flags.get("secure"), secure)
                self.assertIs(flags.get("httponly"), True)
                self.assertEqual(flags["path"], "/identity/")
                self.assertEqual(flags["samesite"], "Lax")

    def test_canonical_authentik_package_applies_cookie_patch(self):
        source = (ROOT / "modules/nas/internal/account-tools.nix").read_text()
        self.assertIn("../../../authentik/patches/authentik-known-device-cookie.patch", source)

    def test_disabled_device_remembrance_does_not_create_a_cookie(self):
        stage = self.patched_stage()
        response = mock.Mock()
        stage.executor = mock.Mock()
        stage.executor.current_stage.remember_device = "disabled"
        stage.executor.stage_ok.return_value = response
        self.assertIs(stage.set_known_device_cookie(types.SimpleNamespace(uid="user-id")), response)
        response.set_cookie.assert_not_called()


class AuthentikSessionCookiePatchTests(unittest.TestCase):
    def setUp(self):
        with tempfile.TemporaryDirectory() as directory:
            tree = pathlib.Path(directory)
            middleware_path = tree / "authentik/root/middleware.py"
            middleware_path.parent.mkdir(parents=True)
            shutil.copyfile(ROOT / "tests/fixtures/authentik-session-middleware.py.txt", middleware_path)
            subprocess.run(
                ["git", "apply", "--include=authentik/root/middleware.py", str(PATCH)],
                cwd=tree,
                check=True,
                capture_output=True,
            )
            source = middleware_path.read_text()
        self.settings = types.SimpleNamespace(
            DEBUG=False,
            TEST=False,
            SESSION_COOKIE_NAME="authentik_session",
            SESSION_COOKIE_PATH="/identity/",
            SESSION_COOKIE_DOMAIN=None,
            SESSION_COOKIE_SAMESITE="Lax",
            SESSION_COOKIE_HTTPONLY=True,
            SESSION_SAVE_EVERY_REQUEST=False,
            CSRF_USE_SESSIONS=False,
            CSRF_COOKIE_NAME="authentik_csrf",
            CSRF_COOKIE_PATH="/identity/",
            CSRF_COOKIE_DOMAIN=None,
            CSRF_COOKIE_AGE=3600,
            CSRF_COOKIE_HTTPONLY=False,
            CSRF_COOKIE_SAMESITE="Lax",
        )
        self.vary = mock.Mock()
        self.encode = mock.Mock(return_value="signed-session")
        self.decode = mock.Mock(return_value={"sid": "session-id"})
        namespace = {
            "UpstreamSessionMiddleware": object,
            "UpstreamCsrfViewMiddleware": object,
            "settings": self.settings,
            "SIGNING_HASH": "signing-key",
            "ACR_AUTHENTIK_SESSION": "goauthentik.io/core/default",
            "encode": self.encode,
            "decode": self.decode,
            "PyJWTError": ValueError,
            "UpdateError": RuntimeError,
            "SessionInterrupted": ValueError,
            "HttpResponseServerError": types.SimpleNamespace(status_code=500),
            "ClientIPMiddleware": types.SimpleNamespace(get_client_ip=lambda request: "127.0.0.1"),
            "CSRF_SESSION_KEY": "_csrftoken",
            "patch_vary_headers": self.vary,
            "time": lambda: 1700000000,
            "http_date": lambda timestamp: formatdate(timestamp, usegmt=True),
        }
        exec(compile(source, "upstream-session-middleware", "exec"), namespace)
        self.middleware = namespace["SessionMiddleware"]()
        self.csrf = namespace["CsrfViewMiddleware"]()
        self.request = mock.Mock(COOKIES={}, META={"CSRF_COOKIE": "csrf-token", "HTTP_USER_AGENT": "fixture"})
        self.request.get_host.return_value = "nas-test.local"
        self.request.is_secure.return_value = True
        self.request.user = types.SimpleNamespace(uid="user-id", is_authenticated=True)
        self.session = self.request.session
        self.session.accessed = self.session.modified = True
        self.session.session_key = "session-id"
        self.session.is_empty.return_value = False
        self.session.get_expire_at_browser_close.return_value = True
        self.response = mock.Mock(status_code=200)

    def test_session_creation_and_renewal_honor_samesite_without_losing_private_session(self):
        for secure in (False, True):
            for same_site in ("Lax", "Strict"):
                with self.subTest(secure=secure, same_site=same_site):
                    self.request.is_secure.return_value = secure
                    self.settings.SESSION_COOKIE_SAMESITE = same_site
                    self.session.modified = False
                    self.settings.SESSION_SAVE_EVERY_REQUEST = True
                    self.session.save.reset_mock()
                    self.assertIs(self.middleware.process_response(self.request, self.response), self.response)
                    self.session.save.assert_called_once_with()
                    args, flags = self.response.set_cookie.call_args
                    self.assertEqual(args, ("authentik_session", "signed-session"))
                    self.assertEqual(flags["samesite"], same_site)
                    self.assertIs(flags["secure"], secure)
                    self.assertIs(flags["httponly"], True)
                    self.assertEqual(flags["path"], "/identity/")
                    self.encode.assert_called_with(
                        payload={
                            "sid": "session-id",
                            "iss": "authentik",
                            "sub": "user-id",
                            "authenticated": True,
                            "acr": "goauthentik.io/core/default",
                        },
                        key="signing-key",
                    )

    def test_logout_deletes_the_same_path_and_samesite_cookie(self):
        self.request.COOKIES = {"authentik_session": "signed-session"}
        self.session.is_empty.return_value = True
        self.assertIs(self.middleware.process_response(self.request, self.response), self.response)
        self.response.delete_cookie.assert_called_once_with(
            "authentik_session", path="/identity/", domain=None, samesite="Lax"
        )
        self.response.set_cookie.assert_not_called()
        self.session.save.assert_not_called()
        self.vary.assert_called_once_with(self.response, ("Cookie",))

    def test_expiring_sessions_retain_their_expiry_and_save(self):
        self.session.get_expire_at_browser_close.return_value = False
        self.session.get_expiry_age.return_value = 3600
        self.middleware.process_response(self.request, self.response)
        flags = self.response.set_cookie.call_args.kwargs
        self.assertEqual(flags["max_age"], 3600)
        self.assertEqual(flags["expires"], formatdate(1700003600, usegmt=True))
        self.session.save.assert_called_once_with()

    def test_http_500_does_not_save_or_replace_a_session(self):
        self.response.status_code = 500
        self.middleware.process_response(self.request, self.response)
        self.session.save.assert_not_called()
        self.response.set_cookie.assert_not_called()

    def test_concurrent_session_deletion_still_interrupts_the_response(self):
        self.session.save.side_effect = RuntimeError("concurrent deletion")
        with self.assertRaisesRegex(ValueError, "session was deleted"):
            self.middleware.process_response(self.request, self.response)
        self.response.set_cookie.assert_not_called()

    def test_signed_session_loading_retains_ip_and_user_agent_binding(self):
        self.request.COOKIES = {"authentik_session": "signed-session"}
        self.middleware.SessionStore = mock.Mock()
        self.middleware.process_request(self.request)
        self.decode.assert_called_once_with("signed-session", "signing-key", algorithms=["HS256"])
        self.middleware.SessionStore.assert_called_once_with(
            "session-id", last_ip="127.0.0.1", last_user_agent="fixture"
        )

    def test_csrf_cookie_remains_script_readable_and_transport_bound(self):
        self.csrf._set_csrf_cookie(self.request, self.response)
        args, flags = self.response.set_cookie.call_args
        self.assertEqual(args, ("authentik_csrf", "csrf-token"))
        self.assertEqual(flags["samesite"], "Lax")
        self.assertIs(flags["secure"], True)
        self.assertIs(flags["httponly"], False)
        self.vary.assert_called_once_with(self.response, ("Cookie",))
