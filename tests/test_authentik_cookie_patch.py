from __future__ import annotations

import datetime
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
                subprocess.run(["git", "apply", str(PATCH)], cwd=tree, check=True, capture_output=True)
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
