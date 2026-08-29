from __future__ import annotations

import pathlib
import stat
import sys
import types
import unittest
from typing import Any
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_first_run_api as api  # noqa: E402
import nas_first_start as first_start  # noqa: E402
import nas_setup as setup  # noqa: E402


class SetupApplicationRetirementTests(unittest.TestCase):
    def _identity_module(
        self, *, listings: list[list[dict[str, object]]] | None = None, failure: Exception | None = None
    ) -> Any:
        module = types.ModuleType("nas_identity_sync")
        remaining = list(listings or [[]])
        setattr(module, "authentik_token", mock.Mock(return_value="temporary-bootstrap-token"))

        def list_applications(_token: str, _path: str):
            if failure is not None:
                raise failure
            if len(remaining) > 1:
                return remaining.pop(0)
            return remaining[0]

        setattr(module, "authentik_list", mock.Mock(side_effect=list_applications))
        setattr(module, "authentik_request", mock.Mock(return_value=None))
        return module

    def test_already_absent_setup_application_is_successful_resume(self) -> None:
        identity = self._identity_module(listings=[[]])
        with mock.patch.dict(sys.modules, {"nas_identity_sync": identity}):
            result = first_start.remove_setup_application()
        self.assertEqual(result, {"removed": True, "resumed": True})
        identity.authentik_request.assert_not_called()

    def test_setup_application_delete_is_verified(self) -> None:
        identity = self._identity_module(listings=[[{"slug": "nas-setup"}], []])
        with mock.patch.dict(sys.modules, {"nas_identity_sync": identity}):
            result = first_start.remove_setup_application()
        self.assertEqual(result, {"removed": True, "resumed": False})
        identity.authentik_request.assert_called_once_with(
            "temporary-bootstrap-token", "core/applications/nas-setup/", method="DELETE"
        )

    def test_surviving_setup_application_fails_closed(self) -> None:
        identity = self._identity_module(listings=[[{"slug": "nas-setup"}], [{"slug": "nas-setup"}]])
        with mock.patch.dict(sys.modules, {"nas_identity_sync": identity}):
            with self.assertRaisesRegex(setup.SetupError, "still exists"):
                first_start.remove_setup_application()

    def test_authentik_failure_fails_closed(self) -> None:
        identity = self._identity_module(failure=RuntimeError("offline"))
        with mock.patch.dict(sys.modules, {"nas_identity_sync": identity}):
            with self.assertRaisesRegex(setup.SetupError, "Unable to retire"):
                first_start.remove_setup_application()


class LocalAdministratorTransactionTests(unittest.TestCase):
    administrator = {
        "username": "owner",
        "name": "NAS Owner",
        "email": "owner@example.test",
    }
    fingerprint = "f" * 64

    @staticmethod
    def _completed(returncode: int = 0, stdout: str = ""):
        return types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr="")

    def test_unclaimed_existing_account_is_never_adopted(self) -> None:
        with (
            mock.patch.object(first_start, "_load_matching_local_admin_marker", return_value=None),
            mock.patch.object(setup, "run_root_noninteractive", return_value=self._completed()),
            mock.patch.object(setup, "atomic_write_json") as write_marker,
        ):
            with self.assertRaisesRegex(setup.SetupError, "already exists"):
                first_start.create_or_resume_local_administrator(
                    self.administrator, "correct horse battery staple", self.fingerprint
                )
        write_marker.assert_not_called()

    def test_owned_partial_account_is_finished_on_resume(self) -> None:
        marker = first_start._local_admin_marker("owner", self.fingerprint)
        calls = [
            self._completed(),
            self._completed(),
            self._completed(stdout="owner wheel nas-administrators nas-operations\n"),
        ]
        with (
            mock.patch.object(first_start, "_load_matching_local_admin_marker", return_value=marker),
            mock.patch.object(setup, "run_root_noninteractive", side_effect=calls),
            mock.patch.object(setup, "run_root") as run_root,
        ):
            result = first_start.create_or_resume_local_administrator(
                self.administrator, "correct horse battery staple", self.fingerprint
            )
        self.assertEqual(result["username"], "owner")
        self.assertTrue(result["resumed"])
        self.assertEqual(run_root.call_args_list[0].args[0], ["chpasswd"])
        self.assertIn("usermod", run_root.call_args_list[1].args[0])

    def test_new_account_claim_is_persisted_before_user_creation(self) -> None:
        desired = {
            "username": "owner",
            "name": "NAS Owner",
            "email": "owner@example.test",
            "active": True,
            "groups": ["nas_admin"],
            "attributes": {},
        }
        order: list[str] = []

        def record_marker(*_args, **_kwargs):
            order.append("marker")

        def record_creation(*_args, **_kwargs):
            order.append("useradd")
            return desired

        with (
            mock.patch.object(first_start, "_load_matching_local_admin_marker", return_value=None),
            mock.patch.object(setup, "run_root_noninteractive", return_value=self._completed(1)),
            mock.patch.object(setup, "atomic_write_json", side_effect=record_marker),
            mock.patch.object(setup, "create_local_administrator", side_effect=record_creation),
        ):
            result = first_start.create_or_resume_local_administrator(
                self.administrator, "correct horse battery staple", self.fingerprint
            )
        self.assertEqual(result, desired)
        self.assertEqual(order, ["marker", "useradd"])


class FirstRunTransientDirectoryTests(unittest.TestCase):
    @staticmethod
    def _metadata(mode: int, *, uid: int = 0, gid: int = 0):
        return types.SimpleNamespace(st_mode=mode, st_uid=uid, st_gid=gid)

    def test_safe_existing_root_directory_is_accepted(self) -> None:
        path = mock.MagicMock()
        path.parent.lstat.return_value = self._metadata(stat.S_IFDIR | 0o755)
        path.mkdir.side_effect = FileExistsError
        path.lstat.return_value = self._metadata(stat.S_IFDIR | 0o700)
        api._ensure_private_root_directory(path)

    def test_symlink_job_root_is_rejected(self) -> None:
        path = mock.MagicMock()
        path.parent.lstat.return_value = self._metadata(stat.S_IFDIR | 0o755)
        path.mkdir.side_effect = FileExistsError
        path.lstat.return_value = self._metadata(stat.S_IFLNK | 0o777)
        with self.assertRaisesRegex(api.RequestError, "unsafe ownership or mode"):
            api._ensure_private_root_directory(path)

    def test_group_writable_parent_is_rejected(self) -> None:
        path = mock.MagicMock()
        path.parent.lstat.return_value = self._metadata(stat.S_IFDIR | 0o775)
        with self.assertRaisesRegex(api.RequestError, "parent is unsafe"):
            api._ensure_private_root_directory(path)


class FirstRunRateLimitTests(unittest.TestCase):
    def tearDown(self) -> None:
        with api._RATE_LOCK:
            api._RATE_EVENTS.clear()

    def test_rate_limit_is_bounded_and_expires_old_events(self) -> None:
        with api._RATE_LOCK:
            api._RATE_EVENTS.clear()
        limit, _window = api._RATE_LIMITS["submit"]
        with mock.patch.object(api.time, "monotonic", return_value=1000.0):
            for _ in range(limit):
                api._enforce_rate_limit("submit")
            with self.assertRaisesRegex(api.RequestError, "Too many"):
                api._enforce_rate_limit("submit")
        with mock.patch.object(api.time, "monotonic", return_value=2000.0):
            api._enforce_rate_limit("submit")


if __name__ == "__main__":
    unittest.main()
