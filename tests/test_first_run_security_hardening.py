from __future__ import annotations

import pathlib
import stat
import sys
import types
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_first_run_api as api  # noqa: E402
import nas_first_start as first_start  # noqa: E402
import nas_setup as setup  # noqa: E402


class SetupApplicationRetirementTests(unittest.TestCase):
    def _identity_module(self, *, listings: list[list[dict[str, object]]] | None = None, failure: Exception | None = None):
        module = types.ModuleType("nas_identity_sync")
        remaining = list(listings or [[]])
        module.authentik_token = mock.Mock(return_value="temporary-bootstrap-token")

        def list_applications(_token: str, _path: str):
            if failure is not None:
                raise failure
            if len(remaining) > 1:
                return remaining.pop(0)
            return remaining[0]

        module.authentik_list = mock.Mock(side_effect=list_applications)
        module.authentik_request = mock.Mock(return_value=None)
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
        identity = self._identity_module(
            listings=[[{"slug": "nas-setup"}], [{"slug": "nas-setup"}]]
        )
        with mock.patch.dict(sys.modules, {"nas_identity_sync": identity}):
            with self.assertRaisesRegex(setup.SetupError, "still exists"):
                first_start.remove_setup_application()

    def test_authentik_failure_fails_closed(self) -> None:
        identity = self._identity_module(failure=RuntimeError("offline"))
        with mock.patch.dict(sys.modules, {"nas_identity_sync": identity}):
            with self.assertRaisesRegex(setup.SetupError, "Unable to retire"):
                first_start.remove_setup_application()


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


if __name__ == "__main__":
    unittest.main()
