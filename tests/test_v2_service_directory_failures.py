from __future__ import annotations

import pathlib
import sys
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_apply as apply_mod  # noqa: E402


class V2ServiceDirectoryFailureTests(unittest.TestCase):
    def test_root_reconcile_fails_when_required_service_directory_cannot_be_created(self) -> None:
        effective = {
            "services": {
                "demo": {
                    "enabled": True,
                    "managed": True,
                    "runtime": {"type": "exec", "command": ["/bin/true"]},
                }
            }
        }
        with (
            mock.patch.object(apply_mod.os, "geteuid", return_value=0),
            mock.patch.object(pathlib.Path, "mkdir", side_effect=PermissionError("read-only filesystem")),
        ):
            with self.assertRaisesRegex(apply_mod.SystemdProjectionError, "service storage directory"):
                apply_mod._ensure_service_dirs(effective)


if __name__ == "__main__":
    unittest.main()
