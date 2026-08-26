from __future__ import annotations

import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_operation_lock as locks  # noqa: E402


class OperationLockCoverageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name) / "ops"
        self.root_patch = mock.patch.object(locks, "OPERATION_ROOT", self.root)
        self.root_patch.start()
        self.env = mock.patch.dict(
            os.environ,
            {"NAS_STATE_ALLOW_UNPRIVILEGED": "1"},
            clear=False,
        )
        self.env.start()
        os.environ.pop(locks.COORDINATION_TOKEN_ENV, None)

    def tearDown(self) -> None:
        os.environ.pop(locks.COORDINATION_TOKEN_ENV, None)
        self.env.stop()
        self.root_patch.stop()
        self.tmp.cleanup()

    def test_reservation_ttl_is_bounded(self) -> None:
        for ttl in (0, 29, 3601):
            with self.subTest(ttl=ttl), self.assertRaises(ValueError):
                locks.reserve_operation("x", ("storage",), ttl_seconds=ttl)

    def test_operation_state_ignores_stale_unlocked_metadata(self) -> None:
        locks.ensure_root()
        stale = self.root / "storage.lock"
        stale.write_text('{"token":"' + "a" * 32 + '","action":"old","classes":["storage"]}\n', encoding="utf-8")
        stale.chmod(0o660)
        state = locks.operation_state()
        self.assertEqual(state["busyClasses"], [])
        self.assertEqual(state["active"], [])

    def test_current_token_reads_environment_for_nested_process(self) -> None:
        os.environ[locks.COORDINATION_TOKEN_ENV] = "b" * 32
        self.assertEqual(locks.current_coordination_token(), "b" * 32)

    def test_cli_requires_action_and_command(self) -> None:
        with self.assertRaises(SystemExit):
            locks.main(["--class", "storage", "--", "/bin/true"])
        with self.assertRaises(SystemExit):
            locks.main(["--action", "x", "--class", "storage"])

    def test_validate_current_without_parent_token_returns_76(self) -> None:
        self.assertEqual(locks.main(["--class", "storage", "--validate-current"]), 76)


if __name__ == "__main__":
    unittest.main()
