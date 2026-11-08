from __future__ import annotations

import contextlib
import io
import json
import pathlib
import stat
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "services"))
import nas_setup as setup  # noqa: E402


class SetupPlanCreationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = pathlib.Path(self.directory.name)
        self.path = self.root / "first-run.json"
        patch = mock.patch.multiple(
            setup,
            STATE_PATH=self.root / "state.json",
            JOURNAL_PATH=self.root / "journal.json",
            FIRST_START_STATUS_PATH=self.root / "status.json",
        )
        patch.start()
        self.addCleanup(patch.stop)

    def request(self):
        return {"storage": {"createPool": True, "devices": ["/dev/vdb"], "topology": "single", "wipeDevices": True}}

    def create(self, request=None):
        with (
            mock.patch.object(setup.os, "geteuid", return_value=0),
            mock.patch.object(setup, "acquire_operation", return_value=contextlib.nullcontext()),
            mock.patch.object(setup, "validate_storage_request") as validate,
            mock.patch.object(setup, "pool_exists", return_value=False),
        ):
            result = setup.create_first_start_plan(str(self.path), request or self.request())
        return result, validate

    def test_fresh_plan_is_private_reviewable_and_does_not_run_setup(self):
        with mock.patch.object(setup, "first_run") as execute:
            result, validate = self.create()
        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["storage"]["devices"], ["/dev/vdb"])
        saved = setup.normalize_config(json.loads(self.path.read_text()))
        self.assertEqual(result["planDigest"], setup.setup_plan_digest(saved))
        self.assertTrue(saved["runPreflight"])
        self.assertEqual(saved["accounts"], [])
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        validate.assert_called_once_with(saved["storage"], ["/dev/vdb"], True)
        execute.assert_not_called()

    def test_existing_plan_and_symlink_are_never_replaced(self):
        self.path.write_text("preserve existing configuration")
        with self.assertRaisesRegex(setup.SetupError, "already exists"):
            self.create()
        self.assertEqual(self.path.read_text(), "preserve existing configuration")
        self.path.unlink()
        target = self.root / "target"
        self.path.symlink_to(target)
        with self.assertRaisesRegex(setup.SetupError, "already exists"):
            self.create()
        self.assertFalse(target.exists())

    def test_started_or_completed_setup_blocks_plan_creation(self):
        for path in (setup.STATE_PATH, setup.JOURNAL_PATH):
            with self.subTest(path=path):
                path.write_text('{"status":"running"}')
                with self.assertRaisesRegex(setup.SetupError, "already started"):
                    self.create()
                self.assertFalse(self.path.exists())
                path.unlink()

    def test_rejects_unsafe_or_secret_fields_before_writing(self):
        for request in (
            {**self.request(), "password": "never persist me"},
            {**self.request(), "configPath": "/etc/shadow"},
            {"storage": {"createPool": True, "devices": ["/dev/../etc/shadow"]}},
            {"storage": {"createPool": True, "devices": ["/dev/vdb", "/dev/vdb"]}},
            {"storage": {"createPool": True, "devices": ["/dev/vdb"], "topology": "mirror"}},
        ):
            with self.subTest(request=request), self.assertRaises(setup.SetupError):
                self.create(request)
            self.assertFalse(self.path.exists())

    def test_disk_rejection_cannot_publish_a_plan(self):
        with (
            mock.patch.object(setup.os, "geteuid", return_value=0),
            mock.patch.object(setup, "acquire_operation", return_value=contextlib.nullcontext()),
            mock.patch.object(setup, "validate_storage_request", side_effect=setup.SetupError("device is in use")),
            self.assertRaisesRegex(setup.SetupError, "in use"),
        ):
            setup.create_first_start_plan(str(self.path), self.request())
        self.assertFalse(self.path.exists())

    def test_nonroot_cannot_create_a_plan_directly(self):
        with (
            mock.patch.object(setup.os, "geteuid", return_value=1000),
            self.assertRaisesRegex(setup.SetupError, "root"),
        ):
            setup.create_first_start_plan(str(self.path), self.request())
        self.assertFalse(self.path.exists())

    def test_cli_uses_the_same_plan_creation_operation(self):
        with (
            mock.patch.object(sys, "argv", ["nas-setup", "create-first-start-plan", "--config", str(self.path)]),
            mock.patch.object(sys, "stdin", io.StringIO(json.dumps(self.request()))),
            contextlib.redirect_stdout(io.StringIO()) as output,
            mock.patch.object(setup, "create_first_start_plan", return_value={"status": "ready"}) as create,
        ):
            self.assertEqual(setup.main(), 0)
        create.assert_called_once_with(str(self.path), self.request())
        self.assertEqual(json.loads(output.getvalue()), {"status": "ready"})

    def test_inventory_marks_boot_disk_and_readonly_media_unavailable(self):
        inventory = {
            "blockdevices": [
                {
                    "path": "/dev/vda",
                    "maj:min": "8:0",
                    "type": "disk",
                    "mountpoints": [None],
                    "ro": False,
                    "children": [{"path": "/dev/vda1", "maj:min": "8:1", "type": "part", "mountpoints": ["/"]}],
                },
                {
                    "path": "/dev/vdb",
                    "maj:min": "8:16",
                    "type": "disk",
                    "mountpoints": [None],
                    "ro": False,
                    "size": 8192,
                },
                {"path": "/dev/vdc", "maj:min": "8:32", "type": "disk", "mountpoints": [None], "ro": True},
            ]
        }

        def command(argv, **kwargs):
            return setup.Completed(
                tuple(argv), json.dumps(inventory) if argv[0] == "lsblk" else "Filename Type Size Used Priority\n", ""
            )

        with mock.patch.object(setup, "run_storage_host", side_effect=command):
            devices = setup.storage_device_inventory()
        by_path = {item["path"]: item for item in devices}
        self.assertFalse(by_path["/dev/vda"]["available"])
        self.assertTrue(by_path["/dev/vdb"]["available"])
        self.assertFalse(by_path["/dev/vdc"]["available"])


if __name__ == "__main__":
    unittest.main()
