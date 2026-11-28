"""KeePass access in `nas-secrets` fails closed (black-box against the Zig binary)."""

from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from test_nas_secrets import PASSWORD, Appliance  # noqa: E402


class KeePassFailClosedTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.nas = Appliance(pathlib.Path(temporary.name))

    def keepass_verbs(self) -> list[str]:
        return [call[0] for call in self.nas.calls("keepassxc-cli")]

    def test_argument_builder_succeeds_without_optional_key_file(self) -> None:
        self.nas.initialise()
        for call in self.nas.calls("keepassxc-cli"):
            self.assertNotIn("--key-file", call)

    def test_membership_uses_exact_flattened_listing(self) -> None:
        data = json.loads(self.nas.db.read_text(encoding="utf-8"))
        data["groups"] = ["NAS"]
        data["entries"]["NAS/zfs-dataset-key-old"] = "not the key"
        self.nas.db.write_text(json.dumps(data), encoding="utf-8")
        result = self.nas.run("init")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Created KeePassXC item: ZFS native encryption key", result.stdout)
        self.assertNotEqual(self.nas.entries()["NAS/zfs-dataset-key"], "not the key")

    def test_listing_failure_aborts_before_add_or_edit(self) -> None:
        data = json.loads(self.nas.db.read_text(encoding="utf-8"))
        data["groups"] = ["NAS"]
        self.nas.db.write_text(json.dumps(data), encoding="utf-8")
        result = self.nas.run("init", env={"FAKE_KP_LS_FAIL": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unable to inspect the KeePassXC secret group.", result.stderr)
        self.assertFalse({"add", "edit"} & set(self.keepass_verbs()))

    def test_group_creation_failure_is_not_ignored(self) -> None:
        result = self.nas.run("init", env={"FAKE_KP_MKDIR_FAIL": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unable to ensure KeePassXC group", result.stderr)
        self.assertEqual(self.keepass_verbs(), ["db-info", "ls", "mkdir"])
        self.assertNotIn(PASSWORD, result.stderr)


if __name__ == "__main__":
    unittest.main()
