from __future__ import annotations

import io
import os
import pathlib
import stat
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_setup_config as config  # noqa: E402


class SetupConfigCoverageTests(unittest.TestCase):
    def base(self) -> dict[str, object]:
        return {
            "schemaVersion": 2,
            "storage": {"createPool": False},
            "accounts": [],
            "services": {},
        }

    def test_scalar_helpers_are_fail_closed(self) -> None:
        self.assertTrue(config._bool(None, "flag", True))
        self.assertFalse(config._bool(False, "flag", True))
        with self.assertRaisesRegex(config.SetupError, "must be true or false"):
            config._bool("yes", "flag", False)
        self.assertEqual(config._string(" value ", "name"), "value")
        self.assertEqual(config._string("  ", "name", allow_empty=True), "")
        for value in (None, "  "):
            with self.subTest(value=value), self.assertRaisesRegex(config.SetupError, "non-empty string"):
                config._string(value, "name")

    def test_unknown_fields_and_schema_are_rejected(self) -> None:
        bad = self.base()
        bad["typo"] = True
        with self.assertRaisesRegex(config.SetupError, "unknown field"):
            config.normalize_config(bad)
        bad = self.base()
        bad["schemaVersion"] = 1
        with self.assertRaisesRegex(config.SetupError, "Unsupported setup schemaVersion"):
            config.normalize_config(bad)

    def test_accounts_container_and_rows_are_validated(self) -> None:
        bad = self.base()
        bad["accounts"] = {}
        with self.assertRaisesRegex(config.SetupError, "accounts must be a list"):
            config.normalize_config(bad)
        for raw, message in [
            (None, "must be an object"),
            ({"username": "alice", "password": "secret"}, "plaintext password"),
            ({"username": "alice", "typo": 1}, "unknown field"),
            ({"username": "../alice"}, "unsafe"),
            ({"username": "akadmin"}, "bootstrap account"),
            ({"username": "alice", "active": "yes"}, "active must be"),
            ({"username": "alice", "name": ""}, "name must be"),
            ({"username": "alice", "email": ""}, "email must be"),
            ({"username": "alice", "groups": "nas_users"}, "groups must be"),
            ({"username": "alice", "attributes": []}, "attributes must be"),
        ]:
            candidate = self.base()
            candidate["accounts"] = [raw]
            with self.subTest(raw=raw), self.assertRaisesRegex(config.SetupError, message):
                config.normalize_config(candidate)

    def test_account_role_and_password_file_rules(self) -> None:
        for groups in (["application.demo.access"], ["custom"]):
            with self.subTest(groups=groups), self.assertRaisesRegex(config.SetupError, "non-role group"):
                config.normalize_account({"username": "alice", "groups": groups}, 0)
        with self.assertRaisesRegex(config.SetupError, "cannot disable"):
            config.normalize_account({"username": "alice", "active": False, "groups": [config.ADMIN_GROUP]}, 0)
        disabled = config.normalize_account(
            {"username": "alice", "active": False, "groups": [config.USER_GROUP, config.DISABLED_GROUP]}, 0
        )
        self.assertEqual(disabled["groups"], [config.DISABLED_GROUP])
        guest = config.normalize_account({"username": "guest", "groups": [config.GUEST_GROUP]}, 0)
        self.assertEqual(guest["groups"], [config.GUEST_GROUP])
        with self.assertRaisesRegex(config.SetupError, "absolute path"):
            config.normalize_account({"username": "alice", "passwordFile": "relative"}, 0)

    def test_syncthing_attributes_are_canonicalized_and_conflicts_rejected(self) -> None:
        device = "IIIIIII-JJJJJJJ-KKKKKKK-LLLLLLL-MMMMMMM-NNNNNNN-OOOOOOO-PPPPPPP"
        value = config.normalize_account({"username": "alice", "attributes": {"nasSyncthingDevice": {"id": device}}}, 0)
        self.assertIn("nasSyncthingDevices", value["attributes"])
        self.assertNotIn("nasSyncthingDevice", value["attributes"])
        with self.assertRaisesRegex(config.SetupError, "must not define both"):
            config.normalize_account(
                {
                    "username": "alice",
                    "attributes": {"nasSyncthingDevices": [], "nasSyncthingDevice": []},
                },
                0,
            )
        with self.assertRaisesRegex(config.SetupError, "invalid Syncthing devices"):
            config.normalize_account({"username": "alice", "attributes": {"nasSyncthingDevices": [None]}}, 0)

    def test_duplicate_accounts_are_rejected(self) -> None:
        bad = self.base()
        bad["accounts"] = [{"username": "alice"}, {"username": "alice"}]
        with self.assertRaisesRegex(config.SetupError, "Duplicate setup accounts"):
            config.normalize_config(bad)

    def test_storage_must_be_an_object_and_known_fields_only(self) -> None:
        bad = self.base()
        bad["storage"] = []
        with self.assertRaisesRegex(config.SetupError, "storage must be an object"):
            config.normalize_config(bad)
        bad = self.base()
        bad["storage"] = {"typo": True}
        with self.assertRaisesRegex(config.SetupError, "storage contains unknown field"):
            config.normalize_config(bad)

    def test_storage_device_alias_fields_and_types_are_closed(self) -> None:
        cases = [
            ({"device": "/dev/a", "devices": ["/dev/b"]}, "Use only one"),
            ({"devices": "/dev/a"}, "must be a list"),
            ({"devices": ["relative"]}, "absolute /dev path"),
            ({"devices": ["/dev/../tmp/x"]}, "parent-directory traversal"),
            ({"devices": ["/dev/a", "/dev/a"]}, "Duplicate storage devices"),
        ]
        for storage, message in cases:
            raw = self.base()
            raw["storage"] = storage
            with self.subTest(storage=storage), self.assertRaisesRegex(config.SetupError, message):
                config.normalize_config(raw)

    def test_storage_topology_wipe_and_ashift_validation(self) -> None:
        cases = [
            ({"topology": "weird"}, "topology must be one of"),
            ({"wipeDevice": True, "wipeDevices": True}, "Use only one"),
            ({"ashift": True}, "integer from 9 through 16"),
            ({"ashift": 8}, "integer from 9 through 16"),
            ({"ashift": 17}, "integer from 9 through 16"),
        ]
        for storage, message in cases:
            raw = self.base()
            raw["storage"] = storage
            with self.subTest(storage=storage), self.assertRaisesRegex(config.SetupError, message):
                config.normalize_config(raw)

    def test_storage_topology_minimums_and_non_create_options(self) -> None:
        minimums = [
            ("single", [], 1),
            ("stripe", ["/dev/a"], 2),
            ("mirror", ["/dev/a"], 2),
            ("raidz1", ["/dev/a", "/dev/b"], 3),
            ("raidz2", ["/dev/a", "/dev/b", "/dev/c"], 4),
            ("raidz3", ["/dev/a", "/dev/b", "/dev/c", "/dev/d"], 5),
        ]
        for topology, devices, required in minimums:
            raw = self.base()
            raw["storage"] = {"createPool": True, "topology": topology, "devices": devices}
            with (
                self.subTest(topology=topology),
                self.assertRaisesRegex(config.SetupError, f"requires at least {required}"),
            ):
                config.normalize_config(raw)
        raw = self.base()
        raw["storage"] = {"createPool": True, "topology": "single", "devices": ["/dev/a", "/dev/b"]}
        with self.assertRaisesRegex(config.SetupError, "exactly one device"):
            config.normalize_config(raw)
        for storage in ({"devices": ["/dev/a"]}, {"wipeDevices": True}):
            raw = self.base()
            raw["storage"] = storage
            with self.subTest(storage=storage), self.assertRaisesRegex(config.SetupError, "require storage.createPool"):
                config.normalize_config(raw)

    def test_legacy_single_device_alias_normalizes(self) -> None:
        raw = self.base()
        raw["storage"] = {"createPool": True, "device": "/dev/a", "wipeDevice": True}
        value = config.normalize_config(raw)
        self.assertEqual(value["storage"]["devices"], ["/dev/a"])
        self.assertTrue(value["storage"]["wipeDevices"])

    def test_services_container_ids_and_modes_are_validated(self) -> None:
        bad = self.base()
        bad["services"] = []
        with self.assertRaisesRegex(config.SetupError, "services must be an object"):
            config.normalize_config(bad)
        bad = self.base()
        bad["services"] = {" ": "always"}
        with self.assertRaisesRegex(config.SetupError, "service id"):
            config.normalize_config(bad)
        bad = self.base()
        bad["services"] = {"demo": "sometimes"}
        with self.assertRaisesRegex(config.SetupError, "must be one of"):
            config.normalize_config(bad)
        value = self.base()
        value["services"] = {"demo": "on-demand"}
        self.assertEqual(config.normalize_config(value)["services"], {"demo": "on-demand"})

    def test_top_level_booleans_are_validated(self) -> None:
        for key in ("deactivateMissingManagedAccounts", "runPreflight"):
            raw = self.base()
            raw[key] = "yes"
            with self.subTest(key=key), self.assertRaisesRegex(config.SetupError, "must be true or false"):
                config.normalize_config(raw)

    def test_secret_line_normalization_accepts_line_endings(self) -> None:
        self.assertEqual(config.normalize_secret_line("secret", "secret"), "secret")
        self.assertEqual(config.normalize_secret_line("secret\n", "secret"), "secret")
        self.assertEqual(config.normalize_secret_line("secret\r", "secret"), "secret")
        self.assertEqual(config.normalize_secret_line("secret\r\n", "secret"), "secret")
        for value in ("", "a\nb", "a\x00b", "x" * 4099):
            with self.subTest(value=value[:10]), self.assertRaises(config.SetupError):
                config.normalize_secret_line(value, "secret")

    def test_read_secret_stdin_uses_bounded_input(self) -> None:
        with mock.patch.object(sys, "stdin", io.StringIO("secret\n")):
            self.assertEqual(config.read_secret_stdin("secret"), "secret")

    def test_read_password_file_enforces_regular_private_utf8_file(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            path = root / "password"
            path.write_text("secret\n", encoding="utf-8")
            os.chmod(path, 0o600)
            self.assertEqual(config.read_password_file(str(path), "alice"), "secret")
            os.chmod(path, 0o644)
            with self.assertRaisesRegex(config.SetupError, "group/other"):
                config.read_password_file(str(path), "alice")
            directory = root / "directory"
            directory.mkdir()
            with self.assertRaisesRegex(config.SetupError, "not a regular file"):
                config.read_password_file(str(directory), "alice")

    def test_read_password_file_rejects_symlink_missing_and_invalid_utf8(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            target = root / "target"
            target.write_text("secret\n", encoding="utf-8")
            os.chmod(target, 0o600)
            link = root / "link"
            link.symlink_to(target)
            with self.assertRaisesRegex(config.SetupError, "without following symlinks"):
                config.read_password_file(str(link), "alice")
            with self.assertRaisesRegex(config.SetupError, "Unable to open"):
                config.read_password_file(str(root / "missing"), "alice")
            invalid = root / "invalid"
            invalid.write_bytes(b"\xff\n")
            os.chmod(invalid, stat.S_IRUSR | stat.S_IWUSR)
            with self.assertRaisesRegex(config.SetupError, "not valid UTF-8"):
                config.read_password_file(str(invalid), "alice")


if __name__ == "__main__":
    unittest.main()
