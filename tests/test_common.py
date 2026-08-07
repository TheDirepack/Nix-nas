from __future__ import annotations

import json
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))

import nas_common as common


class CommonPolicyTests(unittest.TestCase):
    def test_group_parser_is_bounded_and_fails_closed(self):
        self.assertEqual(common.split_groups("nas_users;nas_allow_ai"), {"nas_users", "nas_allow_ai"})
        self.assertEqual(common.split_groups("x" * (common.MAX_GROUP_HEADER_BYTES + 1)), set())
        self.assertEqual(common.split_groups("x" * (common.MAX_GROUP_NAME_LENGTH + 1)), set())
        too_many = ",".join(f"g{index}" for index in range(common.MAX_GROUPS + 1))
        self.assertEqual(common.split_groups(too_many), set())
        self.assertEqual(common.split_groups("nas_users\r\nadmin"), set())

    def test_feature_parent_policy_is_shared(self):
        catalog = {
            "features": {
                "parent": {"available": True, "defaultMode": "always"},
                "child": {"available": True, "defaultMode": "always", "parent": "parent"},
            }
        }
        state = {"features": {"parent": "off", "child": "always"}}
        self.assertEqual(common.effective_feature_modes(catalog, state), {"parent": "off", "child": "off"})

    def test_malformed_feature_state_is_rejected_instead_of_defaulting_on(self):
        entry = {"available": True, "defaultMode": "always"}
        for value in (None, 1, [], {}):
            with self.assertRaises(common.FeatureStateError):
                common.feature_requested_mode(entry, value)

    def test_account_admin_policy_requires_enabled_admin_group(self):
        self.assertTrue(common.account_is_admin({common.ADMIN_GROUP}))
        self.assertFalse(common.account_is_admin({common.ADMIN_GROUP, common.DISABLED_GROUP}))
        self.assertTrue(common.account_has_portal_access({common.USER_GROUP}))
        self.assertFalse(common.account_has_portal_access({common.USER_GROUP, common.DISABLED_GROUP}))

    def test_capability_policy_uses_one_shared_definition(self):
        allow, deny = common.CAPABILITY_GROUPS["ai"]
        self.assertFalse(common.capability_allowed({common.USER_GROUP}, "ai"))
        self.assertFalse(common.capability_allowed({common.USER_GROUP, allow, deny}, "ai"))
        self.assertTrue(common.capability_allowed({common.ADMIN_GROUP, deny}, "ai"))
        self.assertFalse(common.capability_allowed({common.ADMIN_GROUP, common.DISABLED_GROUP}, "ai"))
        self.assertFalse(common.capability_allowed({common.ADMIN_GROUP}, "does-not-exist"))

        original = dict(common.CAPABILITY_REGISTRY["ai"])
        try:
            common.CAPABILITY_REGISTRY["ai"]["administratorBypass"] = False
            self.assertFalse(common.capability_allowed({common.ADMIN_GROUP}, "ai"))
        finally:
            common.CAPABILITY_REGISTRY["ai"].clear()
            common.CAPABILITY_REGISTRY["ai"].update(original)

    def test_personal_share_requires_files_capability_and_non_guest(self):
        allow, _deny = common.CAPABILITY_GROUPS["files"]
        self.assertTrue(common.account_has_personal_share({common.USER_GROUP, allow}))
        self.assertFalse(common.account_has_personal_share({common.GUEST_GROUP, allow}))
        self.assertFalse(common.account_has_personal_share({common.USER_GROUP}))

    def test_new_and_guest_accounts_default_to_no_capabilities(self):
        groups = {common.GUEST_GROUP}
        self.assertFalse(common.capability_allowed(groups, "files"))
        self.assertFalse(common.capability_allowed(groups, "webdav"))
        self.assertFalse(common.capability_allowed(groups, "ai"))
        self.assertFalse(common.capability_allowed(groups, "vault"))

    def test_run_command_is_shell_free_bounded_and_handles_timeout_and_env(self):
        result = common.run_command(
            [
                sys.executable,
                "-c",
                "import os; print(os.environ['NAS_TEST_VALUE']); print('ERR', file=__import__('sys').stderr)",
            ],
            env={"NAS_TEST_VALUE": "expected"},
            timeout_seconds=5,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "expected")
        self.assertEqual(result.stderr.strip(), "ERR")

        truncated = common.run_command(
            [sys.executable, "-c", "print('abcdefghij'); print('klmnopqrst', file=__import__('sys').stderr)"],
            max_output_bytes=4,
        )
        self.assertTrue(truncated.stdout.startswith("abcd"))
        self.assertTrue(truncated.stderr.startswith("klmn"))
        self.assertIn("[output truncated]", truncated.stdout)
        self.assertIn("[output truncated]", truncated.stderr)

        timed_out = common.run_command(
            [sys.executable, "-c", "import time; time.sleep(2)"],
            timeout_seconds=0.01,
        )
        self.assertEqual(timed_out.returncode, 124)
        self.assertEqual(timed_out.stdout, "")
        self.assertIn("timed out", timed_out.stderr.lower())

        signature = __import__("inspect").signature(common.run_command)
        self.assertEqual(signature.parameters["timeout_seconds"].default, 120.0)

    def test_parse_systemd_show_handles_empty_partial_and_crlf_records(self):
        self.assertEqual(common.parse_systemd_show(" \n\t"), {})
        parsed = common.parse_systemd_show(
            "Id=a.service\r\nActiveState=active\r\n\r\n"
            "ActiveState=failed\n\n"
            "Id=b.socket\nListen=/run/b.sock\nignored-line\n"
        )
        self.assertEqual(parsed["a.service"]["ActiveState"], "active")
        self.assertEqual(parsed["b.socket"]["Listen"], "/run/b.sock")
        self.assertEqual(set(parsed), {"a.service", "b.socket"})

    def test_read_json_object_success_failure_warning_and_fallback(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            valid = root / "valid.json"
            valid.write_text('{"ok": true}', encoding="utf-8")
            self.assertEqual(common.read_json_object(valid), {"ok": True})

            warnings: list[str] = []
            missing = root / "missing.json"
            self.assertEqual(
                common.read_json_object(missing, missing={"safe": False}, warn=warnings.append),
                {"safe": False},
            )
            self.assertEqual(len(warnings), 1)
            self.assertIn("Unable to read", warnings[0])

            non_object = root / "array.json"
            non_object.write_text("[]", encoding="utf-8")
            with self.assertRaises(ValueError):
                common.read_json_object(non_object)

            malformed = root / "malformed.json"
            malformed.write_text("{", encoding="utf-8")
            with self.assertRaises(json.JSONDecodeError):
                common.read_json_object(malformed)

    def test_feature_mode_normalization_and_parent_fail_closed_paths(self):
        self.assertEqual(common.feature_requested_mode({"defaultMode": "on-demand"}), "on-demand")
        self.assertEqual(common.feature_requested_mode({"default": False}), "off")
        self.assertEqual(common.feature_requested_mode({"default": True}), "always")
        self.assertEqual(common.feature_requested_mode({}, False), "off")
        self.assertEqual(common.feature_requested_mode({}, True), "always")
        self.assertEqual(common.feature_requested_mode({"legacyTrueMode": "on-demand"}, True), "on-demand")
        self.assertEqual(common.feature_requested_mode({}, "always"), "always")

        self.assertEqual(common.effective_feature_modes({"features": []}, {"features": {}}), {})
        self.assertEqual(common.effective_feature_modes({"features": {}}, {"features": []}), {})

        catalog = {
            "features": {
                "off": {"available": True, "defaultMode": "off"},
                "unavailable": {"available": False, "defaultMode": "always"},
                "missing-parent": {"available": True, "defaultMode": "always", "parent": "missing"},
                "cycle-a": {"available": True, "defaultMode": "always", "parent": "cycle-b"},
                "cycle-b": {"available": True, "defaultMode": "always", "parent": "cycle-a"},
                "parent-off": {"available": True, "defaultMode": "always"},
                "child": {"available": True, "defaultMode": "always", "parent": "parent-off"},
            }
        }
        modes = common.effective_feature_modes(catalog, {"features": {"parent-off": "off"}})
        self.assertEqual(modes["off"], "off")
        self.assertEqual(modes["unavailable"], "off")
        self.assertEqual(modes["missing-parent"], "off")
        self.assertEqual(modes["cycle-a"], "off")
        self.assertEqual(modes["cycle-b"], "off")
        self.assertEqual(modes["child"], "off")
        self.assertFalse(common.effective_feature_flags(catalog, {"features": {"parent-off": "off"}})["child"])

    def test_capability_registry_loader_accepts_valid_custom_registry(self):
        registry = {
            "schemaVersion": 1,
            "identityGroups": {
                "administrator": "admins",
                "user": "users",
                "guest": "guests",
                "disabled": "disabled",
            },
            "capabilities": {
                "files": {
                    "id": "files",
                    "allowGroup": "nas_allow_files",
                    "denyGroup": "nas_deny_files",
                    "administratorBypass": False,
                    "description": "Test capability",
                    "owner": "test-service",
                    "routes": ["/test/"],
                    "canWakeService": False,
                    "exposedInSetup": True,
                    "exposedInCockpit": True,
                    "authentikClaims": ["groups"],
                    "available": True,
                }
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "capabilities.json"
            path.write_text(json.dumps(registry), encoding="utf-8")
            with mock.patch.dict(os.environ, {"NAS_CAPABILITY_REGISTRY_FILE": str(path)}):
                groups, capabilities = common._load_capability_registry()
        self.assertEqual(groups["administrator"], "admins")
        self.assertEqual(capabilities["files"]["administratorBypass"], False)

        with mock.patch.dict(os.environ, {}, clear=False):
            with mock.patch.dict(os.environ, {"NAS_CAPABILITY_REGISTRY_FILE": ""}):
                groups, capabilities = common._load_capability_registry()
        self.assertEqual(groups, {})
        self.assertIn("files", capabilities)

    def test_installed_capability_registry_is_required_and_environment_overrides_are_disabled(self):
        with mock.patch.object(common, "_REGISTRY_REQUIRED", True):
            with mock.patch.dict(os.environ, {"NAS_CAPABILITY_REGISTRY_FILE": ""}, clear=False):
                with self.assertRaisesRegex(RuntimeError, "required"):
                    common._load_capability_registry()
            with mock.patch.dict(os.environ, {"NAS_IDENTITY_ADMIN_GROUP": "evil-admin"}, clear=False):
                self.assertEqual(common._policy_value("NAS_IDENTITY_ADMIN_GROUP", "nas_admin"), "nas_admin")

    def test_capability_registry_loader_rejects_malformed_and_ambiguous_policy(self):
        base = {
            "schemaVersion": 1,
            "identityGroups": {
                "administrator": "admins",
                "user": "users",
                "guest": "guests",
                "disabled": "disabled",
            },
            "capabilities": {
                "files": {
                    "id": "files",
                    "allowGroup": "nas_allow_files",
                    "denyGroup": "nas_deny_files",
                    "administratorBypass": True,
                    "description": "Test capability",
                    "owner": "test-service",
                    "routes": ["/test/"],
                    "canWakeService": False,
                    "exposedInSetup": True,
                    "exposedInCockpit": True,
                    "authentikClaims": ["groups"],
                    "available": True,
                }
            },
        }

        variants: list[object] = [
            [],
            {**base, "schemaVersion": 2},
            {**base, "identityGroups": []},
            {**base, "capabilities": []},
            {**base, "identityGroups": {"administrator": "admins"}},
            {**base, "identityGroups": {**base["identityGroups"], "guest": "Bad Group"}},
            {**base, "identityGroups": {**base["identityGroups"], "guest": "users"}},
            {**base, "capabilities": {}},
            {**base, "capabilities": {"Bad!": base["capabilities"]["files"]}},
            {**base, "capabilities": {"files": []}},
            {**base, "capabilities": {"files": {**base["capabilities"]["files"], "id": "other"}}},
            {**base, "capabilities": {"files": {**base["capabilities"]["files"], "allowGroup": "bad-group"}}},
            {**base, "capabilities": {"files": {**base["capabilities"]["files"], "denyGroup": "bad-group"}}},
            {**base, "capabilities": {"files": {**base["capabilities"]["files"], "administratorBypass": "yes"}}},
            {**base, "capabilities": {"files": {**base["capabilities"]["files"], "denyGroup": "nas_allow_files"}}},
            {**base, "capabilities": {"files": {**base["capabilities"]["files"], "allowGroup": "users"}}},
            {
                **base,
                "capabilities": {
                    "files": base["capabilities"]["files"],
                    "vault": {
                        "id": "vault",
                        "allowGroup": "nas_allow_files",
                        "denyGroup": "nas_deny_vault",
                        "administratorBypass": True,
                        "description": "Test capability",
                        "owner": "test-service",
                        "routes": ["/test/"],
                        "canWakeService": False,
                        "exposedInSetup": True,
                        "exposedInCockpit": True,
                        "authentikClaims": ["groups"],
                        "available": True,
                    },
                },
            },
        ]

        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "capabilities.json"
            for index, value in enumerate(variants):
                with self.subTest(index=index):
                    path.write_text(json.dumps(value), encoding="utf-8")
                    with mock.patch.dict(os.environ, {"NAS_CAPABILITY_REGISTRY_FILE": str(path)}):
                        with self.assertRaises(RuntimeError):
                            common._load_capability_registry()

            path.write_text("{", encoding="utf-8")
            with mock.patch.dict(os.environ, {"NAS_CAPABILITY_REGISTRY_FILE": str(path)}):
                with self.assertRaises(RuntimeError):
                    common._load_capability_registry()

            missing = pathlib.Path(temporary) / "does-not-exist.json"
            with mock.patch.dict(os.environ, {"NAS_CAPABILITY_REGISTRY_FILE": str(missing)}):
                with self.assertRaises(RuntimeError):
                    common._load_capability_registry()


if __name__ == "__main__":
    unittest.main()
