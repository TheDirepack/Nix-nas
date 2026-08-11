from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_common as common  # noqa: E402


class CommonPolicyTests(unittest.TestCase):
    def test_base_identity_roles_are_distinct_from_application_capabilities(self) -> None:
        self.assertEqual(common.ADMIN_GROUP, "nas_admin")
        self.assertEqual(common.USER_GROUP, "nas_users")
        self.assertEqual(common.GUEST_GROUP, "nas_guests")
        self.assertEqual(common.DISABLED_GROUP, "nas_disabled")
        for role in (common.ADMIN_GROUP, common.USER_GROUP, common.GUEST_GROUP, common.DISABLED_GROUP):
            self.assertFalse(role.startswith("application."))

    def test_application_capability_group_is_canonical_and_validated(self) -> None:
        self.assertEqual(
            common.application_capability_group("copyparty", "files"),
            "application.copyparty.files",
        )
        self.assertEqual(
            common.application_capability_group("ai-coding"),
            "application.ai-coding.access",
        )
        for service_id in ("", "UPPER", "../demo", "demo_service"):
            with self.subTest(service_id=service_id), self.assertRaises(ValueError):
                common.application_capability_group(service_id)
        for capability in ("", "UPPER", "../admin", "capability_with_underscore"):
            with self.subTest(capability=capability), self.assertRaises(ValueError):
                common.application_capability_group("demo", capability)

    def test_application_capability_policy_fails_closed_and_admin_bypasses(self) -> None:
        capability = common.application_capability_group("copyparty", "files")
        self.assertTrue(common.application_capability_allowed({capability}, "copyparty", "files"))
        self.assertFalse(common.application_capability_allowed({common.USER_GROUP}, "copyparty", "files"))
        self.assertTrue(common.application_capability_allowed({common.ADMIN_GROUP}, "copyparty", "files"))
        self.assertFalse(
            common.application_capability_allowed(
                {common.ADMIN_GROUP, common.DISABLED_GROUP},
                "copyparty",
                "files",
            )
        )
        self.assertFalse(
            common.application_capability_allowed(
                {common.ADMIN_GROUP},
                "copyparty",
                "files",
                administrator_bypass=False,
            )
        )

    def test_personal_share_requires_copyparty_files_and_non_guest(self) -> None:
        files = common.application_capability_group("copyparty", "files")
        self.assertTrue(common.account_has_personal_share({common.USER_GROUP, files}))
        self.assertTrue(common.account_has_personal_share({common.ADMIN_GROUP}))
        self.assertFalse(common.account_has_personal_share({common.USER_GROUP}))
        self.assertFalse(common.account_has_personal_share({common.GUEST_GROUP, files}))
        self.assertFalse(common.account_has_personal_share({common.USER_GROUP, files, common.DISABLED_GROUP}))

    def test_account_role_helpers_fail_closed_for_disabled_accounts(self) -> None:
        self.assertTrue(common.account_enabled({common.USER_GROUP}))
        self.assertFalse(common.account_enabled({common.USER_GROUP, common.DISABLED_GROUP}))
        self.assertTrue(common.account_is_admin({common.ADMIN_GROUP}))
        self.assertFalse(common.account_is_admin({common.ADMIN_GROUP, common.DISABLED_GROUP}))
        self.assertTrue(common.account_has_portal_access({common.GUEST_GROUP}))
        self.assertFalse(common.account_has_portal_access({common.GUEST_GROUP, common.DISABLED_GROUP}))

    def test_split_groups_accepts_supported_delimiters_and_deduplicates(self) -> None:
        self.assertEqual(
            common.split_groups("nas_users; application.demo.access | nas_users"),
            {"nas_users", "application.demo.access"},
        )

    def test_split_groups_rejects_control_characters_and_resource_exhaustion(self) -> None:
        with mock.patch("sys.stderr"):
            self.assertEqual(common.split_groups("nas_users\napplication.demo.access"), set())
            oversized = "x" * (common.MAX_GROUP_HEADER_BYTES + 1)
            self.assertEqual(common.split_groups(oversized), set())
            too_many = ",".join(f"g{index}" for index in range(common.MAX_GROUPS + 1))
            self.assertEqual(common.split_groups(too_many), set())
            long_name = "x" * (common.MAX_GROUP_NAME_LENGTH + 1)
            self.assertEqual(common.split_groups(long_name), set())

    def test_parse_systemd_show_uses_id_as_record_key(self) -> None:
        parsed = common.parse_systemd_show(
            "Id=demo.service\nActiveState=active\n\nId=second.service\nActiveState=inactive\nResult=success\n"
        )
        self.assertEqual(parsed["demo.service"]["ActiveState"], "active")
        self.assertEqual(parsed["second.service"]["Result"], "success")
        self.assertEqual(common.parse_systemd_show(""), {})

    def test_read_json_object_requires_mapping_or_explicit_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            good = root / "good.json"
            good.write_text(json.dumps({"ok": True}), encoding="utf-8")
            self.assertEqual(common.read_json_object(good), {"ok": True})

            bad = root / "bad.json"
            bad.write_text("[]", encoding="utf-8")
            with self.assertRaises(ValueError):
                common.read_json_object(bad)

            warnings: list[str] = []
            self.assertEqual(
                common.read_json_object(root / "missing.json", missing={"ok": False}, warn=warnings.append),
                {"ok": False},
            )
            self.assertEqual(len(warnings), 1)

    def test_run_command_bounds_output_and_redacts_failed_secret_stdin(self) -> None:
        noisy = common.run_command(
            [sys.executable, "-c", "print('x' * 1000)"],
            max_output_bytes=32,
        )
        self.assertEqual(noisy.returncode, 0)
        self.assertIn("[output truncated]", noisy.stdout)
        self.assertLess(len(noisy.stdout), 100)

        secret = "secret-value-that-must-not-return"
        failed = common.run_command(
            [sys.executable, "-c", "import sys; data=sys.stdin.read(); print(data); raise SystemExit(7)"],
            input_text=secret,
        )
        self.assertEqual(failed.returncode, 7)
        self.assertNotIn(secret, failed.stdout + failed.stderr)
        self.assertEqual(failed.stdout, "")
        self.assertIn("protected standard input", failed.stderr)


if __name__ == "__main__":
    unittest.main()
