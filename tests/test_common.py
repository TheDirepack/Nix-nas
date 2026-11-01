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
            common.application_capability_group("metrics-runtime"),
            "application.metrics-runtime.access",
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

    def test_account_role_helpers_fail_closed_for_disabled_accounts(self) -> None:
        self.assertTrue(common.account_enabled({common.USER_GROUP}))
        self.assertFalse(common.account_enabled({common.USER_GROUP, common.DISABLED_GROUP}))

    def test_split_groups_accepts_supported_delimiters_and_deduplicates(self) -> None:
        self.assertEqual(
            common.split_groups("nas_users, application.demo.access, nas_users"),
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

    def test_run_command_merges_environment_and_handles_timeouts(self) -> None:
        merged = common.run_command(
            [sys.executable, "-c", "import os; print(os.environ['NAS_TEST_MARKER'])"],
            env={"NAS_TEST_MARKER": "inherited-value"},
        )
        self.assertEqual(merged.returncode, 0)
        self.assertIn("inherited-value", merged.stdout)

        timed_out = common.run_command(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            timeout_seconds=1,
            input_text="protected-payload",
        )
        self.assertEqual(timed_out.returncode, 124)
        self.assertIn("protected standard input", timed_out.stderr)
        self.assertEqual(timed_out.stdout, "")

        timed_out_plain = common.run_command(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            timeout_seconds=1,
        )
        self.assertEqual(timed_out_plain.returncode, 124)
        self.assertIn("Command timed out", timed_out_plain.stderr)

    def test_split_groups_rejects_control_characters_in_individual_names(self) -> None:
        with mock.patch("sys.stderr"):
            # A control character hiding inside one comma-separated name
            # rejects the whole header, not only the offending name. The
            # per-name scan runs after stripping, so the control character
            # must survive the strip to reach that branch.
            self.assertEqual(common.split_groups("nas_users, bad\x0bname"), set())
            self.assertEqual(common.split_groups("\x7f"), set())

    def test_capability_resolver_fails_closed_when_existing_effective_is_malformed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            effective = pathlib.Path(raw) / "effective.json"
            with mock.patch.dict("os.environ", {"NAS_V2_EFFECTIVE": str(effective)}):
                # Missing compiled state is an explicit early-boot fallback.
                self.assertEqual(
                    common.resolve_v2_service_capability("NO_SERVICE", "NO_CAP", "demo", "view"),
                    ("demo", "view"),
                )
                for value in (
                    [],
                    {"derived": {}},
                    {"schemaVersion": 3, "derived": {"authorization": {}}, "services": {}},
                ):
                    with self.subTest(value=value):
                        effective.write_text(json.dumps(value), encoding="utf-8")
                        self.assertIsNone(common.resolve_v2_service_capability("NO_SERVICE", "NO_CAP", "demo", "view"))
                effective.write_text(
                    json.dumps(
                        {
                            "schemaVersion": 3,
                            "derived": {"authorization": {"demo": {"capabilities": {"view": "application.demo.view"}}}},
                            "services": {"demo": {"authorization": {"capabilities": [{"id": "view"}]}}},
                        }
                    ),
                    encoding="utf-8",
                )
                self.assertEqual(
                    common.resolve_v2_service_capability("NO_SERVICE", "NO_CAP", "demo", "view"),
                    ("demo", "view"),
                )

    def test_capability_resolver_rejects_invalid_grants_and_declarations(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            effective = pathlib.Path(raw) / "effective.json"
            with mock.patch.dict("os.environ", {"NAS_V2_EFFECTIVE": str(effective)}):
                for group in (None, {}, [], False, 1, "", "nas_admin", "application.other.view"):
                    with self.subTest(group=group):
                        effective.write_text(
                            json.dumps(
                                {
                                    "schemaVersion": 3,
                                    "services": {"demo": {"authorization": {"capabilities": [{"id": "view"}]}}},
                                    "derived": {"authorization": {"demo": {"capabilities": {"view": group}}}},
                                }
                            ),
                            encoding="utf-8",
                        )
                        self.assertIsNone(common.resolve_v2_service_capability("NO_SERVICE", "NO_CAP", "demo", "view"))
                        with self.assertRaises(ValueError):
                            common.load_effective_authority(effective)
                for services in (
                    {},
                    {"demo": None},
                    {"demo": {}},
                    {"demo": {"authorization": {"capabilities": []}}},
                    {"demo": {"authorization": {"capabilities": [{"id": "other"}]}}},
                ):
                    with self.subTest(services=services):
                        effective.write_text(
                            json.dumps(
                                {
                                    "schemaVersion": 3,
                                    "services": services,
                                    "derived": {
                                        "authorization": {"demo": {"capabilities": {"view": "application.demo.view"}}}
                                    },
                                }
                            ),
                            encoding="utf-8",
                        )
                        self.assertIsNone(common.resolve_v2_service_capability("NO_SERVICE", "NO_CAP", "demo", "view"))

    def test_capability_resolver_rejects_unavailable_existing_authority(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            effective = pathlib.Path(raw) / "effective.json"
            effective.symlink_to("current/effective.json")
            with mock.patch.dict("os.environ", {"NAS_V2_EFFECTIVE": str(effective)}):
                with self.subTest(authority="dangling-link"):
                    self.assertIsNone(common.resolve_v2_service_capability("NO_SERVICE", "NO_CAP", "demo", "view"))
                effective.unlink()
                for payload in (b"\xff", b"{", b"[" * 2000 + b"0" + b"]" * 2000):
                    with self.subTest(payload=payload[:10]):
                        effective.write_bytes(payload)
                        self.assertIsNone(common.resolve_v2_service_capability("NO_SERVICE", "NO_CAP", "demo", "view"))
                with mock.patch.object(common.json, "loads", side_effect=RecursionError("parser nesting limit")):
                    self.assertIsNone(common.resolve_v2_service_capability("NO_SERVICE", "NO_CAP", "demo", "view"))

    def test_capability_resolver_accepts_compiler_output_and_implicit_access(self) -> None:
        from nas_v2_spec import build_effective, normalize

        compiled = build_effective(
            normalize(
                {
                    "schemaVersion": 3,
                    "services": {
                        "demo": {
                            "runtime": {"type": "systemd", "unit": "demo.service"},
                            "workload": {"kind": "daemon"},
                            "authorization": {"capabilities": [{"id": "view"}]},
                        }
                    },
                }
            )
        )
        with tempfile.TemporaryDirectory() as raw:
            effective = pathlib.Path(raw) / "effective.json"
            effective.write_text(json.dumps(compiled), encoding="utf-8")
            with mock.patch.dict("os.environ", {"NAS_V2_EFFECTIVE": str(effective)}):
                for capability in ("access", "view"):
                    with self.subTest(capability=capability):
                        self.assertEqual(
                            common.resolve_v2_service_capability("NO_SERVICE", "NO_CAP", "demo", capability),
                            ("demo", capability),
                        )

    def test_implicit_access_without_a_compiled_grant_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            effective = pathlib.Path(raw) / "effective.json"
            with mock.patch.dict("os.environ", {"NAS_V2_EFFECTIVE": str(effective)}):
                for authorization in (
                    {},
                    {"demo": {}},
                    {"demo": {"capabilities": None}},
                    {"demo": {"capabilities": {}}},
                ):
                    with self.subTest(authorization=authorization):
                        effective.write_text(
                            json.dumps(
                                {
                                    "schemaVersion": 3,
                                    "services": {"demo": {"authorization": {"capabilities": []}}},
                                    "derived": {"authorization": authorization},
                                }
                            ),
                            encoding="utf-8",
                        )
                        self.assertIsNone(
                            common.resolve_v2_service_capability("NO_SERVICE", "NO_CAP", "demo", "access")
                        )

    def test_authority_lstat_failure_cannot_enable_bootstrap_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            effective = pathlib.Path(raw) / "effective.json"
            with (
                mock.patch.dict("os.environ", {"NAS_V2_EFFECTIVE": str(effective)}),
                mock.patch.object(pathlib.Path, "lstat", side_effect=PermissionError("authority parent is unreadable")),
            ):
                self.assertIsNone(common.resolve_v2_service_capability("NO_SERVICE", "NO_CAP", "demo", "access"))

    def test_access_and_explicit_capabilities_reject_malformed_service_declarations(self) -> None:
        declarations = (
            None,
            {},
            {"capabilities": None},
            {"capabilities": {}},
            {"capabilities": [None]},
            {"capabilities": [{"id": "view"}, None]},
            {"capabilities": [{"id": "view"}, {}]},
            {"capabilities": [{"id": "view"}, {"id": None}]},
        )
        with tempfile.TemporaryDirectory() as raw:
            effective = pathlib.Path(raw) / "effective.json"
            for declaration in declarations:
                value = {
                    "schemaVersion": 3,
                    "services": {"demo": {"authorization": declaration}},
                    "derived": {
                        "authorization": {
                            "demo": {
                                "capabilities": {"access": "application.demo.access", "view": "application.demo.view"}
                            }
                        }
                    },
                }
                effective.write_text(json.dumps(value), encoding="utf-8")
                with mock.patch.dict("os.environ", {"NAS_V2_EFFECTIVE": str(effective)}):
                    for capability in ("access", "view"):
                        with self.subTest(declaration=declaration, capability=capability):
                            self.assertIsNone(
                                common.resolve_v2_service_capability("NO_SERVICE", "NO_CAP", "demo", capability)
                            )

    def test_compiler_implicit_access_with_no_declared_capabilities_remains_valid(self) -> None:
        from nas_v2_spec import build_effective, normalize

        compiled = build_effective(
            normalize(
                {
                    "schemaVersion": 3,
                    "services": {
                        "demo": {"runtime": {"type": "systemd", "unit": "demo.service"}, "workload": {"kind": "daemon"}}
                    },
                }
            )
        )
        self.assertEqual(compiled["services"]["demo"]["authorization"]["capabilities"], [])
        with tempfile.TemporaryDirectory() as raw:
            effective = pathlib.Path(raw) / "effective.json"
            effective.write_text(json.dumps(compiled), encoding="utf-8")
            with mock.patch.dict("os.environ", {"NAS_V2_EFFECTIVE": str(effective)}):
                self.assertEqual(
                    common.resolve_v2_service_capability("NO_SERVICE", "NO_CAP", "demo", "access"), ("demo", "access")
                )

    def test_bootstrap_fallback_distinguishes_missing_parents_from_dangling_ancestors(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            dangling = root / "dangling"
            dangling.symlink_to("absent")
            live = root / "live"
            live.mkdir()
            linked = root / "linked"
            linked.symlink_to(live, target_is_directory=True)
            for parent, expected in (
                (dangling, None),
                (root / "missing", ("demo", "access")),
                (linked, ("demo", "access")),
            ):
                with (
                    self.subTest(parent=parent.name),
                    mock.patch.dict("os.environ", {"NAS_V2_EFFECTIVE": str(parent / "future/effective.json")}),
                ):
                    self.assertEqual(
                        common.resolve_v2_service_capability("NO_SERVICE", "NO_CAP", "demo", "access"), expected
                    )

    def test_load_effective_authority_validates_shape_and_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)

            def write(name: str, payload: str) -> pathlib.Path:
                path = root / name
                path.write_text(payload, encoding="utf-8")
                return path

            good = write(
                "good.json",
                json.dumps(
                    {
                        "schemaVersion": 3,
                        "services": {"demo": {"enabled": True}},
                        "derived": {"authorization": {"demo": {"capabilities": {"access": "application.demo.access"}}}},
                    }
                ),
            )
            self.assertEqual(common.load_effective_authority(good)["schemaVersion"], 3)

            for name, payload, message in [
                ("not-object.json", "[]", "top-level must be object"),
                ("bad-version.json", json.dumps({"schemaVersion": 1}), "unsupported schemaVersion"),
                (
                    "no-derived.json",
                    json.dumps({"schemaVersion": 3, "services": {}}),
                    "missing derived",
                ),
                (
                    "no-authz.json",
                    json.dumps({"schemaVersion": 3, "services": {}, "derived": {}}),
                    "missing derived.authorization",
                ),
                (
                    "no-services.json",
                    json.dumps({"schemaVersion": 3, "derived": {"authorization": {}}}),
                    "missing services",
                ),
                (
                    "bad-authz-entry.json",
                    json.dumps(
                        {
                            "schemaVersion": 3,
                            "services": {},
                            "derived": {"authorization": {"demo": "not-an-object"}},
                        }
                    ),
                    "must be object",
                ),
                (
                    "bad-caps.json",
                    json.dumps(
                        {
                            "schemaVersion": 3,
                            "services": {},
                            "derived": {"authorization": {"demo": {"capabilities": "not-an-object"}}},
                        }
                    ),
                    "must be object",
                ),
                ("invalid-json.json", "{not json", "Expecting"),
            ]:
                with self.subTest(name=name):
                    with self.assertRaises(ValueError, msg=name):
                        common.load_effective_authority(write(name, payload))


if __name__ == "__main__":
    unittest.main()
