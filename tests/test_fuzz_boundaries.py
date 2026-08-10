from __future__ import annotations

import contextlib
import io
import json
import pathlib
import re
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
TESTS = ROOT / "tests"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

try:
    from hypothesis import HealthCheck, given, settings, strategies as st
except ImportError:
    HAS_HYPOTHESIS = False
else:
    HAS_HYPOTHESIS = True

    import nas_alert_router as alerts
    import nas_cockpit_api as api
    import nas_common as common
    import nas_identity_model as identity
    import nas_setup_config as setup_config
    import nas_state as state
    import nas_syncthing_devices as syncthing
    from fuzz_harness import identifier_candidates, json_values, path_candidates


if HAS_HYPOTHESIS:

    class StructuredBoundaryFuzzTests(unittest.TestCase):  # pyright: ignore[reportRedeclaration]
        @settings(max_examples=500, deadline=None, suppress_health_check=[HealthCheck.too_slow])
        @given(st.text(max_size=9000))
        def test_group_header_parser_is_total_bounded_and_control_safe(self, raw: str) -> None:
            with contextlib.redirect_stderr(io.StringIO()):
                groups = common.split_groups(raw)
            self.assertLessEqual(len(groups), common.MAX_GROUPS)
            for name in groups:
                self.assertLessEqual(len(name), common.MAX_GROUP_NAME_LENGTH)
                self.assertFalse(any(ord(character) < 32 or ord(character) == 127 for character in name))
            if any(ord(character) < 32 or ord(character) == 127 for character in raw):
                self.assertEqual(groups, set())

        @settings(max_examples=400, deadline=None)
        @given(identifier_candidates(max_size=300))
        def test_usernames_never_escape_the_declared_identifier_grammar(self, raw: str) -> None:
            try:
                accepted = syncthing.validate_username(raw)
            except syncthing.DeviceError:
                return
            self.assertEqual(accepted, raw)
            self.assertRegex(accepted, syncthing.USERNAME_RE)

        @settings(max_examples=400, deadline=None)
        @given(identifier_candidates(max_size=512))
        def test_cockpit_feature_argument_acceptance_matches_declared_grammar(self, raw: str) -> None:
            try:
                accepted = api.validate_argument(raw, api.FEATURE_RE, "feature identifier")
            except api.ApiError:
                self.assertTrue(len(raw) > api.MAX_ARGUMENT_LENGTH or api.FEATURE_RE.fullmatch(raw) is None)
                return
            self.assertEqual(accepted, raw)
            self.assertLessEqual(len(accepted), api.MAX_ARGUMENT_LENGTH)
            self.assertIsNotNone(api.FEATURE_RE.fullmatch(accepted))

        @settings(max_examples=400, deadline=None)
        @given(st.text(max_size=4200))
        def test_secret_line_normalization_never_returns_multiline_or_nul_data(self, raw: str) -> None:
            try:
                accepted = setup_config.normalize_secret_line(raw, "fuzz secret")
            except setup_config.SetupError:
                return
            self.assertTrue(accepted)
            self.assertNotIn("\x00", accepted)
            self.assertNotIn("\r", accepted)
            self.assertNotIn("\n", accepted)
            self.assertLessEqual(len(accepted), 4096)

        @settings(max_examples=500, deadline=None)
        @given(st.one_of(path_candidates(), st.text(max_size=2048)))
        def test_archive_member_parser_never_returns_absolute_or_parent_paths(self, raw: str) -> None:
            try:
                accepted = state.safe_member_name(raw)
            except state.StateError:
                return
            self.assertFalse(accepted.is_absolute())
            self.assertNotIn("..", accepted.parts)
            self.assertNotIn("", accepted.parts)
            self.assertFalse(any(ord(character) < 32 or ord(character) == 127 for character in accepted.as_posix()))
            self.assertLessEqual(len(accepted.as_posix().encode("utf-8")), state.MAX_ARCHIVE_MEMBER_NAME_BYTES)
            self.assertTrue(
                all(len(part.encode("utf-8")) <= state.MAX_ARCHIVE_COMPONENT_BYTES for part in accepted.parts)
            )

        @settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.too_slow])
        @given(
            st.one_of(
                st.text(max_size=4096),
                st.dictionaries(
                    st.sampled_from(["deviceID", "name", "addresses", "compression", "introducer"]),
                    json_values(max_leaves=20),
                    max_size=5,
                ).map(lambda value: json.dumps(value, ensure_ascii=False)),
            )
        )
        def test_syncthing_device_decoder_has_only_expected_failure_modes(self, raw: str) -> None:
            try:
                device = syncthing.normalize_device(raw)
            except syncthing.DeviceError:
                return
            self.assertRegex(device["deviceID"], syncthing.DEVICE_ID_RE)
            self.assertLessEqual(len(device["name"]), syncthing.MAX_DEVICE_NAME)
            self.assertLessEqual(len(device["addresses"]), syncthing.MAX_ADDRESSES)

        @settings(max_examples=350, deadline=None, suppress_health_check=[HealthCheck.too_slow])
        @given(
            alertname=st.text(max_size=2000),
            severity=st.text(max_size=2000),
            summary=st.text(max_size=4000),
            description=st.text(max_size=8000),
        )
        def test_alert_normalization_is_bounded_and_control_safe(
            self, alertname: str, severity: str, summary: str, description: str
        ) -> None:
            raw = {
                "labels": {"alertname": alertname, "severity": severity},
                "annotations": {"summary": summary, "description": description},
                "startsAt": "2026-08-06T12:00:00Z",
            }
            try:
                alert = alerts.normalize_alert(raw)
            except alerts.AlertRouterError:
                return
            self.assertLessEqual(len(alert.title), 256)
            self.assertLessEqual(len(alert.message), 4096)
            self.assertFalse(any(ord(character) < 32 or ord(character) == 127 for character in alert.title))
            self.assertTrue(all(len(key) <= 128 and len(value) <= 512 for key, value in alert.labels.items()))
            self.assertTrue(
                all(
                    not any(ord(character) < 32 or ord(character) == 127 for character in value)
                    for value in alert.labels.values()
                )
            )

        @settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
        @given(json_values(max_leaves=60))
        def test_setup_config_never_returns_unsafe_account_identifiers(self, accounts: object) -> None:
            raw = {"schemaVersion": 1, "storage": {"createPool": False}, "accounts": accounts, "features": {}}
            try:
                normalized = setup_config.normalize_config(raw)
            except (setup_config.SetupError, TypeError, ValueError):
                return
            for account in normalized["accounts"]:
                self.assertRegex(account["username"], syncthing.USERNAME_RE)

        @settings(max_examples=400, deadline=None)
        @given(identifier_candidates(max_size=256))
        def test_identity_model_rejects_or_preserves_usernames(self, username: str) -> None:
            raw = {"groups": [], "users": [{"pk": "1", "username": username, "is_active": True}]}
            try:
                model = identity.build_model(raw)
            except identity.SyncError:
                return
            self.assertTrue(all(re.fullmatch(syncthing.USERNAME_RE, user.uid) for user in model.users))
            self.assertTrue(all(user.uid == username for user in model.users))
else:

    @unittest.skip("Hypothesis is not installed; CI runs this suite in the Nix test environment")
    class StructuredBoundaryFuzzTests(unittest.TestCase):  # pyright: ignore[reportRedeclaration]
        def test_hypothesis_tier_placeholder(self) -> None:
            pass


if __name__ == "__main__":
    unittest.main()
