from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

try:
    from hypothesis import HealthCheck, given, settings, strategies as st
except ImportError:
    HAS_HYPOTHESIS = False
else:
    HAS_HYPOTHESIS = True
    import nas_alert_router as alert_router
    import nas_cockpit_api as cockpit_api
    import nas_common as common
    import nas_logging as nas_logging
    import nas_feature_model as feature_model
    import nas_setup_config as setup_config
    import nas_state as nas_state
    import nas_syncthing_devices as syncthing_devices


if HAS_HYPOTHESIS:

    class PropertyInvariantTests(unittest.TestCase):
        @settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.too_slow])
        @given(st.text(max_size=9000))
        def test_group_parser_is_total_and_bounded(self, value: str) -> None:
            result = common.split_groups(value)
            self.assertLessEqual(len(result), common.MAX_GROUPS)
            for group in result:
                self.assertLessEqual(len(group), common.MAX_GROUP_NAME_LENGTH)
                self.assertFalse(any(ord(character) < 32 or ord(character) == 127 for character in group))

        @settings(max_examples=300, deadline=None)
        @given(st.text(max_size=4200))
        def test_secret_normalization_never_returns_control_characters(self, value: str) -> None:
            try:
                normalized = setup_config.normalize_secret_line(value, "property-secret")
            except setup_config.SetupError:
                return
            self.assertTrue(normalized)
            self.assertLessEqual(len(normalized), 4096)
            self.assertFalse(any(ord(character) < 32 or ord(character) == 127 for character in normalized))

        @settings(max_examples=300, deadline=None)
        @given(st.text(max_size=256))
        def test_username_validator_never_accepts_path_or_control_delimiters(self, value: str) -> None:
            try:
                normalized = syncthing_devices.validate_username(value)
            except syncthing_devices.DeviceError:
                return
            self.assertEqual(normalized, value)
            self.assertNotIn("/", normalized)
            self.assertNotIn("\\", normalized)
            self.assertFalse(any(ord(character) < 32 or ord(character) == 127 for character in normalized))

        @settings(max_examples=350, deadline=None)
        @given(st.text(max_size=5000))
        def test_state_archive_member_parser_is_total_and_bounded(self, value: str) -> None:
            try:
                normalized = nas_state.safe_member_name(value)
            except nas_state.StateError:
                return
            self.assertFalse(normalized.is_absolute())
            self.assertNotIn("..", normalized.parts)
            self.assertFalse(any(ord(character) < 32 or ord(character) == 127 for character in normalized.as_posix()))
            self.assertLessEqual(len(normalized.as_posix().encode("utf-8")), nas_state.MAX_ARCHIVE_MEMBER_NAME_BYTES)
            for part in normalized.parts:
                self.assertLessEqual(len(part.encode("utf-8")), nas_state.MAX_ARCHIVE_COMPONENT_BYTES)

        @settings(max_examples=300, deadline=None)
        @given(st.text(max_size=300))
        def test_cockpit_feature_argument_acceptance_matches_declared_grammar(self, value: str) -> None:
            try:
                normalized = cockpit_api.validate_argument(value, cockpit_api.FEATURE_RE, "feature identifier")
            except cockpit_api.ApiError:
                self.assertTrue(
                    len(value) > cockpit_api.MAX_ARGUMENT_LENGTH or cockpit_api.FEATURE_RE.fullmatch(value) is None
                )
                return
            self.assertEqual(normalized, value)
            self.assertIsNotNone(cockpit_api.FEATURE_RE.fullmatch(normalized))
            self.assertLessEqual(len(normalized), cockpit_api.MAX_ARGUMENT_LENGTH)

        @settings(max_examples=250, deadline=None)
        @given(
            st.recursive(
                st.none() | st.booleans() | st.integers() | st.text(max_size=2000),
                lambda children: (
                    st.lists(children, max_size=40) | st.dictionaries(st.text(max_size=200), children, max_size=40)
                ),
                max_leaves=100,
            )
        )
        def test_structured_logging_sanitizer_is_json_serializable_and_bounded(self, value: object) -> None:
            sanitized = nas_logging.sanitize(value)
            import json

            encoded = json.dumps(sanitized)
            self.assertLess(len(encoded), 2_000_000)

        @settings(max_examples=350, deadline=None)
        @given(st.one_of(st.text(max_size=4096), st.none(), st.booleans(), st.integers()))
        def test_loopback_http_url_validator_is_total_and_fail_closed(self, value: object) -> None:
            accepted = feature_model.valid_loopback_http_url(value)
            self.assertIsInstance(accepted, bool)
            if not accepted:
                return
            self.assertIsInstance(value, str)
            import urllib.parse

            parsed = urllib.parse.urlsplit(value)
            self.assertEqual(parsed.scheme, "http")
            self.assertIn(parsed.hostname, {"127.0.0.1", "localhost", "::1"})
            self.assertIsNone(parsed.username)
            self.assertIsNone(parsed.password)
            self.assertFalse(parsed.fragment)
            if parsed.port is not None:
                self.assertGreater(parsed.port, 0)
                self.assertLess(parsed.port, 65536)

        @settings(max_examples=250, deadline=None)
        @given(
            alertname=st.text(max_size=2000),
            instance=st.text(max_size=2000),
            description=st.text(max_size=8000),
            severity=st.text(max_size=100),
        )
        def test_alert_normalization_is_bounded(
            self, alertname: str, instance: str, description: str, severity: str
        ) -> None:
            alert = alert_router.normalize_alert(
                {
                    "labels": {"alertname": alertname, "instance": instance, "severity": severity},
                    "annotations": {"description": description},
                }
            )
            self.assertLessEqual(len(alert.title), 256)
            self.assertLessEqual(len(alert.message), 4096)
            self.assertFalse(any(ord(character) < 32 or ord(character) == 127 for character in alert.title))
            self.assertTrue(
                all(
                    not any(ord(character) < 32 or ord(character) == 127 for character in value)
                    for value in alert.labels.values()
                )
            )
            self.assertIn(alert.severity, {"critical", "warning", "info"})
else:

    @unittest.skip("Hypothesis is not installed; CI runs the property-test tier with it")
    class PropertyInvariantTests(unittest.TestCase):
        def test_hypothesis_tier_placeholder(self) -> None:
            pass


if __name__ == "__main__":
    unittest.main()
