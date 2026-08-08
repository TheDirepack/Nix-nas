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
    import nas_feature_model as feature_model
    import nas_logging as nas_logging
    import nas_managed_service as msvc
    import nas_setup_config as setup_config
    import nas_state as nas_state
    import nas_syncthing_devices as syncthing_devices
    from tests.slow_managed_service_stateful import ProjectionDifferentialTests, StatefulTests


if HAS_HYPOTHESIS:
    SAFE_MANAGED_HOSTNAME = st.from_regex(r"[a-z0-9][a-z0-9-]{0,9}\.example\.test", fullmatch=True)

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

        @settings(
            max_examples=120, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large]
        )
        @given(
            service_id=st.from_regex(r"[a-z][a-z0-9-]{0,12}", fullmatch=True),
            label=st.text(
                min_size=1,
                max_size=32,
                alphabet=st.characters(min_codepoint=33, max_codepoint=126, blacklist_characters="\x00\r\n/\\"),
            ),
            port=st.integers(min_value=1, max_value=65535),
            hostname=SAFE_MANAGED_HOSTNAME,
        )
        def test_managed_service_valid_doc_is_accepted(
            self, service_id: str, label: str, port: int, hostname: str
        ) -> None:
            doc = {
                "label": label,
                "enabled": True,
                "runtime": {
                    "type": "compose",
                    "source": f"/var/lib/nas-control/apps/{service_id}/compose.yaml",
                    "startPolicy": "boot",
                },
                "endpoints": {
                    "web": {
                        "transport": "http",
                        "targetPort": port,
                        "exposure": {"type": "hostname", "value": hostname},
                        "auth": {"mode": "public"},
                    }
                },
            }
            result = msvc.validate_service(service_id, doc)
            self.assertEqual(result, doc)

        @settings(max_examples=120, deadline=None, suppress_health_check=[HealthCheck.too_slow])
        @given(
            service_id=st.from_regex(r"[a-z][a-z0-9-]{0,12}", fullmatch=True),
            label=st.text(
                min_size=1,
                max_size=32,
                alphabet=st.characters(min_codepoint=33, max_codepoint=126, blacklist_characters="\x00\r\n/\\"),
            ),
            port=st.integers(min_value=1, max_value=65535),
            hostname=SAFE_MANAGED_HOSTNAME,
        )
        def test_managed_service_serialize_deserialize_preserves(
            self, service_id: str, label: str, port: int, hostname: str
        ) -> None:
            import json

            doc = {
                "label": label,
                "enabled": False,
                "runtime": {
                    "type": "quadlet",
                    "source": f"/var/lib/nas-control/apps/{service_id}/app.yaml",
                    "startPolicy": "boot",
                },
                "endpoints": {
                    "api": {
                        "transport": "http",
                        "targetPort": port,
                        "exposure": {"type": "dns", "value": hostname},
                        "auth": {"mode": "public"},
                    }
                },
            }
            msvc.validate_service(service_id, doc)
            encoded = json.dumps(doc, sort_keys=True)
            decoded = json.loads(encoded)
            result = msvc.validate_service(service_id, decoded)
            self.assertEqual(result["label"], label)
            self.assertEqual(result["endpoints"]["api"]["targetPort"], port)

        @settings(max_examples=150, deadline=None)
        @given(
            service_id=st.from_regex(r"[a-z][a-z0-9-]{0,12}", fullmatch=True),
            label=st.text(
                min_size=1,
                max_size=32,
                alphabet=st.characters(min_codepoint=33, max_codepoint=126, blacklist_characters="\x00\r\n/\\"),
            ),
            port=st.integers(min_value=1, max_value=65535),
            hostname=SAFE_MANAGED_HOSTNAME,
            mutate=st.sampled_from(["port_zero", "port_overflow", "bad_hostname", "bad_source"]),
        )
        def test_managed_service_mutated_field_is_rejected(
            self, service_id: str, label: str, port: int, hostname: str, mutate: str
        ) -> None:
            doc = {
                "label": label,
                "enabled": True,
                "runtime": {
                    "type": "compose",
                    "source": f"/var/lib/nas-control/apps/{service_id}/compose.yaml",
                    "startPolicy": "boot",
                },
                "endpoints": {
                    "web": {
                        "transport": "http",
                        "targetPort": port,
                        "exposure": {"type": "hostname", "value": hostname},
                        "auth": {"mode": "public"},
                    }
                },
            }
            msvc.validate_service(service_id, doc)
            if mutate == "port_zero":
                doc["endpoints"]["web"]["targetPort"] = 0  # type: ignore
            elif mutate == "port_overflow":
                doc["endpoints"]["web"]["targetPort"] = 70000  # type: ignore
            elif mutate == "bad_hostname":
                doc["endpoints"]["web"]["exposure"] = {"type": "hostname", "value": "bad host"}  # type: ignore
            elif mutate == "bad_source":
                doc["runtime"]["source"] = "/etc/passwd"  # type: ignore
            with self.assertRaises(msvc.ManagedServiceError):
                msvc.validate_service(service_id, doc)

        @settings(max_examples=120, deadline=None)
        @given(st.from_regex(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,12}", fullmatch=True))
        def test_username_valid_generator_always_accepted(self, username: str) -> None:
            normalized = syncthing_devices.validate_username(username)
            self.assertEqual(normalized, username)
            self.assertRegex(normalized, syncthing_devices.USERNAME_RE)
else:

    @unittest.skip("Hypothesis is not installed; CI runs the property-test tier with it")
    class PropertyInvariantTests(unittest.TestCase):
        def test_hypothesis_tier_placeholder(self) -> None:
            pass


if __name__ == "__main__":
    unittest.main()
