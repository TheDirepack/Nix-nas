from __future__ import annotations

import json
import pathlib
import sys
import unittest
import urllib.parse

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

try:
    from hypothesis import HealthCheck, event, given, settings, strategies as st, target
except ImportError:
    HAS_HYPOTHESIS = False
else:
    HAS_HYPOTHESIS = True
    import nas_feature_model as feature_model
    import nas_logging
    import nas_managed_service as msvc
    import nas_syncthing_devices as syncthing_devices


if HAS_HYPOTHESIS:
    SAFE_MANAGED_HOSTNAME = st.from_regex(r"[a-z0-9][a-z0-9-]{0,9}\.example\.test", fullmatch=True)
    SAFE_LABEL = st.text(
        min_size=1,
        max_size=32,
        alphabet=st.characters(min_codepoint=33, max_codepoint=126, blacklist_characters="\x00\r\n/\\"),
    )
    SERVICE_ID = st.from_regex(r"[a-z][a-z0-9-]{0,12}", fullmatch=True)

    def managed_document(
        service_id: str,
        label: str,
        port: int,
        hostname: str,
        *,
        runtime_type: str = "compose",
        enabled: bool = True,
    ) -> dict[str, object]:
        return {
            "label": label,
            "enabled": enabled,
            "runtime": {
                "type": runtime_type,
                "source": f"/var/lib/nas-control/apps/{service_id}/app.yaml",
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

    class PropertyInvariantTests(unittest.TestCase):  # pyright: ignore[reportRedeclaration]
        """Structured cross-object properties; parser boundaries and state machines run separately."""

        @settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
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
            encoded = json.dumps(sanitized)
            target(len(encoded), label="sanitized-json-size")
            self.assertLess(len(encoded), 2_000_000)

        @settings(max_examples=400, deadline=None)
        @given(st.one_of(st.text(max_size=4096), st.none(), st.booleans(), st.integers()))
        def test_loopback_http_url_validator_is_total_and_fail_closed(self, value: object) -> None:
            accepted = feature_model.valid_loopback_http_url(value)
            self.assertIsInstance(accepted, bool)
            if not accepted:
                return
            if not isinstance(value, str):
                self.fail("accepted loopback URL is not a string")
            parsed = urllib.parse.urlsplit(value)
            self.assertEqual(parsed.scheme, "http")
            self.assertIn(parsed.hostname, {"127.0.0.1", "localhost", "::1"})
            self.assertIsNone(parsed.username)
            self.assertIsNone(parsed.password)
            self.assertFalse(parsed.fragment)
            if parsed.port is not None:
                self.assertGreater(parsed.port, 0)
                self.assertLess(parsed.port, 65536)

        @settings(
            max_examples=180,
            deadline=None,
            suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
        )
        @given(
            service_id=SERVICE_ID,
            label=SAFE_LABEL,
            port=st.integers(min_value=1, max_value=65535),
            hostname=SAFE_MANAGED_HOSTNAME,
        )
        def test_managed_service_valid_doc_is_accepted(
            self, service_id: str, label: str, port: int, hostname: str
        ) -> None:
            doc = managed_document(service_id, label, port, hostname)
            result = msvc.validate_service(service_id, doc)
            self.assertEqual(result, doc)

        @settings(max_examples=180, deadline=None, suppress_health_check=[HealthCheck.too_slow])
        @given(
            service_id=SERVICE_ID,
            label=SAFE_LABEL,
            port=st.integers(min_value=1, max_value=65535),
            hostname=SAFE_MANAGED_HOSTNAME,
            runtime_type=st.sampled_from(["compose", "quadlet"]),
            enabled=st.booleans(),
        )
        def test_managed_service_json_round_trip_preserves_semantics(
            self,
            service_id: str,
            label: str,
            port: int,
            hostname: str,
            runtime_type: str,
            enabled: bool,
        ) -> None:
            doc = managed_document(
                service_id,
                label,
                port,
                hostname,
                runtime_type=runtime_type,
                enabled=enabled,
            )
            before = msvc.validate_service(service_id, doc)
            encoded = json.dumps(before, sort_keys=True)
            after = msvc.validate_service(service_id, json.loads(encoded))
            self.assertEqual(after, before)

        @settings(max_examples=220, deadline=None)
        @given(
            service_id=SERVICE_ID,
            label=SAFE_LABEL,
            port=st.integers(min_value=1, max_value=65535),
            hostname=SAFE_MANAGED_HOSTNAME,
            mutate=st.sampled_from(["port_zero", "port_overflow", "bad_hostname", "bad_source"]),
        )
        def test_managed_service_invalid_mutation_is_rejected(
            self, service_id: str, label: str, port: int, hostname: str, mutate: str
        ) -> None:
            doc = managed_document(service_id, label, port, hostname)
            msvc.validate_service(service_id, doc)
            event(f"mutation:{mutate}")
            endpoints = doc["endpoints"]
            runtime = doc["runtime"]
            assert isinstance(endpoints, dict) and isinstance(runtime, dict)
            web = endpoints["web"]
            assert isinstance(web, dict)
            if mutate == "port_zero":
                web["targetPort"] = 0
            elif mutate == "port_overflow":
                web["targetPort"] = 70000
            elif mutate == "bad_hostname":
                web["exposure"] = {"type": "hostname", "value": "bad host"}
            else:
                runtime["source"] = "/etc/passwd"
            with self.assertRaises(msvc.ManagedServiceError):
                msvc.validate_service(service_id, doc)

        @settings(max_examples=180, deadline=None)
        @given(st.from_regex(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,32}", fullmatch=True))
        def test_valid_username_generator_is_sound(self, username: str) -> None:
            normalized = syncthing_devices.validate_username(username)
            self.assertEqual(normalized, username)
            self.assertRegex(normalized, syncthing_devices.USERNAME_RE)
else:

    @unittest.skip("Hypothesis is not installed; CI runs the property-test tier with it")
    class PropertyInvariantTests(unittest.TestCase):  # pyright: ignore[reportRedeclaration]
        def test_hypothesis_tier_placeholder(self) -> None:
            pass


if __name__ == "__main__":
    unittest.main()
