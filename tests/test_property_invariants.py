from __future__ import annotations

import os
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))

try:
    from hypothesis import HealthCheck, given, settings, strategies as st
except ModuleNotFoundError:  # pragma: no cover - local fallback only
    HealthCheck = None  # type: ignore[assignment]
    given = None  # type: ignore[assignment]
    settings = None  # type: ignore[assignment]
    st = None  # type: ignore[assignment]

import nas_alert_router as alert_router
import nas_feature_control as feature_control
import nas_managed_service as msvc
import nas_state
import nas_syncthing_devices as syncthing_devices


@unittest.skipUnless(given is not None, "Hypothesis is not installed")
class PropertyInvariantTests(unittest.TestCase):
    if given is not None and settings is not None and st is not None and HealthCheck is not None:
        @settings(max_examples=150, deadline=None)
        @given(st.text(max_size=4096))
        def test_feature_token_normalization_is_bounded(self, raw: str) -> None:
            try:
                value = feature_control._normalize_feature_token(raw)
            except ValueError:
                return
            self.assertLessEqual(len(value), feature_control.MAX_FEATURE_LEN)
            self.assertRegex(value, feature_control.FEATURE_RE)

        @settings(max_examples=150, deadline=None)
        @given(st.text(max_size=4096))
        def test_group_normalization_is_bounded(self, raw: str) -> None:
            try:
                value = feature_control._normalize_group_token(raw)
            except ValueError:
                return
            self.assertLessEqual(len(value), feature_control.MAX_GROUP_LEN)
            self.assertRegex(value, feature_control.GROUP_RE)

        @settings(max_examples=120, deadline=None)
        @given(st.binary(max_size=64 * 1024))
        def test_state_json_loader_never_escapes_declared_errors(self, payload: bytes) -> None:
            with self.subTest(size=len(payload)):
                path = pathlib.Path(os.environ.get("TMPDIR", "/tmp")) / "nas-property-state.json"
                try:
                    path.write_bytes(payload)
                    try:
                        value = nas_state.load_json(path, max_bytes=64 * 1024)
                    except nas_state.StateError:
                        return
                    self.assertIsInstance(value, dict)
                finally:
                    path.unlink(missing_ok=True)

        @settings(max_examples=120, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])
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

        valid_local_hostname = st.from_regex(
            r"[a-z0-9](?:[a-z0-9-]{0,8}[a-z0-9])?\.local", fullmatch=True
        )

        @settings(max_examples=120, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])
        @given(
            service_id=st.from_regex(r"[a-z][a-z0-9-]{0,12}", fullmatch=True),
            label=st.text(min_size=1, max_size=32, alphabet=st.characters(min_codepoint=33, max_codepoint=126, blacklist_characters="\x00\r\n/\\")),
            port=st.integers(min_value=1, max_value=65535),
            hostname=valid_local_hostname,
        )
        def test_managed_service_valid_doc_is_accepted(self, service_id: str, label: str, port: int, hostname: str) -> None:
            doc = {
                "label": label,
                "enabled": True,
                "runtime": {"type": "compose", "source": f"/var/lib/nas-control/apps/{service_id}/compose.yaml", "startPolicy": "boot"},
                "endpoints": {
                    "web": {"transport": "http", "targetPort": port, "exposure": {"type": "hostname", "value": hostname}, "auth": {"mode": "public"}}
                },
            }
            result = msvc.validate_service(service_id, doc)
            self.assertEqual(result, doc)

        @settings(max_examples=120, deadline=None, suppress_health_check=[HealthCheck.too_slow])
        @given(
            service_id=st.from_regex(r"[a-z][a-z0-9-]{0,12}", fullmatch=True),
            label=st.text(min_size=1, max_size=32, alphabet=st.characters(min_codepoint=33, max_codepoint=126, blacklist_characters="\x00\r\n/\\")),
            port=st.integers(min_value=1, max_value=65535),
            hostname=valid_local_hostname,
        )
        def test_managed_service_serialize_deserialize_preserves(self, service_id: str, label: str, port: int, hostname: str) -> None:
            import json
            doc = {
                "label": label,
                "enabled": False,
                "runtime": {"type": "quadlet", "source": f"/var/lib/nas-control/apps/{service_id}/app.yaml", "startPolicy": "boot"},
                "endpoints": {
                    "api": {"transport": "http", "targetPort": port, "exposure": {"type": "dns", "value": hostname}, "auth": {"mode": "public"}}
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
            label=st.text(min_size=1, max_size=32, alphabet=st.characters(min_codepoint=33, max_codepoint=126, blacklist_characters="\x00\r\n/\\")),
            port=st.integers(min_value=1, max_value=65535),
            hostname=valid_local_hostname,
            mutate=st.sampled_from(["port_zero", "port_overflow", "bad_hostname", "bad_source"]),
        )
        def test_managed_service_mutated_field_is_rejected(self, service_id: str, label: str, port: int, hostname: str, mutate: str) -> None:
            doc = {
                "label": label,
                "enabled": True,
                "runtime": {"type": "compose", "source": f"/var/lib/nas-control/apps/{service_id}/compose.yaml", "startPolicy": "boot"},
                "endpoints": {
                    "web": {"transport": "http", "targetPort": port, "exposure": {"type": "hostname", "value": hostname}, "auth": {"mode": "public"}}
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
    pass
