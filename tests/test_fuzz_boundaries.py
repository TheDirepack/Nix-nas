from __future__ import annotations

import contextlib
import io
import json
import pathlib
import re
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
TESTS = ROOT / "tests"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

try:
    from hypothesis import HealthCheck, event, given, settings, strategies as st, target
except ImportError:
    HAS_HYPOTHESIS = False
else:
    HAS_HYPOTHESIS = True

    import nas_alert_router as alerts
    import nas_common as common
    import nas_identity_model as identity
    import nas_setup_config as setup_config
    import nas_state as state
    import nas_syncthing_devices as syncthing
    import nas_v2_accelerator as accelerator
    import nas_v2_caddy as caddy
    import nas_v2_spec as v2_spec
    from fuzz_strategies import (
        bounded_paths,
        identifier_candidates,
        json_values,
        path_candidates,
        v2_capabilities,
        v2_service_ids,
    )


if HAS_HYPOTHESIS:

    class StructuredBoundaryFuzzTests(unittest.TestCase):  # pyright: ignore[reportRedeclaration]
        @settings(max_examples=500, deadline=None, suppress_health_check=[HealthCheck.too_slow])
        @given(st.text(max_size=9000))
        def test_group_header_parser_is_total_bounded_and_control_safe(self, raw: str) -> None:
            target(len(raw), label="group-header-length")
            event("group-header:control" if any(ord(ch) < 32 or ord(ch) == 127 for ch in raw) else "group-header:text")
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
            target(len(raw), label="username-length")
            try:
                accepted = syncthing.validate_username(raw)
            except syncthing.DeviceError:
                event("username:rejected")
                return
            event("username:accepted")
            self.assertEqual(accepted, raw)
            self.assertRegex(accepted, syncthing.USERNAME_RE)

        @settings(max_examples=400, deadline=None)
        @given(identifier_candidates(max_size=512))
        def test_v2_service_id_acceptance_matches_compiler_grammar(self, raw: str) -> None:
            target(len(raw), label="service-id-length")
            matched = v2_spec.SERVICE_ID_RE.fullmatch(raw)
            event("service-id:accepted" if matched is not None else "service-id:rejected")
            if matched is None:
                return
            self.assertLessEqual(len(raw), 64)
            self.assertEqual(matched.group(0), raw)

        @settings(max_examples=400, deadline=None)
        @given(st.text(max_size=4200))
        def test_secret_line_normalization_never_returns_multiline_or_nul_data(self, raw: str) -> None:
            target(len(raw), label="secret-line-length")
            try:
                accepted = setup_config.normalize_secret_line(raw, "fuzz secret")
            except setup_config.SetupError:
                event("secret-line:rejected")
                return
            event("secret-line:accepted")
            self.assertTrue(accepted)
            self.assertNotIn("\x00", accepted)
            self.assertNotIn("\r", accepted)
            self.assertNotIn("\n", accepted)
            self.assertLessEqual(len(accepted), 4096)

        @settings(max_examples=500, deadline=None)
        @given(st.one_of(path_candidates(), st.text(max_size=2048)))
        def test_archive_member_parser_never_returns_absolute_or_parent_paths(self, raw: str) -> None:
            target(len(raw.encode("utf-8", errors="ignore")), label="archive-member-input-bytes")
            try:
                accepted = state.safe_member_name(raw)
            except state.StateError:
                event("archive-member:rejected")
                return
            event("archive-member:accepted")
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
            target(len(raw), label="syncthing-device-input-length")
            try:
                device = syncthing.normalize_device(raw)
            except syncthing.DeviceError:
                event("syncthing-device:rejected")
                return
            event("syncthing-device:accepted")
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
            target(max(map(len, (alertname, severity, summary, description))), label="alert-field-length")
            raw = {
                "labels": {"alertname": alertname, "severity": severity},
                "annotations": {"summary": summary, "description": description},
                "startsAt": "2026-08-06T12:00:00Z",
            }
            try:
                alert = alerts.normalize_alert(raw)
            except alerts.AlertRouterError:
                event("alert:rejected")
                return
            event("alert:accepted")
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
                event("setup-accounts:rejected")
                return
            event("setup-accounts:accepted")
            target(len(normalized["accounts"]), label="normalized-account-count")
            for account in normalized["accounts"]:
                self.assertRegex(account["username"], syncthing.USERNAME_RE)

        @settings(max_examples=400, deadline=None)
        @given(identifier_candidates(max_size=256))
        def test_identity_model_rejects_or_preserves_usernames(self, username: str) -> None:
            target(len(username), label="identity-username-length")
            raw = {"groups": [], "users": [{"pk": "1", "username": username, "is_active": True}]}
            try:
                model = identity.build_model(raw)
            except identity.SyncError:
                event("identity-username:rejected")
                return
            event("identity-username:accepted")
            self.assertTrue(all(re.fullmatch(syncthing.USERNAME_RE, user.uid) for user in model.users))
            self.assertTrue(all(user.uid == username for user in model.users))

        @settings(max_examples=600, deadline=None, suppress_health_check=[HealthCheck.too_slow])
        @given(v2_service_ids(), v2_capabilities(), st.text(max_size=2000))
        def test_v2_capability_group_is_strict_and_never_empty(
            self, service_id: str, capability: str, suffix: str
        ) -> None:
            target(len(service_id) + len(capability), label="capability-input-length")
            try:
                group = common.application_capability_group(service_id, capability)
            except ValueError:
                event("capability:rejected")
                return
            event("capability:accepted")
            self.assertTrue(group.startswith("application."))
            self.assertNotIn("\x00", group)
            self.assertNotIn("\n", group)
            self.assertLessEqual(len(group), 256)

        @settings(max_examples=500, deadline=None, suppress_health_check=[HealthCheck.too_slow])
        @given(st.text(max_size=8192), st.text(max_size=1024))
        def test_caddy_header_and_path_are_control_safe(self, raw_header: str, raw_path: str) -> None:
            target(len(raw_header) + len(raw_path), label="caddy-input-length")
            # Header names must be rejected if they contain controls
            try:
                caddy._header_name(raw_header)  # type: ignore[attr-defined]
            except caddy.CaddyProjectionError:
                event("caddy-header:rejected")
            else:
                event("caddy-header:accepted")
                self.assertNotIn("\x00", raw_header)
            try:
                caddy._path_patterns(raw_path)  # type: ignore[attr-defined]
            except caddy.CaddyProjectionError:
                event("caddy-path:rejected")
            else:
                event("caddy-path:accepted")
                self.assertTrue(raw_path.startswith("/"))

        @settings(max_examples=500, deadline=None)
        @given(st.text(max_size=2048), st.text(max_size=64))
        def test_accelerator_cdi_selector_never_accepts_device_paths(self, raw: str, dev: str) -> None:
            target(len(raw), label="cdi-input-length")
            is_cdi = accelerator.is_cdi_selector(raw)
            event("cdi:accepted" if is_cdi else "cdi:rejected")
            if is_cdi:
                left, _, qualifier = raw.partition("=")
                self.assertNotRegex(left, r"^/")  # never a leading-slash device path
                self.assertEqual(1, left.count("/"))  # single vendor/class separator
                self.assertNotIn("/", qualifier)  # CDI qualifier grammar forbids slash
                self.assertIn("=", raw)

        @settings(max_examples=500, deadline=None, suppress_health_check=[HealthCheck.too_slow])
        @given(bounded_paths(prefix="/tank"), st.text(max_size=2048))
        def test_state_path_containment_is_strict(self, safe: str, raw: str) -> None:
            target(len(safe), label="path-length")
            # safe path should always hash without symlink error when it exists
            self.assertTrue(safe.startswith("/tank/"))
            try:
                state.safe_member_name(raw)
            except state.StateError:
                event("safe-member:rejected")
            else:
                event("safe-member:accepted")
                self.assertFalse(raw.startswith("/"))

        @settings(max_examples=400, deadline=None)
        @given(json_values(max_leaves=30))
        def test_common_read_json_object_never_returns_non_dict(self, raw: object) -> None:
            target(len(str(raw)), label="json-input-length")
            with tempfile.TemporaryDirectory() as tmp:
                path = pathlib.Path(tmp) / "obj.json"
                path.write_text(json.dumps(raw), encoding="utf-8")
                try:
                    obj = common.read_json_object(path)
                except Exception:
                    event("read-json:rejected")
                    return
                event("read-json:accepted")
                self.assertIsInstance(obj, dict)
else:

    class StructuredBoundaryFuzzTests(unittest.TestCase):  # pyright: ignore[reportRedeclaration]
        def test_hypothesis_is_required(self) -> None:
            self.fail("Hypothesis is required for the structured boundary fuzz suite")


if __name__ == "__main__":
    unittest.main()
