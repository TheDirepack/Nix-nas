from __future__ import annotations

import contextlib
import io
import importlib
import pathlib
import re
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))
sys.path.insert(0, str(ROOT / "tests"))

from adversarial_payloads import (
    ALL_TEXT_PAYLOADS,
    CONTROL_PAYLOADS,
    PATH_PAYLOADS,
    SHELL_PAYLOADS,
    SQL_PAYLOADS,
    XSS_PAYLOADS,
)
from fuzz_harness import DEFAULT_CASES, json_texts, json_values, mutate_text

common = importlib.import_module("nas_common")
setup_config = importlib.import_module("nas_setup_config")
syncthing = importlib.import_module("nas_syncthing_devices")
state = importlib.import_module("nas_state")
api = importlib.import_module("nas_cockpit_api")
alerts = importlib.import_module("nas_alert_router")
identity = importlib.import_module("nas_identity_model")


class DeterministicBoundaryFuzzTests(unittest.TestCase):
    def test_group_header_parser_is_bounded_and_control_character_fail_closed(self):
        for raw in mutate_text(["nas_users", "nas_admin,nas_allow_files", *CONTROL_PAYLOADS], seed=22011):
            with self.subTest(raw=raw[:80]):
                with contextlib.redirect_stderr(io.StringIO()):
                    groups = common.split_groups(raw)
                self.assertLessEqual(len(groups), common.MAX_GROUPS)
                for name in groups:
                    self.assertLessEqual(len(name), common.MAX_GROUP_NAME_LENGTH)
                    self.assertFalse(any(ord(character) < 32 or ord(character) == 127 for character in name))
                if any(ord(character) < 32 or ord(character) == 127 for character in raw):
                    self.assertEqual(groups, set())

    def test_usernames_never_escape_the_declared_identifier_grammar(self):
        corpus = ["alice", "operator", *ALL_TEXT_PAYLOADS]
        for raw in mutate_text(corpus, seed=22012):
            with self.subTest(raw=raw[:80]):
                try:
                    accepted = syncthing.validate_username(raw)
                except syncthing.DeviceError:
                    continue
                self.assertEqual(accepted, raw)
                self.assertRegex(accepted, syncthing.USERNAME_RE)

    def test_cockpit_feature_argument_never_accepts_shell_or_path_injection(self):
        for raw in mutate_text(["ai", "syncthing", *SHELL_PAYLOADS, *PATH_PAYLOADS], seed=22013):
            with self.subTest(raw=raw[:80]):
                try:
                    accepted = api.validate_argument(raw, api.FEATURE_RE, "feature identifier")
                except api.ApiError:
                    continue
                self.assertLessEqual(len(accepted), api.MAX_ARGUMENT_LENGTH)
                self.assertIsNotNone(api.FEATURE_RE.fullmatch(accepted))
                self.assertNotRegex(accepted, r"[\\/;|&$`\s]")

    def test_secret_line_normalization_never_returns_multiline_or_nul_data(self):
        for raw in mutate_text(["secret", *ALL_TEXT_PAYLOADS], seed=22014):
            with self.subTest(raw=raw[:80]):
                try:
                    accepted = setup_config.normalize_secret_line(raw, "fuzz secret")
                except setup_config.SetupError:
                    continue
                self.assertTrue(accepted)
                self.assertNotIn("\x00", accepted)
                self.assertNotIn("\r", accepted)
                self.assertNotIn("\n", accepted)
                self.assertLessEqual(len(raw), 4098)

    def test_archive_member_parser_never_returns_absolute_or_parent_paths(self):
        for raw in mutate_text(["state/file.json", *PATH_PAYLOADS], seed=22015):
            with self.subTest(raw=raw[:80]):
                try:
                    accepted = state.safe_member_name(raw)
                except state.StateError:
                    continue
                self.assertFalse(accepted.is_absolute())
                self.assertNotIn("..", accepted.parts)
                self.assertNotIn("", accepted.parts)
                self.assertFalse(any(ord(character) < 32 or ord(character) == 127 for character in accepted.as_posix()))
                self.assertLessEqual(len(accepted.as_posix().encode("utf-8")), state.MAX_ARCHIVE_MEMBER_NAME_BYTES)

    def test_syncthing_device_decoder_has_only_expected_failure_modes(self):
        for raw in mutate_text(
            [
                '{"deviceID":"AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA"}',
                *ALL_TEXT_PAYLOADS,
            ],
            seed=22016,
        ):
            with self.subTest(raw=raw[:80]):
                try:
                    device = syncthing.normalize_device(raw)
                except syncthing.DeviceError:
                    continue
                self.assertRegex(device["deviceID"], syncthing.DEVICE_ID_RE)
                self.assertLessEqual(len(device["name"]), syncthing.MAX_DEVICE_NAME)
                self.assertLessEqual(len(device["addresses"]), syncthing.MAX_ADDRESSES)

    def test_alert_normalization_never_reflects_unbounded_attacker_text(self):
        for text in mutate_text(["alert", *SQL_PAYLOADS, *XSS_PAYLOADS], seed=22017):
            raw = {
                "labels": {"alertname": text, "severity": text},
                "annotations": {"summary": text, "description": text},
                "startsAt": "2026-08-06T12:00:00Z",
            }
            with self.subTest(text=text[:80]):
                try:
                    alert = alerts.normalize_alert(raw)
                except alerts.AlertRouterError:
                    continue
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

    def test_setup_config_fuzz_never_returns_unsafe_account_identifiers(self):
        for value in json_values(seed=22018):
            raw = {"schemaVersion": 1, "storage": {"createPool": False}, "accounts": value, "features": {}}
            try:
                normalized = setup_config.normalize_config(raw)
            except (setup_config.SetupError, TypeError, ValueError):
                continue
            for account in normalized["accounts"]:
                self.assertRegex(account["username"], syncthing.USERNAME_RE)

    def test_identity_model_rejects_or_normalizes_fuzzed_usernames(self):
        for username in mutate_text(["alice", *ALL_TEXT_PAYLOADS], seed=22019):
            raw = {"groups": [], "users": [{"pk": "1", "username": username, "is_active": True}]}
            try:
                model = identity.build_model(raw)
            except identity.SyncError:
                continue
            self.assertTrue(all(re.fullmatch(syncthing.USERNAME_RE, user.uid) for user in model.users))

    def test_json_text_fuzzer_is_deterministic_and_bounded(self):
        first = list(json_texts(seed=91, cases=min(DEFAULT_CASES, 64)))
        second = list(json_texts(seed=91, cases=min(DEFAULT_CASES, 64)))
        self.assertEqual(first, second)
        self.assertTrue(all(len(value.encode("utf-8")) < 65536 for value in first))


if __name__ == "__main__":
    unittest.main()
