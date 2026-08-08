from __future__ import annotations

import io
import json
import math
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_logging


class StructuredLoggingTests(unittest.TestCase):
    def test_stable_fields_and_secret_redaction(self) -> None:
        stream = io.StringIO()
        record = nas_logging.log_event(
            "rotation",
            operation_id="op-1",
            workflow="secret-rotation",
            phase="validate",
            result="success",
            duration_ms=12.5,
            stream=stream,
            token="must-not-appear",
            details={"password": "also-secret", "safe": "value"},
        )
        emitted = json.loads(stream.getvalue())
        self.assertEqual(record, emitted)
        self.assertEqual(emitted["operationId"], "op-1")
        self.assertEqual(emitted["token"], "[redacted]")
        self.assertEqual(emitted["details"]["password"], "[redacted]")
        self.assertEqual(emitted["details"]["safe"], "value")

    def test_values_are_bounded(self) -> None:
        stream = io.StringIO()
        emitted = nas_logging.log_event("bounded", stream=stream, output="x" * 5000)
        self.assertLessEqual(len(emitted["output"]), nas_logging.MAX_TEXT_LENGTH + len("[truncated]"))
        self.assertTrue(emitted["output"].endswith("[truncated]"))

    def test_bytes_use_text_policy_and_sensitive_key_policy_is_exact(self) -> None:
        value = nas_logging.sanitize(
            {
                "stdout": b"ok\xff",
                "API-Key": "secret",
                "authorizationMethod": "oidc",
                "authorizationScope": "admin",
                "username": "operator",
                "uid": 1000,
                "gid": 100,
            }
        )
        self.assertEqual(value["stdout"], "ok\ufffd")
        self.assertEqual(value["API-Key"], "[redacted]")
        self.assertEqual(value["authorizationMethod"], "oidc")
        self.assertEqual(value["authorizationScope"], "admin")
        self.assertEqual(value["username"], "operator")
        self.assertEqual(value["uid"], 1000)
        self.assertEqual(value["gid"], 100)

    def test_camel_kebab_dotted_and_snake_secret_names_are_redacted(self) -> None:
        secret = "TOP-SECRET-SENTINEL"
        variants = {
            "clientSecret": secret,
            "accessToken": secret,
            "refreshToken": secret,
            "sessionToken": secret,
            "privateKey": secret,
            "apiKey": secret,
            "providerApiKey": secret,
            "db-password": secret,
            "peer.access.token": secret,
            "nested_secret": secret,
        }
        sanitized = nas_logging.sanitize(variants)
        for key in variants:
            with self.subTest(key=key):
                self.assertEqual(sanitized[key], "[redacted]")
        self.assertNotIn(secret, json.dumps(sanitized))

    def test_nested_secret_keys_are_redacted_at_every_supported_depth(self) -> None:
        sentinel = "SECRET-NEVER-LOG"
        value = {
            "level1": {
                "level2": {
                    "clientSecret": sentinel,
                    "safe": [
                        {"apiKey": sentinel},
                        {"message": "visible"},
                    ],
                }
            }
        }
        sanitized = nas_logging.sanitize(value)
        encoded = json.dumps(sanitized)
        self.assertNotIn(sentinel, encoded)
        self.assertIn("visible", encoded)

    def test_non_finite_numbers_never_emit_nonstandard_json(self) -> None:
        stream = io.StringIO()
        record = nas_logging.log_event(
            "numeric",
            stream=stream,
            metric=math.nan,
            nested={"positive": math.inf, "negative": -math.inf},
            duration_ms=math.inf,
        )
        raw = stream.getvalue()
        self.assertNotIn("NaN", raw)
        self.assertNotIn("Infinity", raw)
        decoded = json.loads(raw, parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
        self.assertEqual(decoded, record)
        self.assertEqual(decoded["durationMs"], 0)

    def test_control_characters_cannot_forge_additional_log_records(self) -> None:
        stream = io.StringIO()
        emitted = nas_logging.log_event(
            "attempt\r\nforged",
            actor="admin\nPRIORITY=0",
            stream=stream,
            details={"safe": "line1\r\nline2", "authorization": "Bearer secret"},
        )
        raw = stream.getvalue()
        self.assertEqual(len(raw.splitlines()), 1)
        decoded = json.loads(raw)
        self.assertEqual(decoded, emitted)
        self.assertEqual(decoded["details"]["authorization"], "[redacted]")
        self.assertIn("\n", decoded["event"])
        self.assertNotIn("Bearer secret", raw)


if __name__ == "__main__":
    unittest.main()
