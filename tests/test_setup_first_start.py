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

from nas_setup_config import SetupError  # noqa: E402
from nas_setup_first_start import parse_first_start_request, parse_first_start_secrets  # noqa: E402


def valid_request() -> dict:
    return {
        "schemaVersion": 1,
        "jobId": "a" * 24,
        "reservationToken": "b" * 32,
        "config": "/etc/nas-control/setup.json",
        "planDigest": "c" * 64,
        "devices": ["/dev/disk/by-id/example"],
        "allowDestructiveStorage": False,
        "confirmPasswordReapply": False,
        "encryptStorage": True,
    }


class FirstStartRequestContractTests(unittest.TestCase):
    def test_valid_request_keeps_exact_authorized_fields(self) -> None:
        payload = valid_request()
        self.assertEqual(parse_first_start_request(json.dumps(payload)), payload)

    def test_request_rejects_missing_extra_or_incorrect_fields(self) -> None:
        for changed in (
            {k: v for k, v in valid_request().items() if k != "jobId"},
            {**valid_request(), "unexpected": True},
            {**valid_request(), "schemaVersion": 2},
            {**valid_request(), "reservationToken": "wrong"},
            {**valid_request(), "jobId": "wrong"},
            {**valid_request(), "config": "../relative.json"},
            {**valid_request(), "planDigest": "wrong"},
            {**valid_request(), "devices": ["dev", "dev"]},
            {**valid_request(), "allowDestructiveStorage": 1},
            {**valid_request(), "encryptStorage": "true"},
        ):
            with self.subTest(changed=changed):
                with self.assertRaises(SetupError):
                    parse_first_start_request(json.dumps(changed))

    def test_invalid_request_releases_a_valid_preexisting_reservation(self) -> None:
        import nas_setup as setup

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            request_path = root / "request.json"
            password_path = root / "password.json"
            request_path.write_text(
                json.dumps({**valid_request(), "planDigest": "wrong"}),
                encoding="utf-8",
            )
            request_path.chmod(0o600)
            password_path.write_text("{}", encoding="utf-8")
            password_path.chmod(0o600)
            with (
                mock.patch.object(setup, "STATE_PATH", root / "state.json"),
                mock.patch.object(setup, "cancel_reservation") as cancel,
            ):
                with self.assertRaisesRegex(SetupError, "plan digest"):
                    setup.run_first_start_job(request_path, password_path)
            cancel.assert_called_once_with("b" * 32)
            self.assertFalse(request_path.exists())
            self.assertFalse(password_path.exists())

    def test_bad_json_and_non_mapping_are_rejected(self) -> None:
        for text in ("not-json", "[]", "null"):
            with self.subTest(text=text), self.assertRaises(SetupError):
                parse_first_start_request(text)

    def test_rejected_worker_request_records_failure_without_running_setup(self) -> None:
        import nas_setup as setup

        for field, value in (
            ("config", "relative.json"),
            ("planDigest", "invalid"),
            ("devices", ["duplicate", "duplicate"]),
            ("allowDestructiveStorage", 1),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                root = pathlib.Path(tmp)
                request_path = root / "request.json"
                password_path = root / "password.json"
                request_path.write_text(json.dumps({**valid_request(), field: value}), encoding="utf-8")
                password_path.write_text("SECRET-MUST-NOT-BE-PERSISTED", encoding="utf-8")
                request_path.chmod(0o600)
                password_path.chmod(0o600)
                with (
                    mock.patch.object(setup, "STATE_PATH", root / "state.json"),
                    mock.patch.object(setup, "cancel_reservation") as cancel,
                    mock.patch.object(setup, "first_run") as first_run,
                    self.assertRaises(SetupError),
                ):
                    setup.run_first_start_job(request_path, password_path)
                result_path = root / "jobs" / ("a" * 24 + ".json")
                self.assertTrue(result_path.exists(), "rejected worker remains pending without a job result")
                result = json.loads(result_path.read_text(encoding="utf-8"))
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["jobId"], "a" * 24)
                self.assertIn("error", result)
                self.assertNotIn("SECRET-MUST-NOT-BE-PERSISTED", result_path.read_text(encoding="utf-8"))
                self.assertEqual(result_path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(result_path.parent.stat().st_mode & 0o777, 0o700)
                first_run.assert_not_called()
                cancel.assert_called_once_with("b" * 32)
                self.assertFalse(request_path.exists())
                self.assertFalse(password_path.exists())

    def test_invalid_job_identifiers_never_select_a_result_path(self) -> None:
        import nas_setup as setup

        for job_id in ("../escape", "a" * 25, "A" * 24, None):
            with self.subTest(job_id=job_id), tempfile.TemporaryDirectory() as tmp:
                root = pathlib.Path(tmp)
                request_path = root / "request.json"
                password_path = root / "password.json"
                request_path.write_text(json.dumps({**valid_request(), "jobId": job_id}), encoding="utf-8")
                password_path.write_text("{}", encoding="utf-8")
                request_path.chmod(0o600)
                password_path.chmod(0o600)
                with (
                    mock.patch.object(setup, "STATE_PATH", root / "state.json"),
                    mock.patch.object(setup, "cancel_reservation") as cancel,
                    mock.patch.object(setup, "first_run") as first_run,
                    self.assertRaisesRegex(SetupError, "identifier"),
                ):
                    setup.run_first_start_job(request_path, password_path)
                self.assertEqual(list(root.rglob("*.json")), [])
                first_run.assert_not_called()
                cancel.assert_called_once_with("b" * 32)

    def test_secrets_reject_shape_and_password_failures(self) -> None:
        admin = {"username": "admin", "name": "Administrator", "email": "admin@example.test", "password": "secret"}
        self.assertEqual(
            parse_first_start_secrets(json.dumps({"keepass": "valid-secret", "administrator": admin})),
            ("valid-secret", admin),
        )
        for payload in (
            {"keepass": None, "administrator": admin},
            {"keepass": "", "administrator": admin},
            {"keepass": "secret", "administrator": {"username": "admin"}},
            {"keepass": "secret", "administrator": admin, "unknown": 1},
        ):
            with self.subTest(payload=payload), self.assertRaises(SetupError):
                parse_first_start_secrets(json.dumps(payload))
        with self.assertRaises(SetupError):
            parse_first_start_secrets("[]")


if __name__ == "__main__":
    unittest.main()
