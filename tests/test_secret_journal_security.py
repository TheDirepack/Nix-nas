from __future__ import annotations

import importlib.util
import json
import math
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

SPEC = importlib.util.spec_from_file_location("nas_operation_journal", SERVICES / "nas_operation_journal.py")
assert SPEC and SPEC.loader
journal_module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = journal_module
SPEC.loader.exec_module(journal_module)


class SecretJournalSecurityTests(unittest.TestCase):
    def test_metadata_secret_key_variants_are_redacted_before_disk_write(self) -> None:
        sentinel = "SENTINEL-DO-NOT-PERSIST"
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "operation.json"
            journal = journal_module.OperationJournal.open(
                path,
                workflow="secret-test",
                fingerprint="abc123",
                metadata={
                    "providerApiKey": sentinel,
                    "clientSecret": sentinel,
                    "Authorization": sentinel,
                    "nested": {"refresh-token": sentinel, "safe": "visible"},
                },
            )
            self.assertEqual(journal.value["metadata"]["providerApiKey"], "[redacted]")
            raw = path.read_text(encoding="utf-8")
            self.assertNotIn(sentinel, raw)
            persisted = json.loads(raw)
            self.assertEqual(persisted["metadata"]["nested"]["safe"], "visible")

    def test_step_and_final_results_redact_nested_credentials(self) -> None:
        sentinel = "RESULT-SECRET-SENTINEL"
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "operation.json"
            journal = journal_module.OperationJournal.open(path, workflow="secret-test", fingerprint="abc123")
            journal.start_step("stage")
            journal.complete_step(
                "stage",
                {
                    "provider": "cloud",
                    "credentials": {"apiKey": sentinel, "accessToken": sentinel},
                },
            )
            journal.complete({"result": "ok", "sessionToken": sentinel})
            raw = path.read_text(encoding="utf-8")
            self.assertNotIn(sentinel, raw)
            persisted = json.loads(raw)
            self.assertEqual(
                persisted["steps"]["stage"]["result"]["credentials"],
                "[redacted]",
            )
            self.assertEqual(persisted["result"]["sessionToken"], "[redacted]")

    def test_journal_values_are_bounded_and_strict_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "operation.json"
            journal = journal_module.OperationJournal.open(
                path,
                workflow="secret-test",
                fingerprint="abc123",
                metadata={"output": "x" * 10000, "measurement": math.inf},
            )
            journal.complete_step("safe", {"nan": math.nan, "huge": "y" * 10000})
            raw = path.read_text(encoding="utf-8")
            persisted = json.loads(raw, parse_constant=lambda value: self.fail(f"non-standard JSON constant: {value}"))
            self.assertTrue(persisted["metadata"]["output"].endswith("[truncated]"))
            self.assertEqual(persisted["metadata"]["measurement"], "inf")
            self.assertEqual(persisted["steps"]["safe"]["result"]["nan"], "nan")
            self.assertTrue(persisted["steps"]["safe"]["result"]["huge"].endswith("[truncated]"))

    def test_atomic_write_rejects_unsanitized_nonfinite_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "operation.json"
            with self.assertRaises(ValueError):
                journal_module.atomic_write_json(path, {"bad": math.nan})
            self.assertFalse(path.exists())
            self.assertEqual(list(path.parent.glob(f".{path.name}.*")), [])


if __name__ == "__main__":
    unittest.main()
