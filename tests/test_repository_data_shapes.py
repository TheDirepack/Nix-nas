from __future__ import annotations

import copy
import importlib.util
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/validate-repository-data.py"
VERSIONS = {
    "schemas/managed-services-v3.schema.json": 3,
    "schemas/first-run.schema.json": 2,
    "schemas/account-plan.schema.json": 1,
    "schemas/state-bundle.schema.json": 2,
}
FIRST = "schemas/managed-services-v3.schema.json"
LAST = "schemas/state-bundle.schema.json"


def schema(version: int = 3) -> dict:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": False,
        "properties": {"schemaVersion": {"const": version}},
    }


class RepositoryDataShapeTests(unittest.TestCase):
    def run_fixture(
        self, changes: dict | None = None, *, book: str = '[book]\ntitle = "Fixture"\n', raw_json: bool = False
    ) -> subprocess.CompletedProcess[str]:
        spec = importlib.util.spec_from_file_location("repository_data_fixture", SCRIPT)
        assert spec is not None and spec.loader is not None
        validator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(validator)
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            (root / "scripts").mkdir()
            shutil.copy2(SCRIPT, root / "scripts" / SCRIPT.name)
            (root / "docs").mkdir()
            (root / "docs/book.toml").write_text(book)
            values = {
                relative: schema(VERSIONS[relative]) if relative in VERSIONS else {}
                for relative in validator.JSON_FILES
            }
            values.update(changes or {})
            for relative, value in values.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("{broken" if raw_json and relative == FIRST else json.dumps(value))
            return subprocess.run(
                [sys.executable, str(root / "scripts" / SCRIPT.name)],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

    def assert_file_error(self, result: subprocess.CompletedProcess[str], relative: str = FIRST) -> None:
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(relative + ": ", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_nonobject_schema_top_levels_have_file_diagnostics(self) -> None:
        for value in ([], None, "fixture", True, 42):
            with self.subTest(value=value):
                self.assert_file_error(self.run_fixture({FIRST: value}))

    def test_nonobject_schema_top_level_error_message_is_specific(self) -> None:
        for value, expected in (
            ([], "schema must be a JSON object"),
            (None, "schema must be a JSON object"),
            ("fixture", "schema must be a JSON object"),
            (True, "schema must be a JSON object"),
            (42, "schema must be a JSON object"),
        ):
            with self.subTest(value=value):
                result = self.run_fixture({FIRST: value})
                self.assert_file_error(result)
                self.assertIn(expected, result.stderr)

    def test_nonobject_properties_error_message_is_specific(self) -> None:
        for value, expected in (
            ([], "schema properties must be a JSON object"),
            (None, "schema properties must be a JSON object"),
            ("fixture", "schema properties must be a JSON object"),
            (True, "schema properties must be a JSON object"),
            (42, "schema properties must be a JSON object"),
        ):
            with self.subTest(value=value):
                result = self.run_fixture({FIRST: {**schema(), "properties": value}})
                self.assert_file_error(result)
                self.assertIn(expected, result.stderr)

    def test_nonobject_schema_version_def_error_message_is_specific(self) -> None:
        for value, expected in (
            ([], "schemaVersion schema must be a JSON object"),
            (None, "schemaVersion schema must be a JSON object"),
            ("fixture", "schemaVersion schema must be a JSON object"),
            (True, "schemaVersion schema must be a JSON object"),
            (42, "schemaVersion schema must be a JSON object"),
        ):
            with self.subTest(value=value):
                result = self.run_fixture({FIRST: {**schema(), "properties": {"schemaVersion": value}}})
                self.assert_file_error(result)
                self.assertIn(expected, result.stderr)

    def test_nonobject_properties_have_file_diagnostics(self) -> None:
        for value in ([], None, "fixture", True, 42):
            with self.subTest(value=value):
                self.assert_file_error(self.run_fixture({FIRST: {**schema(), "properties": value}}))

    def test_nonobject_schema_version_definitions_have_file_diagnostics(self) -> None:
        for value in ([], None, "fixture", True, 42):
            with self.subTest(value=value):
                self.assert_file_error(self.run_fixture({FIRST: {**schema(), "properties": {"schemaVersion": value}}}))

    def test_shape_errors_do_not_stop_later_file_validation(self) -> None:
        result = self.run_fixture({FIRST: [], LAST: schema(0)})
        self.assert_file_error(result)
        self.assertIn(LAST + ": ", result.stderr)
        self.assertIn("must require schemaVersion 2", result.stderr)

    def test_invalid_book_shape_does_not_stop_later_file_validation(self) -> None:
        result = self.run_fixture({LAST: schema(0)}, book="book = 3\n")
        self.assert_file_error(result, "docs/book.toml")
        self.assertIn(LAST + ": ", result.stderr)

    def test_schema_contract_rejections_are_preserved(self) -> None:
        for field, value in (("$schema", "wrong-draft"), ("type", "array"), ("additionalProperties", True)):
            with self.subTest(field=field):
                self.assert_file_error(self.run_fixture({FIRST: {**schema(), field: value}}))
        wrong_version = copy.deepcopy(schema())
        wrong_version["properties"]["schemaVersion"]["const"] = 0
        self.assert_file_error(self.run_fixture({FIRST: wrong_version}))
        self.assert_file_error(self.run_fixture(book="[book]\nmultilingual = true\n"), "docs/book.toml")

    def test_json_syntax_errors_still_allow_later_diagnostics(self) -> None:
        result = self.run_fixture({LAST: schema(0)}, raw_json=True)
        self.assert_file_error(result)
        self.assertIn(LAST + ": ", result.stderr)

    def test_valid_data_keeps_a_clean_success_exit(self) -> None:
        result = self.run_fixture()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")
