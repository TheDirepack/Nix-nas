from __future__ import annotations

import pathlib
import importlib.util
import subprocess
import tempfile
import unittest
from unittest import mock

from tests import test_fuzz_custom_inputs as inputs
from tests import test_fuzz_boundaries as boundaries
from tests import slow_managed_service_stateful as stateful
from tests import test_runner_accounting as inventory


class TestingOracleTests(unittest.TestCase):
    def test_inventory_validator_requires_discoverable_python_test_candidates(self):
        path = pathlib.Path(__file__).parents[1] / "scripts/validate-test-inventory.py"
        spec = importlib.util.spec_from_file_location("test_inventory_gate", path)
        assert spec and spec.loader
        validator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(validator)
        with tempfile.TemporaryDirectory() as raw:
            test = pathlib.Path(raw) / "test_empty.py"
            test.write_text("# nas_v2_activation\n")
            with self.assertRaises(SystemExit):
                validator.require_test_cases(test)
            test.write_text(
                "import unittest\nclass Tests(unittest.TestCase):\n def test_behavior(self):\n  self.assertTrue(True)\n"
            )
            validator.require_test_cases(test)

    def test_installed_rejection_oracle_rejects_wrong_exit_and_diagnostic(self):
        spec = importlib.util.spec_from_file_location(
            "installed_rejections", pathlib.Path(__file__).parent / "vm/adversarial-installed.py"
        )
        assert spec and spec.loader
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        for code, message in (
            (1, "permission denied"),
            (2, "permission denied"),
            (126, "usage"),
            (127, "usage"),
            (137, "usage"),
        ):
            with (
                self.subTest(code=code, message=message),
                mock.patch.object(
                    runner.subprocess, "run", return_value=subprocess.CompletedProcess([], code, "", message)
                ),
                self.assertRaises(RuntimeError),
            ):
                runner.run(["command"], allowed={2}, diagnostic="usage")

    def test_hostile_compiler_property_detects_always_allow(self):
        inner = inputs.CustomInputSurfaceFuzzTests.test_v2_document_compilation_rejects_hostile_service_fields.hypothesis.inner_test
        with mock.patch.object(inputs.v2_spec, "compile_document", return_value={}):
            with self.assertRaises(AssertionError):
                inner(inputs.CustomInputSurfaceFuzzTests(), "\x00invalid")

    def test_compiler_property_does_not_swallow_unexpected_runtime_failure(self):
        inner = inputs.CustomInputSurfaceFuzzTests.test_v2_document_compilation_rejects_hostile_service_fields.hypothesis.inner_test
        with mock.patch.object(inputs.v2_spec, "compile_document", side_effect=RuntimeError("broken")):
            with self.assertRaisesRegex(RuntimeError, "broken"):
                inner(inputs.CustomInputSurfaceFuzzTests(), "\x00invalid")

    def test_account_property_reaches_account_validator(self):
        inner = boundaries.StructuredBoundaryFuzzTests.test_setup_config_never_returns_unsafe_account_identifiers.hypothesis.inner_test  # pyright: ignore[reportAttributeAccessIssue]
        original = boundaries.setup_config.normalize_account
        with (
            mock.patch.object(boundaries, "event"),
            mock.patch.object(boundaries, "target"),
            mock.patch.object(boundaries.setup_config, "normalize_account", wraps=original) as normalize,
        ):
            inner(boundaries.StructuredBoundaryFuzzTests(), [{"username": "../invalid"}])
        normalize.assert_called_once()

    def test_rejected_document_oracle_detects_mutation_of_the_actual_input(self):
        machine = stateful.ManagedServiceStateMachine()

        def mutate(document, schema):
            document["services"].clear()
            raise stateful.v2.ManagedServicesV2Error("invalid route")

        with mock.patch.object(stateful.v2, "compile_document", side_effect=mutate):
            with self.assertRaises(AssertionError):
                machine.rejected_document_preserves_model()

    def test_inventory_rejects_comment_only_coverage_claim(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            (root / "test_empty.py").write_text("# nas_v2_activation\n")
            with (
                mock.patch.object(inventory, "ROOT", root),
                mock.patch.object(
                    inventory,
                    "_python_module_contracts",
                    return_value={"services/nas_v2_activation.py": ["test_empty.py"]},
                ),
            ):
                with self.assertRaises(AssertionError):
                    inventory.RunnerAccountingTests().test_python_modules_mapping_has_real_import()


if __name__ == "__main__":
    unittest.main()
