from __future__ import annotations

import json
import pathlib
import sys
import unittest

from maintainer_test_base import MaintainerScriptMixin


class MaintainerCoreTests(MaintainerScriptMixin, unittest.TestCase):
    def test_repository_validators_execute_individually(self) -> None:
        commands = (
            (sys.executable, "scripts/check-version.py"),
            (sys.executable, "scripts/check-mkforce.py"),
            (sys.executable, "scripts/validate-repository-data.py"),
            (sys.executable, "scripts/validate-doc-links.py"),
            (sys.executable, "scripts/validate-python-syntax.py"),
            (sys.executable, "scripts/validate-test-inventory.py"),
            (sys.executable, "scripts/security-static-scan.py"),
            (sys.executable, "scripts/validate-structure.py"),
        )
        for command in commands:
            with self.subTest(command=command[1]):
                result = self.run_clean(*command)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_cockpit_source_builder_check_executes_without_dependencies(self) -> None:
        result = self.run_clean("node", "cockpit/build.js", "--check-source")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        rejected = self.run_clean("node", "cockpit/build.js", "hostile;$(touch /tmp/nas-build-pwned)")
        self.assertEqual(rejected.returncode, 2)
        self.assertIn("Usage:", rejected.stderr)
        self.assertFalse(pathlib.Path("/tmp/nas-build-pwned").exists())

    def test_coverage_checker_accepts_floor_and_rejects_regression(self) -> None:
        checker = self.clean_root / "scripts/check-coverage.py"
        namespace: dict[str, object] = {"__name__": "coverage_constants"}
        exec(compile(checker.read_text(encoding="utf-8"), str(checker), "exec"), namespace)
        floors = namespace["FLOORS"]
        total_floor_raw = namespace["TOTAL_FLOOR"]
        assert isinstance(total_floor_raw, (int, float))
        total_floor = float(total_floor_raw)
        assert isinstance(floors, dict)
        report = pathlib.Path(self._temporary.name) / "synthetic-coverage.json"
        passing = {
            "files": {path: {"summary": {"percent_covered": float(floor)}} for path, floor in floors.items()},
            "totals": {"percent_covered": total_floor},
        }
        report.write_text(json.dumps(passing), encoding="utf-8")
        result = self.run_clean(sys.executable, "scripts/check-coverage.py", str(report))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        first = next(iter(floors))
        passing["files"][first]["summary"]["percent_covered"] = 0
        report.write_text(json.dumps(passing), encoding="utf-8")
        result = self.run_clean(sys.executable, "scripts/check-coverage.py", str(report))
        self.assertEqual(result.returncode, 1)
        self.assertIn(first, result.stdout)

    def test_coverage_run_preserves_committed_configuration(self) -> None:
        config = self.clean_root / ".coveragerc"
        before = config.read_bytes()
        result = self.run_clean(
            sys.executable,
            "scripts/run-unit-tests.py",
            "--quiet",
            "--coverage",
            "coverage.json",
            "--pattern",
            "test_comment_policy.py",
            timeout=90,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(config.is_file())
        self.assertEqual(config.read_bytes(), before)
        for generated in (self.clean_root / "coverage.json", self.clean_root / ".coverage"):
            generated.unlink(missing_ok=True)
        for generated in self.clean_root.glob(".coverage.*"):
            generated.unlink(missing_ok=True)

    def test_isolated_unit_runner_and_compatibility_wrapper_are_bounded(self) -> None:
        runner = (self.clean_root / "scripts/run-unit-tests.py").read_text(encoding="utf-8")
        wrapper = (self.clean_root / "scripts/test-runtime-renderers.py").read_text(encoding="utf-8")
        self.assertIn("subprocess.TimeoutExpired", runner)
        self.assertIn("default=180", runner)
        self.assertIn("SERIAL_TEST_FILES", runner)
        self.assertIn("test_contract_tooling.py", runner)
        self.assertIn("test_maintainer_core.py", runner)
        self.assertIn("test_maintainer_matrix.py", runner)
        self.assertIn("test_maintainer_release.py", runner)
        self.assertIn('"--parallel-mode"', runner)
        self.assertIn('"run-unit-tests.py"', wrapper)
        help_result = self.run_clean(sys.executable, "scripts/run-unit-tests.py", "--help")
        self.assertEqual(help_result.returncode, 0, help_result.stdout + help_result.stderr)

    def test_jsx_validator_has_a_dependency_failure_path_not_silent_success(self) -> None:
        source = (self.clean_root / "scripts/validate-cockpit-jsx.cjs").read_text(encoding="utf-8")
        self.assertIn('require("typescript")', source)
        self.assertIn("process.exit(1)", source)
        self.assertIn("reportDiagnostics: true", source)
