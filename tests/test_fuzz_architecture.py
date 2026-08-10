from __future__ import annotations

import ast
import json
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

SMART_FUZZ_FILES = (
    "scripts/fuzz.py",
    "scripts/fuzz-executables.py",
    "scripts/run-fuzz.py",
    "tests/fuzz_strategies.py",
    "tests/test_fuzz_boundaries.py",
    "tests/test_property_invariants.py",
    "tests/test_secret_security_fuzz.py",
    "tests/slow_managed_service_stateful.py",
)


def imported_roots(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    result: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            result.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            result.add(node.module.split(".", 1)[0])
    return result


class SmartFuzzArchitectureTests(unittest.TestCase):
    def test_project_local_fuzz_layer_does_not_use_rng_mutation_engines(self) -> None:
        for relative in SMART_FUZZ_FILES:
            with self.subTest(path=relative):
                imports = imported_roots(ROOT / relative)
                self.assertNotIn("random", imports)

    def test_shared_strategy_module_uses_hypothesis_not_case_loops(self) -> None:
        source = (ROOT / "tests/fuzz_strategies.py").read_text(encoding="utf-8")
        self.assertIn("from hypothesis import strategies as st", source)
        self.assertNotIn("random.Random", source)
        self.assertNotIn("NAS_FUZZ_CASES", source)
        self.assertNotIn("for _ in range(", source)

    def test_executable_layer_is_a_contract_check_not_payload_fuzzer(self) -> None:
        source = (ROOT / "scripts/fuzz-executables.py").read_text(encoding="utf-8")
        self.assertIn("not a mutation fuzzer", source)
        self.assertNotIn("PAYLOADS =", source)
        self.assertNotIn("rng.choice", source)
        self.assertNotIn("random.Random", source)

    def test_javascript_properties_use_isolated_pinned_fast_check(self) -> None:
        package = json.loads((ROOT / "tests/js-fuzz/package.json").read_text(encoding="utf-8"))
        lock = json.loads((ROOT / "tests/js-fuzz/package-lock.json").read_text(encoding="utf-8"))
        self.assertEqual(package["devDependencies"], {"fast-check": "4.9.0"})
        self.assertEqual(lock["packages"]["node_modules/fast-check"]["version"], "4.9.0")
        source = (ROOT / "tests/js-fuzz/frontend-properties.test.mjs").read_text(encoding="utf-8")
        self.assertIn('from "fast-check"', source)
        self.assertNotIn("Math.random", source)

    def test_generated_browser_mutation_suite_is_removed(self) -> None:
        self.assertFalse((ROOT / "cockpit/e2e/ui-fuzz.spec.mjs").exists())
        config = (ROOT / "cockpit/e2e/playwright.config.mjs").read_text(encoding="utf-8")
        self.assertNotIn("ui-fuzz.spec.mjs", config)

    def test_orchestrator_exposes_independent_parallel_target_classes(self) -> None:
        completed = subprocess.run(
            [sys.executable, "scripts/run-fuzz.py", "--help"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        help_text = completed.stdout + completed.stderr
        for suite in (
            "boundaries",
            "properties",
            "stateful",
            "security",
            "javascript",
            "executable-contracts",
        ):
            with self.subTest(suite=suite):
                self.assertIn(suite, help_text)

    def test_smart_fuzz_workflow_is_independent_of_vm_qualification(self) -> None:
        workflow = (ROOT / ".github/workflows/smart-fuzz.yml").read_text(encoding="utf-8")
        self.assertIn("suite: [boundaries, properties, stateful, security]", workflow)
        self.assertIn("fast-check frontend properties", workflow)
        self.assertIn("Whole-process adversarial contracts", workflow)
        self.assertIn("curl static HTTP adversarial checks", workflow)
        self.assertNotIn("needs: [integration", workflow)
        self.assertNotIn("qemu-test.sh", workflow)
        self.assertNotIn("playwright install", workflow)
        self.assertNotIn("chromium", workflow.lower())
        self.assertIn("scripts/http-adversarial-smoke.sh", workflow)

    def test_curl_http_harness_does_not_use_a_browser_runtime(self) -> None:
        source = (ROOT / "scripts/http-adversarial-smoke.sh").read_text(encoding="utf-8")
        self.assertIn("curl --silent", source)
        self.assertIn("python3 -m http.server", source)
        for browser in ("playwright", "chromium", "firefox", "webkit", "selenium"):
            with self.subTest(browser=browser):
                self.assertNotIn(browser, source.lower())


if __name__ == "__main__":
    unittest.main()
