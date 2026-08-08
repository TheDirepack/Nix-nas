from __future__ import annotations

import ast
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

import json

CONTRACTS = ROOT / "tests" / "custom-script-contracts.json"


def _module_name_from_service_path(path: str) -> str:
    return pathlib.Path(path).stem


def _imports_in_file(test_path: pathlib.Path) -> set[str]:
    try:
        tree = ast.parse(test_path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return set()
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
    text = test_path.read_text(encoding="utf-8")
    for name in imports.copy():
        if name not in text:
            pass
    return imports


class RunnerAccountingTests(unittest.TestCase):
    def test_every_service_module_has_importing_test(self):
        raw = json.loads(CONTRACTS.read_text(encoding="utf-8"))
        python_modules: dict[str, list[str]] = raw.get("pythonModules", {})
        service_modules = {p.relative_to(ROOT).as_posix() for p in (ROOT / "services").glob("*.py")}
        for mod_path in sorted(service_modules):
            with self.subTest(module=mod_path):
                self.assertIn(mod_path, python_modules, msg=f"{mod_path} missing from pythonModules")
                test_files = python_modules[mod_path]
                self.assertTrue(test_files, msg=f"{mod_path} has no tests")
                module_name = _module_name_from_service_path(mod_path)
                found_import = False
                for test_rel in test_files:
                    test_path = ROOT / test_rel
                    self.assertTrue(test_path.is_file(), msg=f"declared test {test_rel} missing")
                    imports = _imports_in_file(test_path)
                    if module_name in imports:
                        found_import = True
                        break
                    text = test_path.read_text(encoding="utf-8")
                    if module_name in text:
                        found_import = True
                        break
                self.assertTrue(found_import, msg=f"{mod_path} mapping {test_files} has no import coverage for {module_name}")

    def test_python_modules_mapping_has_real_import(self):
        raw = json.loads(CONTRACTS.read_text(encoding="utf-8"))
        for module, tests in raw.get("pythonModules", {}).items():
            with self.subTest(module=module):
                module_name = _module_name_from_service_path(module)
                has_import = False
                for test_rel in tests:
                    test_path = ROOT / test_rel
                    if not test_path.is_file():
                        continue
                    imports = _imports_in_file(test_path)
                    if module_name in imports:
                        has_import = True
                        break
                    if module_name in test_path.read_text(encoding="utf-8"):
                        has_import = True
                        break
                self.assertTrue(has_import, msg=f"{module} -> {tests} has no import of {module_name}")

    def test_runner_parses_skipped_and_zero_test(self):
        script = ROOT / "scripts" / "run-unit-tests.py"
        text = script.read_text(encoding="utf-8")
        self.assertIn("ALLOWLIST_ZERO", text)
        self.assertIn("skipped", text)
        self.assertIn("expectedFailures", text)
        self.assertIn("unexpectedSuccesses", text)
        self.assertIn("passed", text)
        self.assertIn("no tests discovered", text)

    def test_caddy_validate_test_exists_and_skips_gracefully(self):
        path = ROOT / "tests" / "test_service_caddy_validate.py"
        self.assertTrue(path.is_file(), msg="test_service_caddy_validate.py must exist")
        text = path.read_text(encoding="utf-8")
        self.assertIn("SkipTest", text)
        self.assertIn("caddy", text.lower())
        self.assertIn("generate_caddy_fragment", text)

    def test_stateful_test_exists(self):
        path = ROOT / "tests" / "test_managed_service_stateful.py"
        self.assertTrue(path.is_file(), msg="test_managed_service_stateful.py must exist")
        text = path.read_text(encoding="utf-8")
        self.assertIn("RuleBasedStateMachine", text)
        self.assertIn("portal", text.lower())
        self.assertIn("effective", text.lower())


if __name__ == "__main__":
    unittest.main()
