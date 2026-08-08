from __future__ import annotations

import ast
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
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
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
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
                    if module_name in imports or module_name in test_path.read_text(encoding="utf-8"):
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
                    if module_name in imports or module_name in test_path.read_text(encoding="utf-8"):
                        has_import = True
                        break
                self.assertTrue(has_import, msg=f"{module} -> {tests} has no import of {module_name}")

    def test_runner_rejects_zero_and_all_skipped_files_by_default(self):
        text = (ROOT / "scripts" / "run-unit-tests.py").read_text(encoding="utf-8")
        self.assertIn("ALLOWLIST_ZERO", text)
        self.assertIn("ALLOWLIST_ALL_SKIPPED", text)
        self.assertIn("all discovered tests were skipped", text)
        self.assertIn("expectedFailures", text)
        self.assertIn("unexpectedSuccesses", text)
        self.assertIn("no tests discovered", text)

    def test_caddy_all_skipped_exception_is_backed_by_dedicated_real_binary_job(self):
        path = ROOT / "tests" / "test_service_caddy_validate.py"
        self.assertTrue(path.is_file(), msg="test_service_caddy_validate.py must exist")
        test_text = path.read_text(encoding="utf-8")
        self.assertIn("SkipTest", test_text)
        self.assertIn("caddy", test_text.lower())
        self.assertIn("generate_caddy_fragment", test_text)

        runner = (ROOT / "scripts" / "run-unit-tests.py").read_text(encoding="utf-8")
        self.assertIn('ALLOWLIST_ALL_SKIPPED = frozenset({"test_service_caddy_validate.py"})', runner)

        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        caddy_block = workflow.split("  caddy-validate:\n", 1)[1].split("\n  static:\n", 1)[0]
        self.assertIn("nix shell nixpkgs#caddy -c caddy version", caddy_block)
        self.assertIn("tests.test_service_caddy_validate", caddy_block)

    def test_managed_service_has_fast_contract_and_slow_state_machine(self):
        fast = ROOT / "tests" / "test_managed_service_stateful.py"
        slow = ROOT / "tests" / "slow_managed_service_stateful.py"
        property_tier = ROOT / "tests" / "test_property_invariants.py"
        self.assertTrue(fast.is_file(), msg="fast managed-service projection contract must exist")
        self.assertTrue(slow.is_file(), msg="slow managed-service state machine must exist")

        fast_text = fast.read_text(encoding="utf-8")
        self.assertIn("ManagedServiceProjectionContractTests", fast_text)
        self.assertIn("portal_projection", fast_text)
        self.assertIn("generate_caddy_fragment", fast_text)

        slow_text = slow.read_text(encoding="utf-8")
        self.assertIn("RuleBasedStateMachine", slow_text)
        self.assertIn("run_state_machine_as_test", slow_text)
        self.assertIn("ProjectionDifferentialTests", slow_text)

        property_text = property_tier.read_text(encoding="utf-8")
        self.assertIn("slow_managed_service_stateful", property_text)


if __name__ == "__main__":
    unittest.main()
