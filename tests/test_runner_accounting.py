from __future__ import annotations

import ast
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTRACTS = (
    ROOT / "tests" / "custom-script-contracts.json",
    ROOT / "tests" / "custom-script-contracts-v2.json",
)


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


def _python_module_contracts() -> dict[str, list[str]]:
    merged: dict[str, list[str]] = {}
    for path in CONTRACTS:
        raw = json.loads(path.read_text(encoding="utf-8"))
        modules = raw.get("pythonModules", {})
        if not isinstance(modules, dict):
            raise AssertionError(f"{path.relative_to(ROOT)} has invalid pythonModules")
        for module, tests in modules.items():
            if module in merged:
                raise AssertionError(f"duplicate python module contract: {module}")
            if not isinstance(tests, list) or not all(isinstance(test, str) for test in tests):
                raise AssertionError(f"{module} has invalid focused-test contract")
            merged[module] = tests
    return merged


class RunnerAccountingTests(unittest.TestCase):
    def test_every_service_module_has_importing_test(self):
        python_modules = _python_module_contracts()
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
                self.assertTrue(
                    found_import,
                    msg=f"{mod_path} mapping {test_files} has no import coverage for {module_name}",
                )

    def test_python_modules_mapping_has_real_import(self):
        for module, tests in _python_module_contracts().items():
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

    def test_caddy_ci_entrypoint_uses_real_v2_binary_tests(self):
        v2_path = ROOT / "tests" / "test_v2_caddy_validate.py"
        self.assertTrue(v2_path.is_file(), msg="test_v2_caddy_validate.py must exist")
        v2_text = v2_path.read_text(encoding="utf-8")
        self.assertIn("SkipTest", v2_text)
        self.assertIn("nas_v2_caddy", v2_text)
        self.assertIn("validate_caddyfile", v2_text)
        self.assertNotIn("nas_service_caddy", v2_text)
        self.assertFalse((ROOT / "tests" / "test_service_caddy_validate.py").exists())

        runner = (ROOT / "scripts" / "run-unit-tests.py").read_text(encoding="utf-8")
        self.assertIn('ALLOWLIST_ALL_SKIPPED = frozenset({"test_v2_caddy_validate.py"})', runner)
        self.assertNotIn('frozenset({"test_service_caddy_validate.py"})', runner)

        qualification = (ROOT / "scripts" / "ci-qualification.sh").read_text(encoding="utf-8")
        security_block = qualification.split("  security)\n", 1)[1].split("  nonroot)\n", 1)[0]
        self.assertIn("Caddy generator validation", security_block)
        self.assertIn("tests.test_v2_caddy", security_block)
        self.assertIn("tests.test_v2_caddy_validate", security_block)
        self.assertNotIn("tests.test_service_caddy", security_block)
        self.assertIn("nix develop .#test", security_block)

    def test_managed_services_v2_has_runtime_and_property_contracts(self):
        v2_contracts = {
            "test_v2_caddy.py": ("nas_v2_caddy", "missing_capability"),
            "test_v2_systemd.py": ("nas_v2_systemd_native", "idle"),
            "test_v2_session.py": ("nas_v2_session", "volume"),
            "test_v2_podman_network.py": ("nas_v2_network", "isolated"),
        }
        for filename, markers in v2_contracts.items():
            with self.subTest(filename=filename):
                path = ROOT / "tests" / filename
                self.assertTrue(path.is_file(), msg=f"{filename} must exist")
                text = path.read_text(encoding="utf-8")
                for marker in markers:
                    self.assertIn(marker, text)

        property_text = (ROOT / "tests" / "test_property_invariants.py").read_text(encoding="utf-8")
        self.assertIn("PropertyInvariantTests", property_text)
        self.assertNotIn("slow_managed_service_stateful", property_text)
        self.assertNotIn("nas_feature_model", property_text)
        self.assertNotIn("nas_managed_service", property_text)


if __name__ == "__main__":
    unittest.main()
