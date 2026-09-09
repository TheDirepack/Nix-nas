from __future__ import annotations

import importlib.util
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _load_structure_validator():
    spec = importlib.util.spec_from_file_location("validate_structure_ws12", ROOT / "scripts" / "validate-structure.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _make_tree(root: pathlib.Path, dirs: list[str]) -> None:
    for entry in dirs:
        target = root / entry
        target.mkdir(parents=True, exist_ok=True)
        (target / ".keep").write_text("fixture\n", encoding="utf-8")


def _harness_forwarded_ports() -> dict[str, str]:
    """Parse the canonical endpoint definition from scripts/qemu-test.sh.

    Returns host port defaults and guest destinations from qemu_network_args().
    """
    text = (ROOT / "scripts" / "qemu-test.sh").read_text(encoding="utf-8")
    ssh_default = re.search(r'SSH_PORT="\$\{NAS_QEMU_SSH_PORT:-(\d+)\}"', text)
    https_default = re.search(r'HTTPS_PORT="\$\{NAS_QEMU_HTTPS_PORT:-(\d+)\}"', text)
    assert ssh_default and https_default, "canonical SSH/HTTPS port defaults missing"
    forwards = re.findall(r"hostfwd=tcp:\$HOST_BIND_ADDRESS:\$(\w+)-:(\d+)", text)
    assert forwards, "canonical hostfwd entries missing"
    return {
        "ssh": ssh_default.group(1),
        "https": https_default.group(1),
        "forwards": ",".join(f"{host}->{guest}" for host, guest in forwards),
    }


class Ws12DevValidationTests(unittest.TestCase):
    def test_documented_workflow_artifacts_pass_development_validation(self) -> None:
        validator = _load_structure_validator()
        self.assertTrue(
            hasattr(validator, "find_forbidden_dirs"),
            "validator must expose find_forbidden_dirs for dev/strict modes",
        )

    def test_development_allows_only_known_generated_locations(self) -> None:
        validator = _load_structure_validator()
        find_forbidden_dirs = validator.find_forbidden_dirs
        import tempfile

        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            _make_tree(
                root,
                [
                    "cockpit/node_modules/some-dep/dist",
                    "setup/first-run-wizard/node_modules/some-dep/dist",
                    "services/__pycache__",
                    "tests/__pycache__",
                    "scripts/__pycache__",
                    ".ruff_cache",
                ],
            )
            self.assertEqual(find_forbidden_dirs(root, strict=False), [])
            # Arbitrary locations with the same names must still fail dev validation.
            _make_tree(root, ["tools/node_modules", "random/build", ".mypy_cache"])
            forbidden = find_forbidden_dirs(root, strict=False)
            self.assertIn("tools/node_modules", forbidden)
            self.assertIn("random/build", forbidden)
            self.assertIn(".mypy_cache", forbidden)

    def test_strict_staging_rejects_all_forbidden_artifacts(self) -> None:
        validator = _load_structure_validator()
        find_forbidden_dirs = validator.find_forbidden_dirs
        import tempfile

        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            _make_tree(
                root,
                [
                    "cockpit/node_modules",
                    "services/__pycache__",
                    ".ruff_cache",
                ],
            )
            forbidden = find_forbidden_dirs(root, strict=True)
            self.assertIn("cockpit/node_modules", forbidden)
            self.assertIn("services/__pycache__", forbidden)
            self.assertIn(".ruff_cache", forbidden)


class Ws12VmEndpointContractTests(unittest.TestCase):
    def test_vm_guide_matches_canonical_harness_endpoints(self) -> None:
        ports = _harness_forwarded_ports()
        guide = (ROOT / "docs" / "development" / "vm-testing.md").read_text(encoding="utf-8")
        # Canonical defaults: SSH 2222, HTTPS 8443, guests :22 and :443.
        self.assertEqual(ports["ssh"], "2222")
        self.assertEqual(ports["https"], "8443")
        self.assertIn("SSH_PORT->22", ports["forwards"])
        self.assertIn("HTTPS_PORT->443", ports["forwards"])
        self.assertIn("2222", guide)
        self.assertIn("8443", guide)
        self.assertIn("/console", guide)
        # Stale endpoints and locked-boot promises must be gone.
        self.assertNotIn("8088", guide)
        self.assertNotIn("9094", guide)
        self.assertNotIn("Cockpit remains reachable while locked", guide)


if __name__ == "__main__":
    unittest.main()
