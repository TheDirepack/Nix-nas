from __future__ import annotations

import os
import pathlib
import re
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "evaluate-reference-configurations.sh"

EXPECTED_CONFIGURATIONS = {
    "nas-ci-ready",
    "nas-qemu",
    "nas-module-consumer",
    "nas-profile-core-storage",
    "nas-profile-identity-sharing",
    "nas-profile-observability",
    "nas-profile-virtualization",
    "nas-profile-all",
}
EXPECTED_CHECKS = {"nas-vm", "nas-vm-encrypted"}


def exported_flake_attributes(flake: str, attribute: str) -> set[str]:
    """Read the attribute names bound inside one flake output attrset.

    Nix evaluation is the only complete check, but it needs a writable Nix store,
    which the fast local tier does not have. Matching the simple ``name = ...``
    bindings mirrors how tests/test_vm_bundles.py reads ``packages.x86_64-linux``
    and is enough to catch a reference to an attribute the flake no longer
    exports.
    """
    opening = re.search(rf"^(\s*){re.escape(attribute)} = (?:rec )?\{{$", flake, flags=re.MULTILINE)
    if opening is None:
        raise AssertionError(f"flake.nix does not define {attribute}")
    indent = opening.group(1)
    names: set[str] = set()
    for line in flake[opening.end() :].splitlines():
        if line.strip() in {"};", "}"}:
            break
        match = re.match(rf"{re.escape(indent)}  ([a-zA-Z0-9][a-zA-Z0-9_-]*)\s*=", line)
        if match:
            names.add(match.group(1))
    return names


class ReferenceConfigurationEvaluatorTests(unittest.TestCase):
    def run_evaluator(self, *, fail_on: str = "") -> tuple[subprocess.CompletedProcess[str], list[str]]:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            log = root / "nix.log"
            fake_nix = root / "nix"
            fake_nix.write_text(
                "#!/usr/bin/env bash\n"
                "set -eu\n"
                'printf \'%s\\n\' "$*" >> "$NAS_TEST_NIX_LOG"\n'
                'case "$*" in\n'
                '  *"${NAS_TEST_NIX_FAIL_ON:-__never__}"*) exit 42 ;;\n'
                "esac\n",
                encoding="utf-8",
            )
            fake_nix.chmod(0o755)
            env = os.environ.copy()
            env["PATH"] = f"{root}:{env.get('PATH', '')}"
            env["NAS_TEST_NIX_LOG"] = str(log)
            if fail_on:
                env["NAS_TEST_NIX_FAIL_ON"] = fail_on
            result = subprocess.run(
                ["bash", str(SCRIPT)],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
            return result, calls

    def test_evaluates_every_complete_reference_configuration_and_vm_check_once(self) -> None:
        result, calls = self.run_evaluator()
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertEqual(len(calls), len(EXPECTED_CONFIGURATIONS) + len(EXPECTED_CHECKS))

        seen_configurations = set()
        seen_checks = set()
        for call in calls:
            self.assertTrue(call.startswith("eval --raw .#"), call)
            if "nixosConfigurations." in call:
                name = call.split("nixosConfigurations.", 1)[1].split(".config.system.build", 1)[0]
                seen_configurations.add(name)
            elif "checks.x86_64-linux." in call:
                name = call.split("checks.x86_64-linux.", 1)[1].split(".drvPath", 1)[0]
                seen_checks.add(name)
            else:
                self.fail(f"unexpected nix evaluation call: {call}")

        self.assertEqual(seen_configurations, EXPECTED_CONFIGURATIONS)
        self.assertEqual(seen_checks, EXPECTED_CHECKS)
        self.assertNotIn("nixosConfigurations.nas.config", "\n".join(calls))
        self.assertIn("reference configuration evaluation passed", result.stdout)

    def test_first_failed_nix_evaluation_fails_the_helper_and_stops_later_calls(self) -> None:
        result, calls = self.run_evaluator(fail_on="nas-profile-observability")
        self.assertEqual(result.returncode, 42)
        self.assertTrue(any("nas-profile-observability" in call for call in calls))
        self.assertFalse(any("nas-profile-virtualization" in call for call in calls))
        self.assertNotIn("reference configuration evaluation passed", result.stdout)

    def test_machine_specific_nas_output_is_documented_as_intentionally_excluded(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("hardware-configuration.nix placeholder", text)
        self.assertIn("nixosConfigurations.nas", text)
        self.assertIn("inventing a root filesystem or bootloader device", text)

    def test_referenced_flake_module_attributes_are_actually_exported(self) -> None:
        """Every self.nixosModules.X reference must name a live flake attribute.

        A test VM module that imports a deleted module set only fails during Nix
        evaluation, which needs a writable store. Catching it here keeps the fast
        local tier honest instead of leaving it to the NixOS CI leg.
        """
        flake = (ROOT / "flake.nix").read_text(encoding="utf-8")
        exported = exported_flake_attributes(flake, "nixosModules")
        # `profiles` is a nested attrset inside `nixosModules`; it is resolved
        # separately below, so only the directly importable entries are compared.
        self.assertLessEqual({"core", "default"}, exported, exported)

        referenced: dict[str, set[str]] = {}
        # flake.nix wires the nixosConfigurations it exports, so it is itself a
        # consumer of these attributes; a profile deleted from modules/profiles
        # but still referenced there fails only at evaluation time.
        sources = [ROOT / "flake.nix", *sorted((ROOT / "tests" / "nixos").rglob("*.nix"))]
        for path in sources:
            text = path.read_text(encoding="utf-8")
            names: set[str] = set()
            for match in re.finditer(r'nixosModules\.profiles\.(?:"([^"]+)"|([a-zA-Z0-9_-]+))', text):
                names.add(f"profiles.{match.group(1) or match.group(2)}")
            for match in re.finditer(r'nixosModules\.(?:"([^"]+)"|([a-zA-Z0-9_-]+))', text):
                name = match.group(1) or match.group(2)
                if name != "profiles":
                    names.add(name)
            if names:
                referenced[path.relative_to(ROOT).as_posix()] = names

        self.assertTrue(referenced, "no nixosModules references found to check")
        profile_names = {name for names in referenced.values() for name in names if name.startswith("profiles.")}
        exported_profiles = {f"profiles.{name}" for name in exported_flake_attributes(flake, "profiles")}
        self.assertTrue(exported_profiles, "flake.nix exports no profiles")
        for name in sorted(profile_names):
            self.assertIn(name, exported_profiles, f"referenced profile {name} is not exported")

        for path, names in referenced.items():
            unknown = {name for name in names if not name.startswith("profiles.")} - exported
            self.assertFalse(unknown, f"{path} references unexported nixosModules: {sorted(unknown)}")


if __name__ == "__main__":
    unittest.main()
