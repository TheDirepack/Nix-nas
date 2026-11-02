"""Execute the composed first-start seed shell and the real bootstrap helper.

The Nix modules compose three steps for the first seed: a preStart marker that
records that no authority existed, the ExecStart stub that creates an empty
authority, and the postStart Python helper that installs the baseline once. The
shell fragments are rendered from the modules and run against fixture paths, so
the test observes the real boundary between the Nix-owned seed and the
operator-owned authority instead of restating it.
"""

from __future__ import annotations

import pathlib
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
SCHEMA = ROOT / "schemas" / "managed-services-v3.schema.json"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_bootstrap as bootstrap  # noqa: E402

SEED_DOCUMENT = """schemaVersion: 3
services:
  demo:
    name: Demo
    workload: {kind: daemon}
    runtime: {type: systemd, unit: demo.service}
"""

OPERATOR_DOCUMENT = """schemaVersion: 3
services:
  operator-service:
    name: Operator Service
    managed: false
    workload: {kind: daemon}
    runtime: {type: systemd, unit: operator.service}
"""


class V2SeedOnceContractTests(unittest.TestCase):
    def test_nix_records_missing_authority_before_base_seed_execstart(self) -> None:
        lifecycle = (ROOT / "modules/nas/config/managed-services-lifecycle.nix").read_text(encoding="utf-8")
        self.assertIn('desiredPath = "/var/lib/nas-control/services.yaml";', lifecycle)
        self.assertIn('initialSeedMarker = "/var/lib/nas-control/.managed-services-native-seed-v2";', lifecycle)
        self.assertIn("if [ ! -e ${lib.escapeShellArg desiredPath} ]; then", lifecycle)
        self.assertIn(": > ${lib.escapeShellArg initialSeedMarker}", lifecycle)
        self.assertNotIn("rm -f ${lib.escapeShellArg initialSeedMarker}", lifecycle)

    def test_native_seed_uses_same_one_shot_marker_and_bootstrap_helper(self) -> None:
        seed = (ROOT / "modules/nas/config/managed-services-seed-v2.nix").read_text(encoding="utf-8")
        self.assertIn('markerPath = "/var/lib/nas-control/.managed-services-native-seed-v2";', seed)
        self.assertIn("${v2Source}/nas_v2_bootstrap.py", seed)
        self.assertIn("--marker ${lib.escapeShellArg markerPath}", seed)
        # Old split seed modules are gone; managed-services-seed-v2.nix is the sole authority.
        for path in (
            "modules/nas/config/managed-services-native-services.nix",
            "modules/nas/config/managed-services-platform-routes.nix",
        ):
            self.assertFalse((ROOT / path).exists(), f"split seed {path} must stay deleted")

    def test_seed_aggregation_contains_all_built_in_categories(self) -> None:
        seed = (ROOT / "modules/nas/config/managed-services-seed-v2.nix").read_text(encoding="utf-8")
        # Must contain baseline, operations, backup, and platform fragments in one document.
        self.assertIn("baselineServices", seed)
        self.assertIn("operationServices", seed)
        self.assertIn("backupResources", seed)
        self.assertIn("backupServices", seed)
        self.assertIn("platformServices", seed)
        self.assertIn("mergedServices = baselineServices // operationServices", seed)
        self.assertIn("storageResources = mergedStorageResources", seed)
        self.assertIn("schemaVersion = 3", seed)

    def test_bootstrap_contains_no_upgrade_merge_database(self) -> None:
        bootstrap_text = (ROOT / "services/nas_v2_bootstrap.py").read_text(encoding="utf-8")
        self.assertNotIn("_merge_new_keys", bootstrap_text)
        self.assertNotIn("_load_seen", bootstrap_text)
        self.assertNotIn('"seen"', bootstrap_text)
        self.assertIn('"authority-exists"', bootstrap_text)
        self.assertIn('"initial-seed"', bootstrap_text)

    def test_first_composed_start_preserves_preexisting_operator_authority(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = self.fixture(pathlib.Path(raw))
            fixture["desired"].write_text(OPERATOR_DOCUMENT, encoding="utf-8")

            result = self.compose_first_start(fixture)

            # The preStart marker must never be created when an authority already
            # exists, and the operator document must survive byte for byte.
            self.assertFalse(result["marker_created"])
            self.assertEqual(result["migration"]["reason"], "authority-exists")
            self.assertFalse(fixture["marker"].exists())
            self.assertEqual(fixture["desired"].read_text(encoding="utf-8"), OPERATOR_DOCUMENT)

    def test_first_composed_start_seeds_once_and_preserves_later_operator_edits(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = self.fixture(pathlib.Path(raw))

            first = self.compose_first_start(fixture)
            self.assertTrue(first["marker_created"])
            self.assertEqual(first["migration"]["reason"], "initial-seed")
            self.assertFalse(fixture["marker"].exists())
            seeded = fixture["desired"].read_text(encoding="utf-8")
            self.assertIn("demo:", seeded)

            # The administrator now owns the authority. A second composed start
            # (reboot, service restart, Nix upgrade) must not rewrite or merge it.
            edited = seeded.replace("name: Demo", "name: Operator Renamed Demo")
            fixture["desired"].write_text(edited, encoding="utf-8")
            second = self.compose_first_start(fixture)
            self.assertFalse(second["marker_created"])
            self.assertEqual(second["migration"]["reason"], "authority-exists")
            self.assertEqual(fixture["desired"].read_text(encoding="utf-8"), edited)

    def fixture(self, root: pathlib.Path) -> dict[str, pathlib.Path]:
        control = root / "nas-control"
        control.mkdir()
        seed = root / "seed.yaml"
        seed.write_text(SEED_DOCUMENT, encoding="utf-8")
        return {
            "root": root,
            "control": control,
            "desired": control / "services.yaml",
            "marker": control / ".managed-services-native-seed-v2",
            "seed": seed,
        }

    def compose_first_start(self, fixture: dict[str, pathlib.Path]) -> dict[str, Any]:
        desired = fixture["desired"]
        marker = fixture["marker"]
        prestart = self.prestart_shell(desired, marker)
        self.run_shell("prestart.sh", prestart)
        marker_created = marker.exists()
        self.run_shell("seed.sh", self.seed_shell(desired, desired.parent))
        migration = bootstrap.migrate(
            desired=desired,
            seed=fixture["seed"],
            marker=marker,
            schema=SCHEMA,
            platform=None,
        )
        return {"marker_created": marker_created, "migration": migration}

    def run_shell(self, name: str, body: str) -> None:
        target = self.root / name
        target.write_text("set -euo pipefail\n" + body, encoding="utf-8")
        result = subprocess.run(
            [self.bash, str(target)],
            env={"PATH": str(self.coreutils / "bin"), "LC_ALL": "C"},
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def prestart_shell(self, desired: pathlib.Path, marker: pathlib.Path) -> str:
        lifecycle = (ROOT / "modules/nas/config/managed-services-lifecycle.nix").read_text(encoding="utf-8")
        body = lifecycle.split("preStart = lib.mkBefore ''", 1)[1].split("\n        '';", 1)[0]
        body = self.dedent(body)
        body = body.replace("${pkgs.coreutils}", str(self.coreutils))
        body = body.replace("${lib.escapeShellArg desiredPath}", shlex.quote(str(desired)))
        body = body.replace("${lib.escapeShellArg initialSeedMarker}", shlex.quote(str(marker)))
        body = body.replace("/var/lib/nas-control", str(desired.parent))
        # The fixture does not run as root and has no nas-operations group.
        body = body.replace("-o root -g nas-operations", "")
        self.assertNotIn("${", body)
        return body

    def seed_shell(self, desired: pathlib.Path, zfs_control_root: pathlib.Path) -> str:
        module = (ROOT / "modules/nas/config/managed-services.nix").read_text(encoding="utf-8")
        body = module.split("seedDesiredState = pkgs.writeShellScript \"nas-managed-services-v2-seed\" ''", 1)[1].split(
            "\n  '';", 1
        )[0]
        body = self.dedent(body)
        body = body.replace("${pkgs.coreutils}", str(self.coreutils))
        body = body.replace("${zfsControlRoot}", shlex.quote(str(zfs_control_root)))
        body = body.replace("${lib.escapeShellArg desiredPath}", shlex.quote(str(desired)))
        # The fixture cannot create root:nas-operations ownership.
        body = body.replace("-o root -g nas-operations", "")
        body = body.replace(f'"{self.coreutils}/bin/chown" root:nas-operations "$tmp"', "true")
        body = body.replace(f'{self.coreutils}/bin/chown root:nas-operations "$tmp"', "true")
        self.assertNotIn("${", body)
        return body

    @staticmethod
    def dedent(body: str) -> str:
        """Strip the common indentation Nix removes from an indented string."""
        lines = body.splitlines()
        indents = [len(line) - len(line.lstrip()) for line in lines if line.strip()]
        common = min(indents) if indents else 0
        return "\n".join(line[common:] if line.strip() else "" for line in lines)

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = pathlib.Path(temporary.name)
        bash = shutil.which("bash")
        assert bash is not None, "host tool unavailable: bash"
        self.bash = bash
        self.coreutils = self.root / "coreutils"
        bin_dir = self.coreutils / "bin"
        bin_dir.mkdir(parents=True)
        for command in ("cat", "chmod", "dirname", "install", "mktemp", "mv", "rm"):
            tool = shutil.which(command)
            assert tool is not None, f"host tool unavailable: {command}"
            (bin_dir / command).symlink_to(tool)


if __name__ == "__main__":
    unittest.main()
