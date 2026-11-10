from __future__ import annotations

import json
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

from repo_test_utils import ROOT


REAL_TOOLS = ("git", "jq", "readlink", "mktemp", "rm", "timeout", "cat")
# Every deployment tool records its call and fails, so a run that gets past
# admission is observable and can never touch the host.
DEPLOYMENT_STUBS = ("nix", "nixos-rebuild", "zfs", "zpool", "curl", "sha256sum", "ip", "ss", "firewall-cmd")


class UpdateApplyAdmissionTests(unittest.TestCase):
    """Run the whole updater with --apply and stop at the first deployment command."""

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.config = self.root / "configuration"
        self.config.mkdir()
        self.log = self.root / "commands.log"
        self.marker = self.root / "probe-launched"
        self.state = self.root / "systemd-reconciled.json"
        bash = shutil.which("bash")
        assert bash is not None
        self.bash = bash
        for name in REAL_TOOLS:
            tool = shutil.which(name)
            assert tool is not None, f"test tool unavailable: {name}"
            (self.bin / name).symlink_to(tool)
        (self.bin / "python3").symlink_to(sys.executable)
        for name in DEPLOYMENT_STUBS:
            self.install(self.bin / name, f'printf "%s\\n" {shlex.quote(name)} >> "$COMMAND_LOG"\nexit 99\n')
        self.install(
            self.bin / "systemctl",
            'printf "systemctl %s\\n" "$*" >> "$COMMAND_LOG"\n'
            "if [[ $1 == is-active ]]; then\n"
            '  unit="${!#}"\n'
            '  if [[ " $ACTIVE_UNITS " == *" $unit "* ]]; then [[ $2 == --quiet ]] || echo active; exit 0; fi\n'
            "  [[ $2 == --quiet ]] || echo inactive\n"
            "  exit 3\n"
            "fi\n"
            "exit 99\n",
        )
        self.install(
            self.root / "coordinator",
            '[[ "$*" == "--validate-current --class appliance" ]] || exit 98\n',
        )
        self.probe = self.root / "probe"
        self.install(self.probe, 'printf launched > "$PROBE_MARKER"\n')
        source = (ROOT / "scripts/update-nas.sh").read_text(encoding="utf-8")
        predicate = "(( EUID == 0 ))"
        self.assertEqual(source.count(predicate), 1)
        self.script = self.root / "updater.sh"
        self.script.write_text(source.replace(predicate, "true", 1), encoding="utf-8")

    def install(self, path: Path, body: str) -> None:
        path.write_text(f"#!{self.bash}\nset -euo pipefail\n{body}", encoding="utf-8")
        path.chmod(0o700)

    def apply(
        self, *, probe: list[str] | None, start_units: list[str] | None, active: list[str], pending: bool = False
    ):
        marker = self.root / "reconcile.pending"
        if pending:
            marker.write_text("", encoding="utf-8")
        if start_units is None:
            self.state.unlink(missing_ok=True)
        else:
            self.state.write_text(json.dumps({"schemaVersion": 1, "startUnits": start_units}), encoding="utf-8")
        environment = {
            "PATH": str(self.bin),
            "HOME": str(self.root),
            "LANG": "C.UTF-8",
            "TMPDIR": str(self.root),
            "COMMAND_LOG": str(self.log),
            "PROBE_MARKER": str(self.marker),
            "ACTIVE_UNITS": " ".join(["nas-protected-services.target", *active]),
            "NAS_CONFIG_DIR": str(self.config),
            "NAS_LAN_HOST": "fixture.invalid",
            "NAS_V2_SYSTEMD_STATE": str(self.state),
            "NAS_V2_RECONCILE_PENDING": str(marker),
            "NAS_OPERATION_RUNNER": str(self.root / "coordinator"),
            "NAS_OPERATION_COORDINATION_TOKEN": "fixture-only",
            "NAS_UPDATE_EXTERNAL_PROBE_COMMAND_JSON": json.dumps(probe) if probe is not None else "",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
        }
        return subprocess.run(
            [self.bash, str(self.script), "--apply", "--non-interactive"],
            cwd=self.config,
            env=environment,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )

    def calls(self) -> list[str]:
        return self.log.read_text(encoding="utf-8").splitlines() if self.log.exists() else []

    def assert_no_deployment(self) -> None:
        self.assertFalse(set(self.calls()) & set(DEPLOYMENT_STUBS), self.calls())
        self.assertFalse(self.marker.exists())
        self.assertEqual(sorted(self.root.rglob("pre-activation-*")), [])

    def test_unconfigured_probe_refuses_apply_before_any_deployment_work(self) -> None:
        result = self.apply(probe=None, start_units=[], active=[])
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("Persistent deployment requires NAS_UPDATE_EXTERNAL_PROBE_COMMAND_JSON", result.stderr)
        self.assert_no_deployment()

    def test_enabled_application_already_down_refuses_apply_before_build(self) -> None:
        result = self.apply(
            probe=[str(self.probe)],
            start_units=["copyparty.service", "syncthing.service"],
            active=["syncthing.service"],
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("not active: copyparty.service", result.stderr)
        self.assertIn("Refusing to apply", result.stderr)
        self.assert_no_deployment()

    def test_copyparty_turned_off_in_v2_reaches_the_build(self) -> None:
        result = self.apply(
            probe=[str(self.probe)],
            start_units=["syncthing.service"],
            active=["syncthing.service"],
        )
        # The stubbed nix proves admission passed; no activation phase was entered.
        self.assertEqual(result.returncode, 99, result.stdout + result.stderr)
        self.assertIn("nix", self.calls())
        self.assertFalse([call for call in self.calls() if "copyparty" in call], self.calls())
        self.assertNotIn("nixos-rebuild", self.calls())
        self.assertFalse(self.marker.exists())

    def test_pending_reconciliation_refuses_apply_before_build(self) -> None:
        result = self.apply(
            probe=[str(self.probe)], start_units=["syncthing.service"], active=["syncthing.service"], pending=True
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("reconciliation is pending or running", result.stderr)
        self.assert_no_deployment()

    def test_running_reconciliation_refuses_apply_before_build(self) -> None:
        result = self.apply(
            probe=[str(self.probe)],
            start_units=["syncthing.service"],
            active=["syncthing.service", "nas-managed-services-reconcile.service"],
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("reconciliation is pending or running", result.stderr)
        self.assert_no_deployment()

    def test_missing_v2_state_refuses_apply_while_protected_stack_runs(self) -> None:
        result = self.apply(probe=[str(self.probe)], start_units=None, active=["copyparty.service"])
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("start state is unavailable", result.stderr)
        self.assert_no_deployment()


if __name__ == "__main__":
    unittest.main()
