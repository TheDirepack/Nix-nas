from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

from repo_test_utils import ROOT


DEPLOYMENT_COMMANDS = (
    "nix",
    "nixos-rebuild",
    "systemctl",
    "zfs",
    "zpool",
    "curl",
    "sha256sum",
    "ip",
    "ss",
    "firewall-cmd",
)
STATUS_COMMANDS = ("git", "jq", "readlink")


class UpdateStatusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.config = self.root / "configuration"
        self.config.mkdir()
        self.log = self.root / "commands.log"
        self.bash = shutil.which("bash")
        self.assertIsNotNone(self.bash)
        self.environment = {
            "PATH": str(self.bin),
            "HOME": str(self.root),
            "LANG": "C.UTF-8",
            "COMMAND_LOG": str(self.log),
            "NAS_CONFIG_DIR": str(self.config),
            "NAS_LAN_HOST": "fixture.invalid",
            "NAS_OPERATION_RUNNER": str(self.root / "coordinator"),
            "NAS_OPERATION_COORDINATION_TOKEN": "fixture-only",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
        }
        self.install_script(
            self.root / "coordinator",
            'printf "coordinator\\n" >> "$COMMAND_LOG"\n[[ "$*" == "--validate-current --class update" ]] || exit 99\n',
        )
        for name in STATUS_COMMANDS:
            executable = shutil.which(name)
            self.assertIsNotNone(executable, f"Required test tool is unavailable: {name}")
            self.install_script(
                self.bin / name,
                f'printf "%s\\n" {shlex.quote(name)} >> "$COMMAND_LOG"\nexec {shlex.quote(str(executable))} "$@"\n',
            )
        source = (ROOT / "scripts/update-nas.sh").read_text(encoding="utf-8")
        predicate = "(( EUID == 0 ))"
        self.assertEqual(source.count(predicate), 1)
        # Bash's readonly EUID has no injectable process API. Only this predicate
        # changes in the unprivileged fixture; deployment commands abort if called.
        self.script = self.root / "updater.sh"
        self.script.write_text(source.replace(predicate, "true", 1), encoding="utf-8")

    def install_script(self, path: Path, body: str) -> None:
        path.write_text(f"#!{self.bash}\nset -euo pipefail\n{body}", encoding="utf-8")
        path.chmod(0o700)

    def poison_deployment_commands(self, *, missing: str | None = None) -> None:
        for name in DEPLOYMENT_COMMANDS:
            if name != missing:
                self.install_script(
                    self.bin / name,
                    f'printf "%s\\n" {shlex.quote(name)} >> "$COMMAND_LOG"\nexit 99\n',
                )

    def calls(self) -> list[str]:
        return self.log.read_text(encoding="utf-8").splitlines() if self.log.exists() else []

    def invoke(self, *arguments: str, original: bool = False) -> subprocess.CompletedProcess[str]:
        script = ROOT / "scripts/update-nas.sh" if original else self.script
        return subprocess.run(
            [str(self.bash), str(script), *arguments],
            cwd=self.config,
            env=self.environment,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    def tree(self) -> dict[str, str]:
        return {
            str(path.relative_to(self.config)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in self.config.rglob("*")
            if path.is_file()
        }

    def test_status_succeeds_without_firewall_cmd_and_never_runs_deployment_tools(self) -> None:
        self.poison_deployment_commands(missing="firewall-cmd")
        result = self.invoke("--status", "--json")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIs(json.loads(result.stdout)["git"], False)
        self.assertFalse(set(self.calls()) - set(STATUS_COMMANDS), self.calls())

    def test_json_status_needs_only_read_tools_and_preserves_dirty_checkout(self) -> None:
        git = shutil.which("git")
        self.assertIsNotNone(git)
        for arguments in (
            ["init", "-b", "fixture"],
            [
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "--allow-empty",
                "-m",
                "fixture",
            ],
        ):
            subprocess.run(
                [str(git), *arguments], cwd=self.config, env=self.environment, check=True, capture_output=True
            )
        (self.config / "untracked.txt").write_text("retained fixture\n", encoding="utf-8")
        before = self.tree()
        result = self.invoke("--status", "--json")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        value = json.loads(result.stdout)
        self.assertTrue(value["git"])
        self.assertTrue(value["dirty"])
        self.assertEqual(value["branch"], "fixture")
        self.assertRegex(value["revision"], r"^[0-9a-f]{12}$")
        self.assertIsNone(value["upstream"])
        self.assertIsNone(value["ahead"])
        self.assertIsNone(value["behind"])
        self.assertEqual(value["configurationDir"], str(self.config))
        self.assertEqual(self.tree(), before)
        self.assertFalse(set(self.calls()) - set(STATUS_COMMANDS), self.calls())

    def test_text_status_works_outside_git_without_deployment_tools(self) -> None:
        result = self.invoke("--status")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Revision: unknown\nBranch: unknown\n", result.stdout)
        self.assertEqual(result.stderr, "")
        self.assertFalse(set(self.calls()) - set(STATUS_COMMANDS), self.calls())

    def test_missing_read_tools_still_fail_status(self) -> None:
        for name in STATUS_COMMANDS:
            with self.subTest(command=name):
                path = self.bin / name
                path.rename(self.root / name)
                try:
                    result = self.invoke("--status", "--json")
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    self.assertIn(f"Missing command: {name}", result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(self.calls(), [])
                finally:
                    (self.root / name).rename(path)

    def test_deployment_still_requires_each_existing_deployment_command(self) -> None:
        self.poison_deployment_commands()
        for name in DEPLOYMENT_COMMANDS:
            with self.subTest(command=name):
                path = self.bin / name
                path.rename(self.root / name)
                self.log.unlink(missing_ok=True)
                try:
                    result = self.invoke()
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    self.assertIn(f"Missing command: {name}", result.stderr)
                    self.assertFalse(set(self.calls()) - {*STATUS_COMMANDS, "coordinator"}, self.calls())
                    self.assertIn("coordinator", self.calls())
                finally:
                    (self.root / name).rename(path)

    def probe_tools(self) -> Path:
        # Only --apply and status with a configured probe need the decoder tools.
        for name in ("mktemp", "rm"):
            executable = shutil.which(name)
            assert executable is not None, f"test tool unavailable: {name}"
            (self.bin / name).symlink_to(executable)
        (self.bin / "python3").symlink_to(sys.executable)
        marker = self.root / "probe-launched"
        probe = self.root / "probe"
        self.install_script(probe, f"printf launched > {shlex.quote(str(marker))}\n")
        return probe

    def test_unconfigured_probe_is_reported_as_an_apply_blocker(self) -> None:
        self.poison_deployment_commands()
        result = self.invoke("--status", "--json")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(value["externalProbe"], {"configured": False, "valid": None, "error": None})
        self.assertEqual([item["code"] for item in value["applyBlockers"]], ["external-probe-unconfigured"])
        self.assertIn("nas.update.externalProbeCommand", value["applyBlockers"][0]["message"])
        self.assertFalse(set(self.calls()) - set(STATUS_COMMANDS), self.calls())
        text_result = self.invoke("--status")
        self.assertIn("External probe: not configured (apply unavailable)\n", text_result.stdout)

    def test_local_only_override_does_not_hide_the_status_blocker(self) -> None:
        result = self.invoke("--status", "--json", "--allow-local-health-only")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            [item["code"] for item in json.loads(result.stdout)["applyBlockers"]], ["external-probe-unconfigured"]
        )

    def test_valid_probe_is_validated_without_being_launched(self) -> None:
        self.poison_deployment_commands()
        probe = self.probe_tools()
        self.environment["NAS_UPDATE_EXTERNAL_PROBE_COMMAND_JSON"] = json.dumps([str(probe), "--target", "nas"])
        result = self.invoke("--status", "--json")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(value["externalProbe"], {"configured": True, "valid": True, "error": None})
        self.assertEqual(value["applyBlockers"], [])
        self.assertFalse((self.root / "probe-launched").exists())
        self.assertFalse(set(self.calls()) - set(STATUS_COMMANDS), self.calls())
        self.assertIn("External probe: configured\n", self.invoke("--status").stdout)

    def test_invalid_probe_reports_the_decoder_reason_without_launching(self) -> None:
        probe = self.probe_tools()
        cases = {
            "{}": "nonempty JSON string array",
            "not-json": "must be valid JSON",
            json.dumps([str(probe), "bad\0tail"]): "contains NUL",
        }
        for raw, reason in cases.items():
            with self.subTest(raw=raw):
                self.environment["NAS_UPDATE_EXTERNAL_PROBE_COMMAND_JSON"] = raw
                result = self.invoke("--status", "--json")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                value = json.loads(result.stdout)
                self.assertTrue(value["externalProbe"]["configured"])
                self.assertIs(value["externalProbe"]["valid"], False)
                self.assertIn(reason, value["externalProbe"]["error"])
                self.assertEqual([item["code"] for item in value["applyBlockers"]], ["external-probe-invalid"])
                self.assertIn(reason, value["applyBlockers"][0]["message"])
                self.assertFalse((self.root / "probe-launched").exists())

    def test_original_script_keeps_root_requirement(self) -> None:
        result = subprocess.run(
            [str(self.bash), "-s", "--", "--status", "--json"],
            input=(ROOT / "scripts/update-nas.sh").read_text(encoding="utf-8"),
            cwd="/",
            env=self.environment,
            user=65534 if os.geteuid() == 0 else None,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, "Run nas-update as root.\n")
        self.assertEqual(self.calls(), [])

    def test_json_without_status_remains_invalid_before_dependency_checks(self) -> None:
        result = self.invoke("--json", original=True)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stderr, "--json requires --status.\n")
        self.assertEqual(self.calls(), [])


if __name__ == "__main__":
    unittest.main()
