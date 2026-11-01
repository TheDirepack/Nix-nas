from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

from repo_test_utils import text


class UpdateRuntimeTests(unittest.TestCase):
    """Exercise unchanged updater functions with source-declared PATH fixtures, not a Nix build."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.bash = self.host_tool("bash")
        self.trace = self.root / "trace"
        self.probe_args = self.root / "probe-args"
        wrapper = text("modules/nas/internal/maintenance-tools.nix").split(
            "nasUpdate = pkgs.writeShellApplication {", 1
        )[1]
        declaration = wrapper.split("runtimeInputs = [", 1)[1].split("];", 1)[0]
        self.inputs = declaration.split()
        self.assertTrue(self.inputs)
        self.assertTrue(all(re.fullmatch(r"(?:pkgs|config)(?:\.[A-Za-z0-9_-]+)+", item) for item in self.inputs))
        self.assertIn("${builtins.readFile ../../../scripts/update-nas.sh}", wrapper)
        for package in self.inputs:
            self.package_bin(package).mkdir(parents=True, exist_ok=True)
        self.link_tool("pkgs.gnugrep", "grep")
        self.link_tool("pkgs.gawk", "awk")
        self.link_tool("pkgs.coreutils", "timeout")
        self.package_bin("pkgs.python3").mkdir(parents=True, exist_ok=True)
        (self.package_bin("pkgs.python3") / "python3").symlink_to(sys.executable)
        self.stub("pkgs.systemd", "systemctl")
        self.stub("pkgs.zfs", "zpool")
        self.stub("pkgs.zfs", "zfs")
        self.stub("pkgs.iproute2", "ip", "printf 'fixture address or route\\n'\n")
        self.stub("pkgs.iproute2", "ss", "printf 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\\n'\n")
        self.stub("config.services.firewalld.package", "firewall-cmd", "printf 'nas-lan\\n'\n")
        self.stub("pkgs.firewalld", "firewall-cmd", "printf 'wrong-default-zone\\n'\n")
        self.probe = self.stub(
            "probe", "external-probe", 'printf \'%s\\0\' "$@" > "$PROBE_ARGS"\nexit "${PROBE_EXIT:-0}"\n'
        )
        source = text("scripts/update-nas.sh")
        self.functions = (
            "listener_present() {" + source.split("listener_present() {", 1)[1].split("restart_protected() {", 1)[0]
        )

    @staticmethod
    def host_tool(name: str) -> str:
        tool = shutil.which(name)
        assert tool is not None, f"test tool unavailable: {name}"
        return tool

    def package_bin(self, package: str) -> Path:
        return self.root / package / "bin"

    def link_tool(self, package: str, command: str) -> None:
        directory = self.package_bin(package)
        directory.mkdir(parents=True, exist_ok=True)
        (directory / command).symlink_to(self.host_tool(command))

    def stub(self, package: str, command: str, body: str = "") -> Path:
        directory = self.package_bin(package)
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / command
        path.write_text(
            f'#!{self.bash}\nset -euo pipefail\nprintf \'%s\\n\' "{package}:{command} $*" >> "$TRACE"\n' + body,
            encoding="utf-8",
        )
        path.chmod(0o755)
        return path

    def run_function(self, function: str, *, inherited: tuple[str, ...] = (), **settings: str):
        # Only fixture package bins are inherited; host service/firewall commands cannot run.
        path = os.pathsep.join(str(self.package_bin(item)) for item in [*self.inputs, *inherited])
        environment = {
            "PATH": path,
            "TRACE": str(self.trace),
            "PROBE_ARGS": str(self.probe_args),
            "LC_ALL": "C",
            **settings,
        }
        command = (
            "set -Eeuo pipefail\n"
            'trusted_interfaces=fixture0\nfirewall_enabled="${FIREWALL_ENABLED:-1}"\n'
            'firewall_zone="${FIREWALL_ZONE:-nas-lan}"\nprotected_was_active=false\n'
            "allow_local_health_only=false\n" + self.functions + "\n" + function + "\n"
        )
        return subprocess.run(
            [self.bash, "--noprofile", "--norc", "-c", command],
            cwd=self.root,
            env=environment,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    def test_firewall_health_works_with_only_declared_inputs(self):
        result = self.run_function("health_check")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(
            "config.services.firewalld.package:firewall-cmd --get-zone-of-interface=fixture0", self.trace.read_text()
        )

    def test_configured_firewalld_package_precedes_ambient_default(self):
        result = self.run_function("health_check", inherited=("pkgs.firewalld",))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("config.services.firewalld.package:firewall-cmd", self.trace.read_text())
        self.assertNotIn("pkgs.firewalld:firewall-cmd", self.trace.read_text())

    def test_disabled_firewall_skips_zone_query(self):
        result = self.run_function("health_check", FIREWALL_ENABLED="0")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("firewall-cmd", self.trace.read_text())

    def test_wrong_zone_remains_fatal(self):
        result = self.run_function(
            "health_check", inherited=("config.services.firewalld.package",), FIREWALL_ZONE="required-zone"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Trusted interface fixture0 is in nas-lan instead of required-zone", result.stderr)

    def test_external_probe_decodes_argv_with_only_declared_inputs(self):
        args = ["space ; $(not-a-command)", 'quote"\\value', "line\nbreak", "unicode-✓"]
        result = self.run_function(
            "external_management_probe", NAS_UPDATE_EXTERNAL_PROBE_COMMAND_JSON=json.dumps([str(self.probe), *args])
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.probe_args.read_bytes(), b"".join(arg.encode() + b"\0" for arg in args))

    def test_external_probe_preserves_failure_exit(self):
        result = self.run_function(
            "external_management_probe",
            NAS_UPDATE_EXTERNAL_PROBE_COMMAND_JSON=json.dumps([str(self.probe), "failure-control"]),
            PROBE_EXIT="23",
        )
        self.assertEqual(result.returncode, 23, result.stdout + result.stderr)
        self.assertEqual(self.probe_args.read_bytes(), b"failure-control\0")

    def test_preflight_rejects_embedded_nul_before_launch(self):
        invalid = (
            [str(self.probe), "bad\u0000tail"],
            [str(self.probe), ""],
            [],
            {"not": "an argv"},
        )
        for args in invalid:
            with self.subTest(args=args):
                result = self.run_function(
                    "validate_external_probe_configuration",
                    inherited=("pkgs.python3",),
                    NAS_UPDATE_EXTERNAL_PROBE_COMMAND_JSON=json.dumps(args),
                )
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertFalse(self.trace.exists(), "preflight must not run the probe")
                self.assertFalse(self.probe_args.exists())
                if isinstance(args, list) and any("\u0000" in arg for arg in args):
                    self.assertIn("contains NUL", result.stderr)

    def test_preflight_accepts_literal_backslash_x_without_running_probe(self):
        result = self.run_function(
            "validate_external_probe_configuration",
            inherited=("pkgs.python3",),
            NAS_UPDATE_EXTERNAL_PROBE_COMMAND_JSON=json.dumps([str(self.probe), r"\\x00"]),
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.trace.exists())
        self.assertFalse(self.probe_args.exists())

    def test_update_checks_probe_and_profile_before_any_snapshot_or_activation(self):
        source = text("scripts/update-nas.sh")
        preflight = source.index('if [[ -z "$old_profile_link" || -z "$old_profile" ]]')
        probe = source.index("  validate_external_probe_configuration", preflight)
        snapshot = source.index("  create_state_snapshot", probe)
        activate = source.index("  nixos-rebuild test --flake", snapshot)
        self.assertLess(preflight, probe)
        self.assertLess(probe, snapshot)
        self.assertLess(snapshot, activate)

    def test_missing_profile_baseline_aborts_before_probe_preflight(self):
        source = text("scripts/update-nas.sh")
        section = (
            "if $apply; then"
            + source.split("# Check external probe *configuration*", 1)[1]
            .split("if $apply; then", 1)[1]
            .split('echo "Evaluating reviewed flake inputs', 1)[0]
        )
        script = (
            "set -euo pipefail\n"
            "apply=true\n"
            "old_profile_link=''\n"
            "old_profile=''\n"
            "validate_external_probe_configuration() { echo PROBE_CALLED; }\n" + section
        )
        result = subprocess.run(
            [self.bash, "--noprofile", "--norc", "-c", script],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("rollback baseline", result.stderr)
        self.assertNotIn("PROBE_CALLED", result.stdout)

    def test_persistent_profile_rollback_uses_symlink_target_changes(self):
        source = text("scripts/update-nas.sh")
        rollback_source = (
            "rollback() {" + source.split("rollback() {", 1)[1].split("\n}\n\ntrap rollback EXIT", 1)[0] + "\n}"
        )
        for changed in (False, True):
            with self.subTest(changed=changed):
                with tempfile.TemporaryDirectory() as folder:
                    location = Path(folder)
                    system_profile = location / "system"
                    system_profile.symlink_to("generation-2" if changed else "generation-1")
                    log = location / "rollback.log"
                    command = (
                        "set -euo pipefail\n"
                        f"system_profile={shlex.quote(str(system_profile))}\n"
                        f"trace={shlex.quote(str(log))}\n"
                        'old_profile_link="generation-1"\n'
                        'old_profile=""\n'
                        "rollback_needed=true\n"
                        "runtime_activation_attempted=false\n"
                        "source_promoted=false\n"
                        'original_source_commit=""\n'
                        "cleanup_candidate() { :; }\n"
                        'nixos-rebuild() { printf "%s\\n" "$*" >> "$trace"; ln -sfn generation-1 "$system_profile"; }\n'
                        + rollback_source
                        + "\nset +e\nfalse\nrollback\n"
                    )
                    result = subprocess.run(
                        [self.bash, "--noprofile", "--norc", "-c", command],
                        cwd=location,
                        capture_output=True,
                        text=True,
                        timeout=5,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    self.assertEqual(system_profile.readlink(), Path("generation-1"))
                    if changed:
                        self.assertIn("--rollback switch", log.read_text(encoding="utf-8"))
                    else:
                        self.assertFalse(log.exists(), "unchanged profile must not trigger rollback")

    def test_invalid_probe_is_rejected_without_launch(self):
        # The Python validator fails first; wait propagates that failure before
        # the later empty-argv safeguard, so it must not print both diagnostics.
        invalid_commands = ({}, [], "", [""], ["echo", 3], [None])
        for invalid in invalid_commands:
            with self.subTest(command=invalid):
                result = self.run_function(
                    "external_management_probe",
                    inherited=("pkgs.python3",),
                    NAS_UPDATE_EXTERNAL_PROBE_COMMAND_JSON=json.dumps(invalid),
                )
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("external probe command must be a nonempty JSON string array", result.stderr)
                self.assertFalse(self.trace.exists())
                self.assertFalse(self.probe_args.exists())

    def test_external_probe_is_required_without_explicit_override(self):
        result = self.run_function("external_management_probe")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Persistent deployment requires NAS_UPDATE_EXTERNAL_PROBE_COMMAND_JSON", result.stderr)
        self.assertFalse(self.trace.exists())

    def test_local_health_override_remains_explicit(self):
        result = self.run_function("allow_local_health_only=true\nexternal_management_probe")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("WARNING: persisting after local-only management checks by explicit override", result.stderr)
        self.assertFalse(self.trace.exists())


if __name__ == "__main__":
    unittest.main()
