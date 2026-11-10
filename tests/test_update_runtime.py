from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import re
import shutil
import socket
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
        # external_management_probe reads the decoder's argv from a temp file, so
        # the declared coreutils package must provide both tools.
        self.link_tool("pkgs.coreutils", "mktemp")
        self.link_tool("pkgs.coreutils", "rm")
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
            "listener_present() {" + source.split("listener_present() {", 1)[1].split("\ninside_git=false\n", 1)[0]
        )
        # The dangling-profile guard and the old_profile computation it depends on
        # are executed verbatim from the updater rather than re-derived here.
        self.old_profile_expression = 'old_profile="$(readlink -f "$system_profile" 2>/dev/null || true)"'
        self.assertIn(self.old_profile_expression, source)
        guard_start = source.index("# Reject a dangling system profile before activation")
        guard_end = source.index(
            'echo "Capturing mutable application state before candidate activation..."', guard_start
        )
        self.profile_guard = source[guard_start:guard_end]

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
                self.assertNotIn("External management probe command is empty.", result.stderr)
                self.assertFalse(self.trace.exists())
                self.assertFalse(self.probe_args.exists())

    def test_malformed_probe_json_is_rejected_without_traceback_or_launch(self):
        for raw in ("[", '{"command":', "not-json"):
            with self.subTest(raw=raw):
                result = self.run_function("external_management_probe", NAS_UPDATE_EXTERNAL_PROBE_COMMAND_JSON=raw)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("external probe command must be valid JSON", result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertNotIn("External management probe command is empty.", result.stderr)
                self.assertFalse(self.trace.exists())
                self.assertFalse(self.probe_args.exists())

    def test_unencodable_probe_arguments_are_rejected_without_traceback_or_launch(self):
        for argument in ("\ud800", "\udfff"):
            with self.subTest(argument=ascii(argument)):
                result = self.run_function(
                    "external_management_probe",
                    NAS_UPDATE_EXTERNAL_PROBE_COMMAND_JSON=json.dumps([str(self.probe), argument]),
                )
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("external probe argument must be UTF-8 encodable", result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertFalse(self.trace.exists())
                self.assertFalse(self.probe_args.exists())

    def test_missing_or_non_executable_probe_is_rejected_before_launch(self):
        plain = self.root / "plain-file"
        plain.write_text("not a program\n")
        for command in (["relative-probe"], [str(self.root / "missing")], [str(plain)], [str(self.root)]):
            for invocation in ("external_management_probe --validate", "external_management_probe"):
                with self.subTest(command=command, invocation=invocation):
                    result = self.run_function(invocation, NAS_UPDATE_EXTERNAL_PROBE_COMMAND_JSON=json.dumps(command))
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    self.assertIn("not an absolute executable file", result.stderr)
                    self.assertFalse(self.trace.exists())

    def test_invalid_probe_argument_cannot_reach_candidate_activation(self):
        # A NUL byte is legal JSON and legal argv in the encoded document, so it
        # must be rejected by the validator rather than silently truncated by
        # exec(2) before any candidate activation phase starts.
        before = {path.relative_to(self.root) for path in self.root.rglob("*")}
        result = self.run_function(
            "external_management_probe",
            inherited=("pkgs.python3",),
            NAS_UPDATE_EXTERNAL_PROBE_COMMAND_JSON=json.dumps([str(self.probe), "bad\0arg"]),
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("external probe argument contains NUL", result.stderr)
        # No probe execution, no snapshot, and no other updater artifact: the
        # invalid probe returns before any phase that mutates the system.
        self.assertFalse(self.trace.exists())
        self.assertFalse(self.probe_args.exists())
        self.assertEqual(sorted(self.root.rglob("pre-activation-*")), [])
        self.assertEqual({path.relative_to(self.root) for path in self.root.rglob("*")}, before)

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

    SUBSTRATE_UNITS = (
        "sshd.service",
        "postgresql.service",
        "authentik-worker.service",
        "authentik.service",
        "nas-cockpit-sso.socket",
        "nas-cockpit-sso.service",
        "caddy.service",
    )

    def protected_health(
        self,
        start_units,
        active,
        *,
        copyparty_socket: bool = False,
        raw_state: str | None = None,
        states: dict[str, list[str]] | None = None,
        readiness: list[str] | None = None,
        pending: bool = False,
        settle_seconds: int = 1,
    ):
        """Run the unchanged health_check against a fake V2 start set and live units.

        ``states`` gives a unit a sequence of ``is-active`` answers; the last one
        repeats. Other units are active exactly when listed in ``active``.
        """
        for command in ("jq", "sleep"):
            if not (self.package_bin("pkgs.jq" if command == "jq" else "pkgs.coreutils") / command).exists():
                self.link_tool("pkgs.jq" if command == "jq" else "pkgs.coreutils", command)
        sequences = self.root / "unit-states"
        shutil.rmtree(sequences, ignore_errors=True)
        sequences.mkdir()
        for unit, answers in (states or {}).items():
            (sequences / unit).write_text("\n".join(answers) + "\n")
        self.stub(
            "pkgs.systemd",
            "systemctl",
            "if [[ $1 == is-active ]]; then\n"
            '  unit="${!#}"\n'
            '  if [[ -f "$UNIT_STATES/$unit" ]]; then\n'
            '    mapfile -t answers < "$UNIT_STATES/$unit"\n'
            '    state="${answers[0]}"\n'
            '    ((${#answers[@]} < 2)) || printf "%s\\n" "${answers[@]:1}" > "$UNIT_STATES/$unit"\n'
            '  elif [[ " $ACTIVE_UNITS " == *" $unit "* ]]; then state=active\n'
            "  else state=inactive; fi\n"
            '  [[ $2 == --quiet ]] || printf "%s\\n" "$state"\n'
            "  [[ $state == active ]]\n"
            "fi\n",
        )
        self.stub(
            "pkgs.iproute2",
            "ss",
            "printf 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\\nLISTEN 0 128 0.0.0.0:443 0.0.0.0:*\\n'\n",
        )
        self.stub(
            "pkgs.curl", "curl", 'for argument; do [[ $argument == "%{http_code}" ]] && printf 200; done; exit 0\n'
        )
        sockets = self.root / "sockets"
        sockets.mkdir(exist_ok=True)
        cockpit = sockets / "cockpit.sock"
        copyparty = sockets / "copyparty.sock"
        bound = []
        for path, wanted in ((cockpit, True), (copyparty, copyparty_socket)):
            if wanted and not path.exists():
                listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                listener.bind(str(path))
                bound.append(listener)
        for listener in bound:
            self.addCleanup(listener.close)
        state = self.root / "systemd-reconciled.json"
        document: dict[str, object] = {"schemaVersion": 1, "startUnits": start_units}
        if readiness is not None:
            document["readinessUnits"] = readiness
        state.write_text(raw_state if raw_state is not None else json.dumps(document))
        marker = self.root / "reconcile.pending"
        if pending:
            marker.write_text("")
        else:
            marker.unlink(missing_ok=True)
        ca = self.root / "ca.crt"
        ca.write_text("fixture CA\n")
        prelude = (
            "protected_was_active=true\n"
            f"v2_systemd_state={shlex.quote(str(state))}\n"
            f"copyparty_socket={shlex.quote(str(copyparty))}\n"
            f"cockpit_socket={shlex.quote(str(cockpit))}\n"
            f"caddy_ca_file={shlex.quote(str(ca))}\n"
            f"v2_reconcile_pending={shlex.quote(str(marker))}\n"
            f"application_settle_seconds={settle_seconds}\n"
            "lan_host=fixture.invalid\nauthentik_port=9000\nauthentik_path=/identity/\n"
        )
        return self.run_function(
            prelude + "health_check",
            ACTIVE_UNITS=" ".join(active),
            UNIT_STATES=str(sequences),
            FIREWALL_ENABLED="0",
        )

    def is_active_queries(self) -> list[str]:
        return [
            line.split()[-1]
            for line in self.trace.read_text().splitlines()
            if line.startswith("pkgs.systemd:systemctl is-active")
        ]

    def test_v2_disabled_copyparty_is_not_required_after_update(self):
        units = ["syncthing.service", "nas-v2-timer-identity-sync-0.timer"]
        result = self.protected_health(units, [*self.SUBSTRATE_UNITS, *units])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("copyparty", self.trace.read_text())
        self.assertEqual(self.is_active_queries()[-2:], units)

    def test_v2_enabled_copyparty_that_is_inactive_fails_health(self):
        units = ["copyparty.service", "syncthing.service"]
        result = self.protected_health(units, [*self.SUBSTRATE_UNITS, "syncthing.service"], copyparty_socket=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("did not become active within 1s: copyparty.service (inactive)", result.stderr)
        self.assertNotIn("--unix-socket", self.trace.read_text())

    def test_v2_enabled_copyparty_requires_its_listener_and_http_answer(self):
        units = ["copyparty.service"]
        missing = self.protected_health(units, [*self.SUBSTRATE_UNITS, *units])
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn("CopyParty Unix listener is missing", missing.stderr)
        self.trace.unlink()
        present = self.protected_health(units, [*self.SUBSTRATE_UNITS, *units], copyparty_socket=True)
        self.assertEqual(present.returncode, 0, present.stdout + present.stderr)
        self.assertIn(str(self.root / "sockets" / "copyparty.sock"), self.trace.read_text())

    def test_units_still_activating_after_restart_are_polled_until_active(self):
        units = ["syncthing.service", "nas-v2-photos.service"]
        result = self.protected_health(
            units,
            self.SUBSTRATE_UNITS,
            states={"syncthing.service": ["activating", "active"], "nas-v2-photos.service": ["inactive", "active"]},
            settle_seconds=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.is_active_queries().count("nas-v2-photos.service"), 2)

    def test_units_that_never_become_active_fail_at_the_deadline(self):
        result = self.protected_health(
            ["nas-v2-photos.service"], self.SUBSTRATE_UNITS, states={"nas-v2-photos.service": ["activating"]}
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("did not become active within 1s: nas-v2-photos.service (activating)", result.stderr)

    def test_failed_unit_fails_without_waiting_for_the_deadline(self):
        result = self.protected_health(
            ["nas-v2-photos.service"],
            self.SUBSTRATE_UNITS,
            states={"nas-v2-photos.service": ["failed"]},
            settle_seconds=3600,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Managed Services V2 units failed: nas-v2-photos.service", result.stderr)
        self.assertEqual(self.is_active_queries().count("nas-v2-photos.service"), 1)

    def test_readiness_gates_need_only_to_have_not_failed(self):
        units = ["nas-v2-ready-metrics.service", "victoriametrics.service"]
        passed = self.protected_health(
            units,
            [*self.SUBSTRATE_UNITS, "victoriametrics.service"],
            readiness=["nas-v2-ready-metrics.service"],
        )
        self.assertEqual(passed.returncode, 0, passed.stdout + passed.stderr)
        self.trace.unlink()
        running = self.protected_health(
            units,
            [*self.SUBSTRATE_UNITS, "victoriametrics.service"],
            readiness=["nas-v2-ready-metrics.service"],
            states={"nas-v2-ready-metrics.service": ["activating", "inactive"]},
            settle_seconds=30,
        )
        self.assertEqual(running.returncode, 0, running.stdout + running.stderr)
        self.trace.unlink()
        failed = self.protected_health(
            units,
            [*self.SUBSTRATE_UNITS, "victoriametrics.service"],
            readiness=["nas-v2-ready-metrics.service"],
            states={"nas-v2-ready-metrics.service": ["failed"]},
        )
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("units failed: nas-v2-ready-metrics.service", failed.stderr)
        self.trace.unlink()
        # Without readinessUnits the same oneshot gate would be required to stay active.
        ungated = self.protected_health(units, [*self.SUBSTRATE_UNITS, "victoriametrics.service"])
        self.assertIn("nas-v2-ready-metrics.service (inactive)", ungated.stderr)

    def test_health_waits_for_reconciliation_to_settle_before_reading_v2_state(self):
        result = self.protected_health(
            ["syncthing.service"], [*self.SUBSTRATE_UNITS, "syncthing.service"], pending=True
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("reconciliation is pending or running", result.stderr)
        self.assertNotIn("syncthing.service", self.is_active_queries())
        self.trace.unlink()
        settling = self.protected_health(
            ["syncthing.service"],
            [*self.SUBSTRATE_UNITS, "syncthing.service"],
            states={"nas-managed-services-reconcile.service": ["activating", "inactive"]},
            settle_seconds=30,
        )
        self.assertEqual(settling.returncode, 0, settling.stdout + settling.stderr)

    def test_unit_names_accepted_by_v2_are_queried_after_end_of_options(self):
        units = [":leading-colon.service", "-.slice-like.target"]
        result = self.protected_health(units, [*self.SUBSTRATE_UNITS, *units])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for unit in units:
            self.assertIn(f"pkgs.systemd:systemctl is-active -- {unit}", self.trace.read_text())

    def test_v2_target_owner_units_are_accepted_and_required(self):
        units = ["nas-v2-wiki.target", "nas-v2-source-wiki.path"]
        result = self.protected_health(units, [*self.SUBSTRATE_UNITS, *units])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.trace.unlink()
        down = self.protected_health(units, [*self.SUBSTRATE_UNITS, "nas-v2-source-wiki.path"])
        self.assertIn("nas-v2-wiki.target (inactive)", down.stderr)

    def test_failed_custom_application_expected_by_v2_fails_health(self):
        units = ["nas-v2-photos.service", "nas-v2-activation-wiki-web.socket"]
        result = self.protected_health(units, [*self.SUBSTRATE_UNITS, "nas-v2-activation-wiki-web.socket"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("nas-v2-photos.service (inactive)", result.stderr)

    def test_fixed_substrate_is_still_required_with_an_empty_v2_start_set(self):
        result = self.protected_health([], self.SUBSTRATE_UNITS)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for unit in self.SUBSTRATE_UNITS[1:]:
            with self.subTest(unit=unit):
                self.trace.unlink()
                failed = self.protected_health([], [item for item in self.SUBSTRATE_UNITS if item != unit])
                self.assertNotEqual(failed.returncode, 0)
                self.assertIn(f"{unit} is not active", failed.stderr)

    def test_unavailable_or_malformed_v2_state_fails_closed_before_application_queries(self):
        cases = {
            "invalid-json": "{",
            "not-object": "[]",
            "missing": "{}",
            "no-version": '{"startUnits": []}',
            "wrong-version": '{"schemaVersion": 2, "startUnits": []}',
            "non-array": '{"schemaVersion": 1, "startUnits": "copyparty.service"}',
            "non-string": '{"schemaVersion": 1, "startUnits": [3]}',
            "space": '{"schemaVersion": 1, "startUnits": ["a b.service"]}',
            "backslash": '{"schemaVersion": 1, "startUnits": ["a\\\\x2d.service"]}',
            "shell": '{"schemaVersion": 1, "startUnits": ["a;b.service"]}',
            "not-a-unit": '{"schemaVersion": 1, "startUnits": ["copyparty"]}',
            "bad-readiness": '{"schemaVersion": 1, "startUnits": [], "readinessUnits": "nas-v2-ready-x.service"}',
            "unsafe-readiness": '{"schemaVersion": 1, "startUnits": [], "readinessUnits": ["a b.service"]}',
        }
        for name, raw in cases.items():
            with self.subTest(case=name):
                self.trace.unlink(missing_ok=True)
                result = self.protected_health([], self.SUBSTRATE_UNITS, raw_state=raw)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Managed Services V2 start state", result.stderr)
                self.assertEqual(
                    self.is_active_queries(), [*self.SUBSTRATE_UNITS, "nas-managed-services-reconcile.service"]
                )
        (self.root / "systemd-reconciled.json").unlink()
        self.trace.unlink(missing_ok=True)
        prelude = (
            f"protected_was_active=true\nv2_systemd_state={shlex.quote(str(self.root / 'absent.json'))}\n"
            "application_settle_seconds=1\n"
        )
        absent = self.run_function(prelude + "application_health")
        self.assertNotEqual(absent.returncode, 0)
        self.assertIn("start state is unavailable", absent.stderr)

    def test_persistent_profile_rollback_uses_symlink_target_changes(self):
        # A switch that fails without moving the profile must not step the
        # persistent profile back one generation.
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

    def run_profile_guard(self, system_profile: Path) -> subprocess.CompletedProcess[str]:
        command = (
            "set -Eeuo pipefail\n"
            'system_profile="$1"\n'
            + self.old_profile_expression
            + "\n"
            + self.profile_guard
            + '\necho "guard-passed"\n'
        )
        return subprocess.run(
            [self.bash, "--noprofile", "--norc", "-c", command, "--", str(system_profile)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            env={**os.environ, "LC_ALL": "C"},
        )

    def test_dangling_system_profile_is_detected_before_activation(self):
        # A dangling system_profile link resolves via readlink -f to a nonempty
        # path whose target does not exist, so the updater guard must refuse
        # activation. -e follows the link; relative targets resolve from its dir.
        dangling = self.root / "system-profile"
        dangling.symlink_to(self.root / "missing-final-target")
        result = self.run_profile_guard(dangling)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("refusing activation without a rollback baseline", result.stderr)
        self.assertNotIn("guard-passed", result.stdout)

        # An absent profile has no rollback baseline either.
        result = self.run_profile_guard(self.root / "system-profile-absent")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("refusing activation without a rollback baseline", result.stderr)
        self.assertNotIn("guard-passed", result.stdout)

        # An existing, resolvable profile passes the guard.
        real = self.root / "real-profile"
        real.write_text("")
        valid = self.root / "system-profile-valid"
        valid.symlink_to(real)
        result = self.run_profile_guard(valid)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("guard-passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
