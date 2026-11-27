"""Contracts for the installed two-reboot setup lifecycle runner."""

from __future__ import annotations

import ast
import importlib.util
import io
import json
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
RUNNER = ROOT / "tests/vm/setup-reboot-e2e.py"
VM_FIXTURE = ROOT / "tests/nixos/vm-common.nix"


class SetupRebootE2eContracts(unittest.TestCase):
    @staticmethod
    def runner():
        spec = importlib.util.spec_from_file_location("setup_reboot_e2e", RUNNER)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_browser_failure_preserves_complete_diagnostics_and_proxy_status(self) -> None:
        runner = self.runner()
        detail = "head" * 400 + "UNCLIPPED-BROWSER-EXCEPTION" + "tail" * 600
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            (root / "bin").mkdir()
            (root / "lib/systemd").mkdir(parents=True)
            (root / "bin/systemd-socket-activate").touch()
            (root / "lib/systemd/systemd-socket-proxyd").touch()
            secrets = root / "secrets"
            secrets.mkdir()
            temporary = mock.MagicMock()
            temporary.__enter__.return_value = str(secrets)
            with (
                mock.patch.object(runner.shutil, "which", return_value=str(root / "bin/systemctl")),
                mock.patch.object(runner.tempfile, "TemporaryDirectory", return_value=temporary),
                mock.patch.object(runner, "wait_http"),
                mock.patch.object(runner.subprocess, "Popen") as popen,
                mock.patch.object(
                    runner.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", detail)
                ),
                mock.patch.object(runner.sys, "stderr", stderr),
                self.assertRaises(runner.CheckError),
            ):
                popen.return_value.poll.return_value = -9
                runner.browser_sign_in("test reboot")
            self.assertIn(detail, stderr.getvalue())
            self.assertIn("callback proxy exit status: -9", stderr.getvalue())
            self.assertIs(popen.call_args.kwargs["stderr"], stderr)
            self.assertIs(popen.call_args.kwargs["restore_signals"], False)
            popen.return_value.terminate.assert_called_once_with()
            popen.return_value.wait.assert_called_once_with(timeout=20)

    def test_final_reboot_verification_reuses_activation_health_and_browser_checks(self) -> None:
        runner = self.runner()
        calls = []
        with (
            mock.patch.object(runner.sys, "argv", ["setup-reboot-e2e.py", "--verify"]),
            mock.patch.object(runner, "activate_after_reboot", side_effect=lambda: calls.append("activate")),
            mock.patch.object(runner, "verify_services", side_effect=lambda stage: calls.append(("health", stage))),
            mock.patch.object(runner, "browser_sign_in", side_effect=lambda stage: calls.append(("browser", stage))),
        ):
            self.assertEqual(runner.main(), 0)
        self.assertEqual(calls, ["activate", ("health", "the final reboot"), ("browser", "the final reboot")])

    def test_post_switch_doctor_runs_only_after_canonical_reboot_verification(self) -> None:
        source = (ROOT / "scripts/qemu-test.sh").read_text(encoding="utf-8")
        final_boot = source.split('log "Rebooting the switched generation for persistence verification"', 1)[1]
        verification = "nas-vm-guest-test --setup-reboot-e2e --verify"
        self.assertIn(verification, final_boot)
        self.assertLess(final_boot.index(verification), final_boot.index("nas-doctor --json"))

    def test_reboot_health_does_not_ignore_failed_rollback(self) -> None:
        runner = self.runner()
        status = '{"runtimeSecretsActive":true,"poolPresent":true,"datasetPresent":true}'
        with (
            mock.patch.object(runner, "require", return_value=status),
            mock.patch.object(runner, "run", return_value=subprocess.CompletedProcess([], 0, "", "")),
            self.assertRaisesRegex(runner.CheckError, "rollback.*failed"),
        ):
            runner.verify_services("test reboot")

    def test_reboot_unlocks_through_the_unlock_api_with_the_password_only_on_stdin(self) -> None:
        runner = self.runner()
        calls = []
        started = iter(["100", "200"])

        def require(command, **_kwargs):
            calls.append(command)
            if command == ("nas-setup", "status"):
                return '{"runtimeSecretsActive":false}'
            if command[:2] == ("systemctl", "show"):
                return next(started)
            return ""

        def run(*command, **kwargs):
            calls.append(command)
            if command[0] == "systemctl":
                return subprocess.CompletedProcess(command, 3, "", "")
            self.assertEqual(command[0], "curl")
            self.assertIn("/run/nas-unlock/unlock.sock", command)
            self.assertIn("Remote-Groups: nas_admin", command)
            self.assertNotIn("nixos-nas-vm-test-password", " ".join(command))
            password = json.loads(kwargs["input_text"])["password"]
            if password == "nixos-nas-vm-test-password":
                return subprocess.CompletedProcess(command, 0, '{"locked": false, "unlocked": true}\n200', "")
            return subprocess.CompletedProcess(command, 0, '{"error": "not accepted"}\n401', "")

        with (
            mock.patch.object(runner, "require", side_effect=require),
            mock.patch.object(runner, "run", side_effect=run),
            mock.patch.object(runner, "verify_locked_browser_surface") as locked_surface,
            mock.patch.object(runner, "wait_active") as wait_active,
            mock.patch.object(runner.time, "sleep"),
            mock.patch.object(runner.pathlib.Path, "exists", return_value=False),
        ):
            runner.activate_after_reboot()
        locked_surface.assert_called_once_with()
        wait_active.assert_any_call("nas-authentik-proxy-outpost.service", timeout_seconds=120)
        self.assertEqual(calls[0], ("nas-setup", "status"))
        self.assertIn(("nas-vm-guest-test", "--oci-probe", "locked"), calls)
        self.assertIn(("zpool", "import", "-N", "tank"), calls)
        self.assertEqual(sum(1 for call in calls if call[0] == "curl"), 2)

    def test_reboot_requires_authentik_restart_after_unlock(self) -> None:
        runner = self.runner()

        def require(command, **_kwargs):
            if command == ("nas-setup", "status"):
                return '{"runtimeSecretsActive":false}'
            return "100" if command[:2] == ("systemctl", "show") else ""

        def run(*command, **kwargs):
            if command[0] == "systemctl":
                return subprocess.CompletedProcess(command, 3, "", "")
            if json.loads(kwargs["input_text"])["password"] == "nixos-nas-vm-test-password":
                return subprocess.CompletedProcess(command, 0, '{"unlocked": true}\n200', "")
            return subprocess.CompletedProcess(command, 0, '{"error": "x"}\n401', "")

        with (
            mock.patch.object(runner, "require", side_effect=require),
            mock.patch.object(runner, "run", side_effect=run),
            mock.patch.object(runner, "verify_locked_browser_surface"),
            mock.patch.object(runner, "wait_active"),
            mock.patch.object(runner.time, "sleep"),
            self.assertRaisesRegex(Exception, "not restarted"),
        ):
            runner.activate_after_reboot()

    def locked_surface(self, responses):
        runner = self.runner()
        requests = []

        def run(*command, **_kwargs):
            requests.append(command)
            path = command[-1].removeprefix("https://nas-test.local")
            method = "POST" if "--request" in command else "GET"
            code, location, body = responses(method, path)
            return subprocess.CompletedProcess(command, 0, f"{body}\n{code} {location}", "")

        def exists(path):
            return str(path).endswith("outpost-token")

        with (
            mock.patch.object(runner, "run", side_effect=run),
            mock.patch.object(runner, "wait_active"),
            mock.patch.object(runner.pathlib.Path, "exists", exists),
            mock.patch.object(runner.pathlib.Path, "is_file", exists),
        ):
            runner.verify_locked_browser_surface()
        return runner, requests

    @staticmethod
    def healthy_locked(method, path):
        if path == "/unlock/":
            return "302", "https://nas-test.local/outpost.goauthentik.io/start", ""
        if path == "/unlock/api/activate":
            return "302", "https://nas-test.local/outpost.goauthentik.io/start", ""
        if path == "/identity/-/health/live/":
            return "204", "", ""
        return "303", "https://nas-test.local/unlock/", ""

    def test_locked_boot_serves_only_sign_in_and_the_gated_unlock_page(self) -> None:
        _runner, requests = self.locked_surface(self.healthy_locked)
        paths = [command[-1].removeprefix("https://nas-test.local") for command in requests]
        for route in ("/", "/console/", "/identity/if/admin/", "/unlock/", "/unlock/api/activate", "/setup/api/reboot"):
            self.assertIn(route, paths)

        def override(target, answer):
            return lambda method, path: answer if path == target else self.healthy_locked(method, path)

        for label, responses in (
            ("Cockpit proxied", override("/console/", ("200", "", "cockpit"))),
            ("admin interface served", override("/identity/if/admin/", ("200", "", "admin"))),
            ("unlock page without sign-in", override("/unlock/", ("200", "", '<form id="unlock-form">'))),
            ("unlock API without sign-in", override("/unlock/api/activate", ("200", "", '{"unlocked": true}'))),
            ("Authentik down", override("/identity/-/health/live/", ("503", "", "notice"))),
            ("setup API reachable", override("/setup/api/reboot", ("200", "", '{"rebooting": true}'))),
        ):
            with self.subTest(label), self.assertRaises(Exception) as raised:
                self.locked_surface(responses)
            self.assertEqual(type(raised.exception).__name__, "CheckError")

    def test_runner_rechecks_storage_v2_apps_and_authenticated_routes_after_each_reboot(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn('"after-first-reboot"', source)
        self.assertIn('"after-second-reboot"', source)
        self.assertIn("verifiedReboots=2", source)
        self.assertIn('"copyparty.service"', source)
        self.assertIn('"syncthing.service"', source)
        self.assertIn('"vaultwarden.service"', source)
        self.assertIn('"grafana.service"', source)
        self.assertIn('"nas-authentik-proxy-outpost.service"', source)
        self.assertIn('"nas-cockpit-sso.service"', source)
        self.assertIn('"nas-managed-services-control", "status"', source)
        self.assertIn('"tests/browser/authz.py"', source)
        self.assertIn('"/tank/shares/e2e-reboot-sentinel.txt"', source)
        self.assertIn("lib/systemd/systemd-socket-proxyd", source)
        self.assertIn('"--resolve"', source)
        self.assertIn('"nas-test.local:8443:127.0.0.1"', source)
        self.assertIn('"http://127.0.0.1:8222/vault/alive"', source)
        cockpit_probes = [
            node
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "wait_http"
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value == "Cockpit"
        ]
        self.assertEqual(len(cockpit_probes), 1)
        self.assertEqual(
            ast.literal_eval(cockpit_probes[0].args[0]),
            (
                "curl",
                "--fail",
                "--silent",
                "--show-error",
                "--max-time",
                "10",
                "--unix-socket",
                "/run/nas-cockpit-sso/ws.sock",
                "http://localhost/console/",
            ),
        )
        self.assertIn('"http://127.0.0.1:9010/outpost.goauthentik.io/ping"', source)
        self.assertIn('require(("zpool", "import", "-N", "tank"))', source)
        self.assertIn('KEEPASS_PASSWORD = "nixos-nas-vm-test-password"', source)
        self.assertIn('"nas-unlock-api.service"', source)
        self.assertIn("activate_after_reboot()", source)
        self.assertIn('"nas-managed-services-reconcile.service"', source)

    def test_runner_resumes_through_the_vm_only_systemd_unit(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        fixture = VM_FIXTURE.read_text(encoding="utf-8")
        self.assertIn("systemd.services.nas-vm-setup-reboot-e2e", fixture)
        self.assertIn('ConditionPathExists = "/var/lib/nas-test/setup-reboot-e2e-state.json"', fixture)
        self.assertIn('"${guestTest}/bin/nas-vm-guest-test --setup-reboot-e2e --resume"', fixture)
        self.assertIn('wantedBy = [ "multi-user.target" ]', fixture)
        self.assertIn("path = [ config.system.path ];", fixture)
        self.assertIn('f"--unit=nas-vm-setup-reboot-e2e-{next_phase}"', source)
        self.assertIn('"nas-bootstrap-runtime-select.service" ];', fixture)
        self.assertNotIn('UNIT = pathlib.Path("/etc/systemd/system/', source)

    def test_failed_verification_reports_bridge_unit_state_before_disposal(self) -> None:
        runner = self.runner()
        stderr = io.StringIO()
        commands: list[tuple[str, ...]] = []

        def run(*command, **_kwargs):
            commands.append(command)
            if command[:2] == ("systemctl", "--failed"):
                return subprocess.CompletedProcess(command, 0, "  UNIT loaded active running caddy\n", "")
            if command[0] == "systemctl" and command[1] == "show":
                unit = command[2]
                return subprocess.CompletedProcess(
                    command,
                    0,
                    f"Id={unit}\nActiveState=active\nSubState=running\nNRestarts=3\n"
                    "Result=success\nExecMainStartTimestampMonotonic=100\n"
                    "ExecMainExitTimestampMonotonic=0\n",
                    "",
                )
            self.assertEqual(command[0], "journalctl")
            return subprocess.CompletedProcess(command, 0, "BRIDGE-JOURNAL-EVIDENCE\n", "")

        with (
            mock.patch.object(runner.sys, "argv", ["setup-reboot-e2e.py", "--verify"]),
            mock.patch.object(runner.sys, "stderr", stderr),
            mock.patch.object(runner, "run", side_effect=run),
            mock.patch.object(runner, "verify_reboot", side_effect=runner.CheckError("ORIGINAL-CHECK-FAILURE")),
        ):
            self.assertEqual(runner.main(), 1)

        output = stderr.getvalue()
        self.assertIn("setup reboot E2E failed: ORIGINAL-CHECK-FAILURE", output)
        self.assertIn("failed units:", output)
        self.assertIn("UNIT loaded active running caddy", output)
        for unit in runner.BRIDGE_UNITS:
            self.assertIn(f"{unit}:\nId={unit}", output)
            self.assertIn("NRestarts=3", output)
        self.assertIn("caddy and cockpit bridge journal:", output)
        self.assertIn("BRIDGE-JOURNAL-EVIDENCE", output)
        self.assertEqual(len([command for command in commands if command[1] == "show"]), len(runner.BRIDGE_UNITS))

    def test_failed_verification_diagnostics_failures_preserve_the_original_error(self) -> None:
        runner = self.runner()
        stderr = io.StringIO()

        def broken(*_command, **_kwargs):
            raise RuntimeError("diagnostics-broke")

        with (
            mock.patch.object(runner.sys, "argv", ["setup-reboot-e2e.py", "--verify"]),
            mock.patch.object(runner.sys, "stderr", stderr),
            mock.patch.object(runner, "run", side_effect=broken),
            mock.patch.object(runner, "verify_reboot", side_effect=runner.CheckError("ORIGINAL-CHECK-FAILURE")),
        ):
            self.assertEqual(runner.main(), 1)

        output = stderr.getvalue()
        self.assertIn("setup reboot E2E failed: ORIGINAL-CHECK-FAILURE", output)
        self.assertIn("failure diagnostics unavailable: diagnostics-broke", output)

    def test_detached_failure_emits_diagnostics_before_publishing_result_once(self) -> None:
        for broken in (False, True):
            with self.subTest(diagnostics_broken=broken):
                runner = self.runner()
                stderr = io.StringIO()
                order = []

                def diagnostics():
                    order.append("diagnostics")
                    if broken:
                        raise RuntimeError("diagnostics-broke")
                    return "DETACHED-FAILURE-EVIDENCE"

                def finish(*_args, **_kwargs):
                    order.append("result")

                with (
                    mock.patch.object(runner.sys, "argv", ["setup-reboot-e2e.py", "--resume"]),
                    mock.patch.object(runner.sys, "stderr", stderr),
                    mock.patch.object(runner, "read_state", return_value={"phase": "after-first-reboot"}),
                    mock.patch.object(runner, "verify_reboot", side_effect=runner.CheckError("ORIGINAL-CHECK-FAILURE")),
                    mock.patch.object(runner, "failure_diagnostics", side_effect=diagnostics),
                    mock.patch.object(runner, "finish", side_effect=finish),
                ):
                    self.assertEqual(runner.main(), 1)
                self.assertEqual(order, ["diagnostics", "result"])
                self.assertIn("ORIGINAL-CHECK-FAILURE", stderr.getvalue())
                self.assertIn("diagnostics-broke" if broken else "DETACHED-FAILURE-EVIDENCE", stderr.getvalue())

    def test_bridge_diagnostics_are_bounded_read_only_and_failure_only(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        diagnostics = source.split("def failure_diagnostics() -> str:", 1)[1].split("\ndef ", 1)[0]
        self.assertIn("systemctl", diagnostics)
        self.assertIn('"--failed"', diagnostics)
        self.assertIn(
            '"--property=ActiveState,SubState,NRestarts,Result,ExecMainStartTimestampMonotonic,"', diagnostics
        )
        self.assertIn('"journalctl"', diagnostics)
        self.assertIn("timeout=30", diagnostics)
        self.assertIn("timeout=15", diagnostics)
        for verb in ("stop", "restart", "start", "mask", "disable", "kill"):
            self.assertNotIn(f'"{verb}"', diagnostics)
        failure_handler = source.split("def report_failure(error: Exception) -> None:", 1)[1].split("\ndef ", 1)[0]
        self.assertIn("failure_diagnostics()", failure_handler)
        self.assertLess(
            failure_handler.index("setup reboot E2E failed"), failure_handler.index("failure_diagnostics()")
        )


if __name__ == "__main__":
    unittest.main()
