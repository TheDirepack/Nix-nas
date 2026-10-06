"""Contracts for the installed two-reboot setup lifecycle runner."""

from __future__ import annotations

import importlib.util
import io
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

    def test_reboot_reactivation_checks_locked_state_and_sends_password_only_on_stdin(self) -> None:
        runner = self.runner()
        calls = []

        def require(command, **_kwargs):
            calls.append(command)
            if command == ("nas-setup", "status"):
                return '{"runtimeSecretsActive":false}'
            return ""

        def run(*command, **kwargs):
            calls.append(command)
            if command[0] == "systemctl":
                return subprocess.CompletedProcess(command, 3, "", "")
            self.assertEqual(command[-2:], ("nas-secrets", "activate-stdin"))
            self.assertEqual(kwargs["input_text"], "nixos-nas-vm-test-password\n")
            self.assertEqual(kwargs["timeout"], 600)
            self.assertNotIn("nixos-nas-vm-test-password", " ".join(command))
            return subprocess.CompletedProcess(command, 0, "", "")

        with (
            mock.patch.object(runner, "require", side_effect=require),
            mock.patch.object(runner, "run", side_effect=run),
            mock.patch.object(runner, "wait_active") as wait_active,
        ):
            runner.activate_after_reboot()
        wait_active.assert_called_once_with("nas-authentik-proxy-outpost.service", timeout_seconds=120)
        self.assertEqual(calls[0], ("nas-setup", "status"))
        self.assertEqual(calls[2], ("zpool", "import", "-N", "tank"))
        self.assertEqual(
            calls[3][:8], ("runuser", "-u", "nasadmin", "--", "env", "-C", "/", "HOME=/tank/homes/nasadmin")
        )

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
        self.assertIn('"http://127.0.0.1:9092/console/"', source)
        self.assertIn('"http://127.0.0.1:9010/outpost.goauthentik.io/ping"', source)
        self.assertIn('require(("zpool", "import", "-N", "tank"))', source)
        self.assertIn('input_text="nixos-nas-vm-test-password\\n"', source)
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


if __name__ == "__main__":
    unittest.main()
