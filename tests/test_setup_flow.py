"""Setup flow tests - validates code/config changes."""

import argparse
import contextlib
import json
import pathlib
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_setup as setup  # noqa: E402


class TestBrowserBootstrapPages(unittest.TestCase):
    """The wizard and the locked notice are the only static setup pages."""

    def test_unserved_portal_templates_stay_removed(self):
        # The canonical wizard replaced web/portal/setup.html and Authentik's
        # library replaced its launcher; web/locked is the served locked page.
        self.assertFalse((ROOT / "web/portal").exists())
        self.assertTrue((ROOT / "web/locked/index.html").is_file())
        for path in (ROOT / "modules").rglob("*.nix"):
            with self.subTest(path=path.relative_to(ROOT)):
                text = path.read_text(encoding="utf-8")
                self.assertNotIn("nasPortalStatic", text)
                self.assertNotIn("web/portal", text)


class TestCaddyConfig(unittest.TestCase):
    """Tests for Caddy configuration changes."""

    def test_caddy_bootstrap_sends_home_and_unknown_paths_to_authentik_launcher(self):
        """Authentik owns the appliance home page in both Caddy configurations."""
        bootstrap_path = pathlib.Path(ROOT / "modules/nas/config/caddy-bootstrap.nix")
        self.assertTrue(pathlib.Path(bootstrap_path).exists(), "caddy-bootstrap.nix should exist")
        content = bootstrap_path.read_text(encoding="utf-8")

        # Authentik must remain reachable without forward-auth to avoid a loop.
        for route in ("handle @authentikUi {", "handle @authentikOutpost {"):
            with self.subTest(route=route):
                start = content.index(route)
                end = content.index("\n  }", start)
                self.assertNotIn("${caddyForwardAuth}", content[start:end])

        canonical = content[content.index("handle /setup {") : content.index("handle /setup/* {")]
        self.assertIn("redir /setup /setup/ 308", canonical)

        setup_start = content.index("handle /setup/* {")
        setup_end = content.find("\n  }\n", setup_start)
        self.assertIn("${caddyForwardAuth}", content[setup_start:setup_end], "/setup/* must require Authentik")

        console_start = content.index("handle /console* {")
        console_end = content.find("\n  }\n", console_start)
        console = content[console_start:console_end]
        self.assertIn("${caddyForwardAuth}", console)
        self.assertIn("respond @missingCockpitAdmin 403", console)
        self.assertIn("reverse_proxy unix//run/nas-cockpit-sso/ws.sock", console)

        root = content[content.index("handle / {") : content.index("handle /setup {")]
        self.assertIn("redir * ${cfg.identity.authentikPath}if/user/ 303", root)
        fallback = content[content.rindex("handle {") :]
        self.assertIn("redir * ${cfg.identity.authentikPath}if/user/ 303", fallback)

    def test_caddy_no_shell_conditionals(self):
        """Verify Caddy config doesn't have invalid shell conditionals."""
        bootstrap_path = pathlib.Path(ROOT / "modules/nas/config/caddy-bootstrap.nix")
        content = bootstrap_path.read_text()
        lines = content.split("\n")
        shell_if_lines = [i for i, line in enumerate(lines) if "if [ -f" in line]
        self.assertEqual(len(shell_if_lines), 0, "Caddy config should not have shell if conditionals")


class TestApplicationChanges(unittest.TestCase):
    """Tests for application configuration changes."""

    def test_copyparty_does_not_use_absolute_statedirectory(self):
        """Absolute StateDirectory values are ignored by systemd."""
        app_path = pathlib.Path(ROOT / "modules/nas/config/application-services.nix")
        self.assertTrue(pathlib.Path(app_path).exists(), "application-services.nix should exist")
        content = app_path.read_text()
        copyparty = content[content.index("systemd.services.copyparty = {") :]
        copyparty = copyparty[: copyparty.index("systemd.services.syncthing")]
        self.assertIn('serviceConfig.StateDirectory = lib.mkForce "";', copyparty)
        self.assertIn("serviceConfig.WorkingDirectory = lib.mkForce copypartyDataDir;", copyparty)
        self.assertIn("environment.XDG_CONFIG_HOME = lib.mkForce copypartyDataDir;", copyparty)
        self.assertNotIn("${cfg.zfsRoot}/copyparty", copyparty)

    def test_vaultwarden_statedirectory_override(self):
        """Verify vaultwarden StateDirectory is overridden."""
        app_path = pathlib.Path(ROOT / "modules/nas/config/application-services.nix")
        content = app_path.read_text()
        self.assertIn("StateDirectory", content, "Should have StateDirectory override for vaultwarden")


class TestSecurityExpectations(unittest.TestCase):
    """Tests for security expectations from the setup flow."""

    def test_no_shell_if_in_caddyfile(self):
        """Ensure no shell if conditionals in Caddy config."""
        bootstrap_path = pathlib.Path(ROOT / "modules/nas/config/caddy-bootstrap.nix")
        content = bootstrap_path.read_text()
        lines = content.split("\n")
        has_shell_if = any("if [ -f" in line for line in lines)
        self.assertFalse(has_shell_if, "Caddy config should not contain shell if conditionals")


class ManagedServicesMountSeedTests(unittest.TestCase):
    def test_desired_state_seed_waits_for_data_mount_and_first_run_restarts_it(self) -> None:
        managed = (ROOT / "modules/nas/config/managed-services.nix").read_text(encoding="utf-8")
        seed = managed.split("systemd.services.nas-managed-services-seed = {", 1)[1]
        seed = seed.split("systemd.services.nas-managed-services-reconcile = {", 1)[0]
        self.assertIn("unitConfig.ConditionPathIsMountPoint = cfg.zfsRoot;", seed)
        self.assertIn('after = [ "nas-zfs-mount-guard.service" ];', seed)
        self.assertIn("mountpoint -q -- ${lib.escapeShellArg cfg.zfsRoot}", managed)
        reconcile = managed.split("systemd.services.nas-managed-services-reconcile = {", 1)[1]
        self.assertIn("AssertPathIsMountPoint = cfg.zfsRoot;", reconcile)
        setup_source = (ROOT / "services/nas_setup.py").read_text(encoding="utf-8")
        storage = setup_source.split("def prepare_storage_runtime(", 1)[1]
        storage = storage.split("def storage_runtime_ready(", 1)[0]
        self.assertIn('run_root(["systemctl", "restart", "nas-managed-services-seed.service"])', storage)


class FirstRunRecoveryTests(unittest.TestCase):
    """The first-run guard must fail closed and recover an interrupted journal."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        self.state_path = self.root / "state.json"
        self.journal_path = self.root / "journal.json"
        paths = mock.patch.multiple(
            setup,
            STATE_PATH=self.state_path,
            JOURNAL_PATH=self.journal_path,
            FIRST_START_STATUS_PATH=self.root / "first-start-status.json",
        )
        paths.start()
        self.addCleanup(paths.stop)

    def args(self, digest: str = "a" * 64) -> argparse.Namespace:
        return argparse.Namespace(
            reservation_token=None, confirm_plan_digest=digest, config=str(self.root / "setup.json")
        )

    def report(self, digest: str = "a" * 64, status: str = "complete") -> dict:
        return {
            "schemaVersion": 1,
            "status": status,
            "planDigest": digest,
            "completedAt": 1_700_000_000,
            "durationSeconds": 12,
        }

    def write_journal(self, report: dict, status: str = "running") -> None:
        self.journal_path.write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "workflow": "first-run-v2",
                    "fingerprint": "f" * 64,
                    "status": status,
                    "steps": {"final-state": {"status": "complete", "completedAt": 1_700_000_000, "result": report}},
                }
            ),
            encoding="utf-8",
        )

    def run_first_run(self, args: argparse.Namespace) -> dict:
        with (
            mock.patch.object(setup, "acquire_operation", return_value=contextlib.nullcontext()),
            mock.patch.object(setup, "run_root", return_value=setup.Completed((), "", "")),
            mock.patch.object(setup, "run_root_noninteractive", return_value=SimpleNamespace(returncode=0)),
            mock.patch.object(setup, "ensure_secret_gated_services"),
        ):
            return setup.first_run(args)

    def test_corrupt_or_unreadable_state_fails_closed_without_restarting_setup(self) -> None:
        self.state_path.write_text("{not json", encoding="utf-8")
        with (
            mock.patch.object(setup, "acquire_operation") as acquire,
            mock.patch.object(setup, "_first_run_locked") as locked,
        ):
            with self.assertRaisesRegex(setup.SetupError, "corrupt"):
                setup.first_run(self.args())
        acquire.assert_not_called()
        locked.assert_not_called()

        self.state_path.unlink()
        self.state_path.mkdir()
        with (
            mock.patch.object(setup, "acquire_operation") as acquire,
            mock.patch.object(setup, "_first_run_locked") as locked,
        ):
            with self.assertRaisesRegex(setup.SetupError, "unreadable"):
                setup.first_run(self.args())
        acquire.assert_not_called()
        locked.assert_not_called()

    def test_absent_state_still_permits_the_first_run(self) -> None:
        with (
            mock.patch.object(setup, "acquire_operation", return_value=contextlib.nullcontext()),
            mock.patch.object(setup, "_first_run_locked", return_value={"status": "complete"}) as locked,
            mock.patch.object(setup, "run_root", return_value=setup.Completed((), "", "")),
            mock.patch.object(setup, "run_root_noninteractive", return_value=SimpleNamespace(returncode=0)),
            mock.patch.object(setup, "ensure_secret_gated_services"),
        ):
            self.assertEqual(setup.first_run(self.args()), {"status": "complete"})
        locked.assert_called_once()

    def test_completed_state_with_interrupted_journal_finishes_the_journal(self) -> None:
        report = self.report()
        self.state_path.write_text(json.dumps(report), encoding="utf-8")
        self.write_journal(report)
        with (
            mock.patch.object(setup, "_first_run_locked") as locked,
            mock.patch.object(setup, "prepare_first_start") as published,
        ):
            result = self.run_first_run(self.args())
        locked.assert_not_called()
        self.assertEqual(result, report)
        journal = json.loads(self.journal_path.read_text(encoding="utf-8"))
        self.assertEqual(journal["status"], "complete")
        self.assertEqual(journal["result"], report)
        published.assert_called_once_with(self.args().config)

    def test_completed_state_is_rechecked_inside_the_lock(self) -> None:
        report = self.report()
        with (
            mock.patch.object(setup, "completed_setup_report", side_effect=[None, report]) as completed,
            mock.patch.object(setup, "_first_run_locked") as locked,
        ):
            result = self.run_first_run(self.args())
        self.assertEqual(completed.call_count, 2)
        locked.assert_not_called()
        self.assertEqual(result, report)

    def test_completed_state_still_requires_recovery_acknowledgement_and_matching_plan(self) -> None:
        report = self.report()
        self.state_path.write_text(json.dumps(report), encoding="utf-8")
        self.write_journal(report, status="manual-recovery-required")
        with self.assertRaisesRegex(setup.SetupError, "acknowledge manual recovery"):
            self.run_first_run(self.args())

        self.write_journal(report)
        with self.assertRaisesRegex(setup.SetupError, "different plan"):
            self.run_first_run(self.args(digest="b" * 64))


if __name__ == "__main__":
    unittest.main()
