from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class BacklogCompletionTests(unittest.TestCase):
    def test_active_backlog_was_retired(self) -> None:
        self.assertFalse((ROOT / "docs/development/backlog.md").exists())
        self.assertTrue((ROOT / "docs/development/dependencies.md").is_file())

    def test_service_policy_uses_canonical_v2_modules_and_is_packaged(self) -> None:
        account_tools = (ROOT / "modules/nas/internal/account-tools.nix").read_text()
        pyproject = (ROOT / "pyproject.toml").read_text()
        self.assertIn("buildPythonApplication", account_tools)
        self.assertFalse((ROOT / "services/nas_feature_model.py").exists())
        for name in ("nas_v2_spec", "nas_v2_control", "nas_v2_editor", "nas_identity_model", "nas_setup_config"):
            self.assertTrue((ROOT / "services" / f"{name}.py").is_file())
            self.assertIn(f'"{name}"', pyproject)

    def test_secret_transaction_and_fault_injection_are_wired(self) -> None:
        secret_tools = (ROOT / "modules/nas/internal/secret-tools.nix").read_text()
        bats = (ROOT / "tests/bats/nas-secret-transaction.bats").read_text()
        self.assertIn("nas-secret-transaction.sh", secret_tools)
        self.assertIn("termination after swap restores the prior tree", bats)
        secret_tools = (ROOT / "modules/nas/internal/secret-tools.nix").read_text(encoding="utf-8")
        self.assertIn("trap cleanup EXIT", secret_tools)
        self.assertIn("trap 'exit 143' TERM", secret_tools)
        self.assertNotIn("trap cleanup EXIT HUP INT TERM", secret_tools)

    def test_browser_matrix_covers_all_capabilities_and_baseline_user(self) -> None:
        browser = (ROOT / "tests/browser/authz.py").read_text()
        for capability in ("files", "webdav", "ai", "vault", "syncthing"):
            self.assertIn(f'"{capability}"', browser)
        self.assertIn('"baseline"', browser)
        self.assertIn('RouteExpectation("/syncthing/", False)', browser)

    def test_live_drill_entry_points_exist(self) -> None:
        script = (ROOT / "scripts/live-validation.sh").read_text()
        for command in ("locked-boot", "copyparty", "syncoid", "restic", "authentik", "observability"):
            self.assertIn(command, script)


if __name__ == "__main__":
    unittest.main()
