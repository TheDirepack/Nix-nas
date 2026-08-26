from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from typing import cast

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import prepare_release  # noqa: E402


class ReleaseAutomationTests(unittest.TestCase):
    def make_repo(self, root: pathlib.Path) -> None:
        files = {
            "VERSION": "1.2.3\n",
            "README.md": "# NixOS NAS 1.2.3\n\n> **Release status:** 1.2.3 is source-only.\n",
            "flake.nix": '{\n  description = "NixOS NAS 1.2.3 appliance";\n}\n',
            "CHANGELOG.md": "# Changelog\n\nIntro.\n\n## 1.2.3 — 2026-01-01\n\n### Added\n\n- Baseline.\n",
            "cockpit/package.json": json.dumps({"name": "test", "version": "1.2.3"}, indent=2) + "\n",
            "cockpit/package-lock.json": json.dumps(
                {
                    "name": "test",
                    "version": "1.2.3",
                    "lockfileVersion": 3,
                    "packages": {"": {"name": "test", "version": "1.2.3"}},
                },
                indent=2,
            )
            + "\n",
            "modules/nas/internal/secret-tools.nix": (
                'store_value authentik-bootstrap-password "old-bootstrap-password-123456"\n'
            ),
            "modules/nas/config/application-services.nix": (
                "printf '%s\\n' 'AUTHENTIK_BOOTSTRAP_PASSWORD=old-bootstrap-password-123456'\n"
            ),
            "docs/example.md": "Login with old-bootstrap-password-123456.\n",
        }
        for relative, content in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
        subprocess.run(["git", "add", "."], cwd=root, check=True)
        subprocess.run(["git", "commit", "-qm", "fixture"], cwd=root, check=True)

    def test_prepare_release_updates_version_and_all_tracked_password_references(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.make_repo(root)
            (root / "untracked.txt").write_text("old-bootstrap-password-123456\n", encoding="utf-8")
            metadata_path = root / ".tmp" / "release.json"
            metadata = prepare_release.prepare_release(
                root,
                run_number=4,
                source_sha="a" * 40,
                metadata_out=metadata_path,
                password="new-bootstrap-password-654321",
                release_date="2026-08-26",
            )

            self.assertEqual(metadata["version"], "1.2.4")
            self.assertEqual((root / "VERSION").read_text().strip(), "1.2.4")
            self.assertIn("# NixOS NAS 1.2.4", (root / "README.md").read_text())
            self.assertIn("NixOS NAS 1.2.4 appliance", (root / "flake.nix").read_text())
            package = json.loads((root / "cockpit/package.json").read_text())
            lock = json.loads((root / "cockpit/package-lock.json").read_text())
            self.assertEqual(package["version"], "1.2.4")
            self.assertEqual(lock["version"], "1.2.4")
            self.assertEqual(lock["packages"][""]["version"], "1.2.4")
            self.assertIn("## 1.2.4 — 2026-08-26", (root / "CHANGELOG.md").read_text())
            bootstrap_files = cast(list[str], metadata["bootstrap_files"])
            for relative in bootstrap_files:
                text = (root / relative).read_text()
                self.assertNotIn("old-bootstrap-password-123456", text)
                self.assertIn("new-bootstrap-password-654321", text)
            self.assertEqual((root / "untracked.txt").read_text(), "old-bootstrap-password-123456\n")
            on_disk = json.loads(metadata_path.read_text())
            self.assertEqual(on_disk["bootstrap_username"], "akadmin")
            self.assertEqual(on_disk["bootstrap_password"], "new-bootstrap-password-654321")

    def test_existing_tags_and_run_number_keep_patch_versions_monotonic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.make_repo(root)
            subprocess.run(["git", "tag", "v1.2.8"], cwd=root, check=True)
            current = prepare_release.Version.parse("1.2.3")
            self.assertEqual(str(prepare_release.next_version(root, current, 4)), "1.2.9")
            self.assertEqual(str(prepare_release.next_version(root, current, 12)), "1.2.12")

    def test_generated_password_matches_runtime_secret_atom_contract(self) -> None:
        for _ in range(20):
            password = prepare_release.generate_bootstrap_password()
            self.assertGreaterEqual(len(password), 20)
            prepare_release.validate_bootstrap_password(password)

    def test_current_bootstrap_seed_is_safe_and_shared_by_both_runtime_paths(self) -> None:
        password = prepare_release.discover_bootstrap_password(ROOT)
        prepare_release.validate_bootstrap_password(password)
        paths = {
            path.relative_to(ROOT).as_posix() for path in prepare_release.tracked_files_containing(ROOT, password)
        }
        self.assertTrue(prepare_release.CORE_BOOTSTRAP_PATHS.issubset(paths))

    def test_release_workflow_builds_packages_and_publishes_credentials(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertIn("branches: [main]", workflow)
        self.assertIn("permissions:\n  contents: write", workflow)
        self.assertIn("scripts/prepare_release.py", workflow)
        self.assertIn("nix build .#nixosConfigurations.nas-ci-ready.config.system.build.toplevel", workflow)
        self.assertIn("./scripts/package-release.sh --source-only", workflow)
        self.assertIn("gh release create", workflow)
        self.assertIn("bootstrap_username", workflow)
        self.assertIn("bootstrap_password", workflow)

    def test_release_workflow_passes_actionlint_when_available(self) -> None:
        actionlint = shutil.which("actionlint")
        if actionlint is None:
            self.skipTest("actionlint is not installed outside the Nix test environment")
        result = subprocess.run(
            [actionlint, ".github/workflows/release.yml"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
