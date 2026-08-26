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

    def test_prepare_release_updates_version_and_release_copy_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.make_repo(root)
            (root / "untracked.txt").write_text("old-bootstrap-password-123456\n", encoding="utf-8")
            metadata_path = root / ".tmp" / "release.json"
            release_password = "Acorn-Adobe-Alder-Amber-Anchor"
            metadata = prepare_release.prepare_release(
                root,
                run_number=4,
                source_sha="a" * 40,
                metadata_out=metadata_path,
                password=release_password,
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
                self.assertIn(release_password, text)
            self.assertEqual((root / "untracked.txt").read_text(), "old-bootstrap-password-123456\n")
            on_disk = json.loads(metadata_path.read_text())
            self.assertEqual(on_disk["bootstrap_username"], "akadmin")
            self.assertEqual(on_disk["bootstrap_password"], release_password)

    def test_existing_tags_and_run_number_keep_patch_versions_monotonic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.make_repo(root)
            subprocess.run(["git", "tag", "v1.2.8"], cwd=root, check=True)
            current = prepare_release.Version.parse("1.2.3")
            self.assertEqual(str(prepare_release.next_version(root, current, 4)), "1.2.9")
            self.assertEqual(str(prepare_release.next_version(root, current, 12)), "1.2.12")

    def test_rerun_recovers_version_and_diceware_password_from_existing_release_tag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.make_repo(root)
            source_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
            tagged_password = "Beacon-Birch-Cedar-Delta-Ember"
            for relative in prepare_release.CORE_BOOTSTRAP_PATHS:
                path = root / relative
                path.write_text(
                    path.read_text().replace("old-bootstrap-password-123456", tagged_password), encoding="utf-8"
                )
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "release"], cwd=root, check=True)
            subprocess.run(["git", "tag", "-a", "v1.2.8", "-m", "release"], cwd=root, check=True)
            subprocess.run(["git", "checkout", "-q", source_sha], cwd=root, check=True)

            metadata = prepare_release.prepare_release(
                root,
                run_number=8,
                source_sha=source_sha,
                metadata_out=root / ".tmp" / "release.json",
                password="Different-Fresh-Words-Should-Ignore",
                release_date="2026-08-26",
            )
            self.assertEqual(metadata["version"], "1.2.8")
            self.assertEqual(metadata["existing_tag"], "v1.2.8")
            self.assertEqual(metadata["bootstrap_password"], tagged_password)
            for relative in prepare_release.CORE_BOOTSTRAP_PATHS:
                self.assertIn(tagged_password, (root / relative).read_text())

    def test_release_passphrase_requires_exactly_five_safe_words(self) -> None:
        prepare_release.validate_release_passphrase("Alpha-Bravo-Cedar-Delta-Ember")
        for invalid in (
            "Alpha-Bravo-Cedar-Delta",
            "Alpha-Bravo-Cedar-Delta-Ember-Forest",
            "Alpha Bravo Cedar Delta Ember",
            "Alpha-Bravo-Cedar-Delta-1234",
            "a-b-c-d-e",
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    prepare_release.validate_release_passphrase(invalid)

    def test_development_tree_keeps_the_fixed_bootstrap_password(self) -> None:
        self.assertEqual(prepare_release.discover_bootstrap_password(ROOT), "nas-admin-first-boot")
        paths = {
            path.relative_to(ROOT).as_posix()
            for path in prepare_release.tracked_files_containing(ROOT, "nas-admin-first-boot")
        }
        self.assertTrue(prepare_release.CORE_BOOTSTRAP_PATHS.issubset(paths))

    def test_release_workflow_uses_pinned_diceware_and_never_pushes_release_commit_to_main(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        flake = (ROOT / "flake.nix").read_text(encoding="utf-8")
        self.assertIn("branches: [main]", workflow)
        self.assertIn("permissions:\n  contents: write", workflow)
        self.assertIn("nix develop .#test -c diceware -n 5 -d - -w en_eff --caps -r system", workflow)
        self.assertIn("diceware", flake)
        self.assertIn("scripts/prepare_release.py", workflow)
        self.assertIn("nix build .#nixosConfigurations.nas-ci-ready.config.system.build.toplevel", workflow)
        self.assertIn("./scripts/package-release.sh --source-only", workflow)
        self.assertIn("gh release create", workflow)
        self.assertIn("gh release upload", workflow)
        self.assertIn("existing_tag", workflow)
        self.assertIn("bootstrap_username", workflow)
        self.assertIn("bootstrap_password", workflow)
        self.assertNotIn("release_commit:refs/heads/main", workflow)
        self.assertNotIn("Fast-forward release metadata onto main", workflow)

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
