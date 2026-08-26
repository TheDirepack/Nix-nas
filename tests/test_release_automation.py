from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from typing import cast

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import prepare_release  # noqa: E402


class ReleaseAutomationTests(unittest.TestCase):
    def git(self, root: pathlib.Path, *args: str) -> str:
        return subprocess.check_output(["git", *args], cwd=root, text=True).strip()

    def commit(self, root: pathlib.Path, message: str) -> str:
        subprocess.run(["git", "add", "."], cwd=root, check=True)
        subprocess.run(["git", "commit", "-qm", message], cwd=root, check=True)
        return self.git(root, "rev-parse", "HEAD")

    def make_repo(self, root: pathlib.Path) -> str:
        files = {
            "VERSION": "1.2.3\n",
            "README.md": "# NixOS NAS 1.2.3\n\n> **Release status:** 1.2.3 is source-only.\n",
            "flake.nix": '{\n  description = "NixOS NAS 1.2.3 appliance";\n}\n',
            "CHANGELOG.md": ("# Changelog\n\nIntro.\n\n## 1.2.3 — 2026-01-01\n\n### Added\n\n- Baseline.\n"),
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
            "tests/example.py": "EXPECTED = 'old-bootstrap-password-123456'\n",
        }
        for relative, content in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        subprocess.run(
            ["git", "config", "user.email", "test@example.invalid"],
            cwd=root,
            check=True,
        )
        subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
        baseline = self.commit(root, "baseline")
        subprocess.run(["git", "branch", "-M", "main"], cwd=root, check=True)
        subprocess.run(["git", "checkout", "-qb", "release-automation"], cwd=root, check=True)
        epoch_path = root / prepare_release.RELEASE_EPOCH_PATH
        epoch_path.parent.mkdir(parents=True, exist_ok=True)
        epoch_path.write_text(
            json.dumps({"version": "1.2.3"}, indent=2) + "\n",
            encoding="utf-8",
        )
        self.commit(root, "release automation")
        subprocess.run(["git", "checkout", "-q", "main"], cwd=root, check=True)
        return baseline

    def add_source_commit(self, root: pathlib.Path, number: int) -> str:
        if not (root / prepare_release.RELEASE_EPOCH_PATH).exists():
            subprocess.run(["git", "checkout", "-q", "release-automation"], cwd=root, check=True)
            path = root / f"source-{number}.txt"
            path.write_text(f"source {number}\n", encoding="utf-8")
            self.commit(root, f"source {number}")
            subprocess.run(["git", "checkout", "-q", "main"], cwd=root, check=True)
            subprocess.run(
                ["git", "merge", "--no-ff", "-qm", f"merge source {number}", "release-automation"],
                cwd=root,
                check=True,
            )
            return self.git(root, "rev-parse", "HEAD")

        path = root / f"source-{number}.txt"
        path.write_text(f"source {number}\n", encoding="utf-8")
        return self.commit(root, f"source {number}")

    def test_prepare_release_updates_version_and_runtime_targets_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.make_repo(root)
            source_sha = self.add_source_commit(root, 1)
            (root / "untracked.txt").write_text("old-bootstrap-password-123456\n", encoding="utf-8")
            metadata_path = root / ".tmp" / "release.json"
            release_password = "Acorn-Adobe-Alder-Amber-Anchor"
            metadata = prepare_release.prepare_release(
                root,
                source_sha=source_sha,
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
            self.assertEqual(bootstrap_files, sorted(prepare_release.BOOTSTRAP_TARGETS))
            for relative in bootstrap_files:
                source = (root / relative).read_text()
                self.assertNotIn("old-bootstrap-password-123456", source)
                self.assertIn(release_password, source)
            self.assertEqual(
                (root / "docs/example.md").read_text(),
                "Login with old-bootstrap-password-123456.\n",
            )
            self.assertEqual(
                (root / "tests/example.py").read_text(),
                "EXPECTED = 'old-bootstrap-password-123456'\n",
            )
            self.assertEqual(
                (root / "untracked.txt").read_text(),
                "old-bootstrap-password-123456\n",
            )
            on_disk = json.loads(metadata_path.read_text())
            self.assertEqual(on_disk["bootstrap_username"], "akadmin")
            self.assertEqual(on_disk["bootstrap_password"], release_password)

    def test_first_parent_distance_makes_versions_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.make_repo(root)
            source_one = self.add_source_commit(root, 1)
            source_two = self.add_source_commit(root, 2)
            current = prepare_release.Version.parse("1.2.3")
            self.assertEqual(str(prepare_release.next_version(root, current, source_one)), "1.2.4")
            self.assertEqual(str(prepare_release.next_version(root, current, source_two)), "1.2.5")
            subprocess.run(["git", "tag", "v1.2.8", source_one], cwd=root, check=True)
            self.assertEqual(str(prepare_release.next_version(root, current, source_two)), "1.2.5")

    def test_release_epoch_has_no_self_referential_sha_and_must_match_version(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.make_repo(root)
            source_sha = self.add_source_commit(root, 1)
            epoch = json.loads((root / prepare_release.RELEASE_EPOCH_PATH).read_text())
            self.assertEqual(epoch, {"version": "1.2.3"})
            self.assertEqual(str(prepare_release.release_epoch(root)), "1.2.3")

            (root / "VERSION").write_text("1.3.0\n", encoding="utf-8")
            source_sha = self.commit(root, "start next development series incorrectly")
            with self.assertRaisesRegex(RuntimeError, "advance the release epoch"):
                prepare_release.next_version(root, prepare_release.Version.parse("1.3.0"), source_sha)

    def test_rerun_recovers_version_and_diceware_password_from_existing_release_tag(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.make_repo(root)
            source_sha = self.add_source_commit(root, 1)
            tagged_password = "Beacon-Birch-Cedar-Delta-Ember"
            metadata_path = root / ".tmp" / "first-release.json"
            metadata = prepare_release.prepare_release(
                root,
                source_sha=source_sha,
                metadata_out=metadata_path,
                password=tagged_password,
                release_date="2026-08-26",
            )
            self.assertEqual(metadata["version"], "1.2.4")
            subprocess.run(["git", "add", "-A"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "release"], cwd=root, check=True)
            subprocess.run(
                ["git", "tag", "-a", "v1.2.4", "-m", "release"],
                cwd=root,
                check=True,
            )
            subprocess.run(["git", "checkout", "-q", source_sha], cwd=root, check=True)

            recovered = prepare_release.prepare_release(
                root,
                source_sha=source_sha,
                metadata_out=root / ".tmp" / "rerun.json",
                password="Different-Fresh-Words-Should-Ignore",
                release_date="2026-08-26",
            )
            self.assertEqual(recovered["version"], "1.2.4")
            self.assertEqual(recovered["existing_tag"], "v1.2.4")
            self.assertEqual(recovered["bootstrap_password"], tagged_password)
            for relative in prepare_release.BOOTSTRAP_TARGETS:
                self.assertIn(tagged_password, (root / relative).read_text())

    def test_later_release_inherits_prior_generated_changelog_sections(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.make_repo(root)
            source_one = self.add_source_commit(root, 1)
            prepare_release.prepare_release(
                root,
                source_sha=source_one,
                metadata_out=root / ".tmp" / "one.json",
                password="Alpha-Bravo-Cedar-Delta-Ember",
                release_date="2026-08-26",
            )
            subprocess.run(["git", "add", "-A"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "release one"], cwd=root, check=True)
            subprocess.run(
                ["git", "tag", "-a", "v1.2.4", "-m", "release one"],
                cwd=root,
                check=True,
            )
            subprocess.run(["git", "checkout", "-q", source_one], cwd=root, check=True)
            source_two = self.add_source_commit(root, 2)

            prepare_release.prepare_release(
                root,
                source_sha=source_two,
                metadata_out=root / ".tmp" / "two.json",
                password="Forest-Garden-Harbor-Island-Jungle",
                release_date="2026-08-27",
            )
            changelog = (root / "CHANGELOG.md").read_text()
            self.assertLess(changelog.index("## 1.2.5"), changelog.index("## 1.2.4"))
            self.assertLess(changelog.index("## 1.2.4"), changelog.index("## 1.2.3"))

    def test_runtime_bootstrap_assignment_must_exactly_match_secret_seed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.make_repo(root)
            path = root / "modules/nas/config/application-services.nix"
            path.write_text(
                "printf '%s\\n' 'AUTHENTIK_BOOTSTRAP_PASSWORD=different-bootstrap-password-123456'\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RuntimeError, "does not use the same bootstrap password"):
                prepare_release.discover_bootstrap_password(root)

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
        for relative in prepare_release.BOOTSTRAP_TARGETS:
            self.assertIn("nas-admin-first-boot", (ROOT / relative).read_text())
        self.assertEqual(str(prepare_release.release_epoch(ROOT)), "0.1.0")
        epoch = json.loads((ROOT / prepare_release.RELEASE_EPOCH_PATH).read_text(encoding="utf-8"))
        self.assertEqual(epoch, {"version": "0.1.0"})

    def test_release_trigger_graph_is_ci_gated_queued_and_loop_free(self) -> None:
        release = yaml.load(
            (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8"),
            Loader=yaml.BaseLoader,
        )
        ci = yaml.load(
            (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"),
            Loader=yaml.BaseLoader,
        )
        release_triggers = release["on"]
        ci_triggers = ci["on"]

        self.assertEqual(set(release_triggers), {"workflow_run"})
        self.assertEqual(release_triggers["workflow_run"]["workflows"], ["CI"])
        self.assertEqual(release_triggers["workflow_run"]["types"], ["completed"])
        self.assertEqual(release_triggers["workflow_run"]["branches"], ["main"])
        self.assertNotIn("tags", ci_triggers["push"])
        self.assertEqual(ci_triggers["push"]["branches"], ["main"])
        self.assertEqual(release["concurrency"]["group"], "main-release-publication")
        self.assertEqual(release["concurrency"]["queue"], "max")
        self.assertNotIn("cancel-in-progress", release["concurrency"])

        eligibility = release["jobs"]["eligibility"]
        eligibility_text = repr(eligibility)
        self.assertIn("workflow_run.conclusion == 'success'", eligibility_text)
        self.assertIn("workflow_run.event == 'push'", eligibility_text)
        self.assertIn("workflow_run.head_branch == 'main'", eligibility_text)
        self.assertIn("commits/$SOURCE_SHA/pulls", eligibility_text)
        self.assertIn(".merged_at != null", eligibility_text)
        self.assertIn('.base.ref == "main"', eligibility_text)

    def test_release_build_is_read_only_and_only_publish_job_can_write(self) -> None:
        workflow = yaml.load(
            (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8"),
            Loader=yaml.BaseLoader,
        )
        jobs = workflow["jobs"]
        self.assertEqual(workflow["permissions"]["contents"], "read")
        self.assertEqual(workflow["permissions"]["actions"], "read")
        self.assertEqual(jobs["build"]["permissions"]["contents"], "read")
        self.assertEqual(jobs["build"]["permissions"]["actions"], "read")
        self.assertEqual(jobs["publish"]["permissions"]["contents"], "write")
        self.assertEqual(jobs["publish"]["permissions"]["actions"], "read")
        build_text = repr(jobs["build"])
        publish_text = repr(jobs["publish"])
        self.assertIn("persist-credentials", build_text)
        self.assertIn("release-candidate.bundle", build_text)
        self.assertIn("vm-bundle-handoff", build_text)
        self.assertIn("workflow_run.id", build_text)
        self.assertIn('git push origin "refs/tags/$tag"', publish_text)
        self.assertNotIn("refs/heads/main", publish_text)
        self.assertNotIn("nix build", publish_text)
        self.assertNotIn("npm ", publish_text)

    def test_release_workflow_uses_pinned_diceware_and_release_only_commit(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        flake = (ROOT / "flake.nix").read_text(encoding="utf-8")
        self.assertIn(
            "nix develop .#test -c diceware -n 5 -d - -w en_eff --caps -r system",
            workflow,
        )
        self.assertIn("diceware", flake)
        self.assertIn("scripts/prepare_release.py", workflow)
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
            [
                actionlint,
                "-ignore",
                'unexpected key "queue" for "concurrency" section',
                ".github/workflows/release.yml",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
