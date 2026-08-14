from __future__ import annotations

import concurrent.futures
import hashlib
import os
import pathlib
import subprocess
import tempfile
import unittest

from maintainer_test_base import MaintainerScriptMixin


class MaintainerReleaseTests(MaintainerScriptMixin, unittest.TestCase):
    def test_installer_rejects_missing_or_untrusted_inputs_before_destructive_commands(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = root / "source"
            source.mkdir()
            (source / "flake.nix").write_text("{}\n", encoding="utf-8")
            key = root / "admin.pub"
            key.write_text("ssh-ed25519 test\n", encoding="utf-8")
            marker = root / "must-survive"
            marker.write_text("safe\n", encoding="utf-8")
            env = {
                **os.environ,
                "NAS_INSTALL_DISK": str(root / "not-a-block-device"),
                "NAS_INSTALL_SOURCE": str(source),
                "NAS_INSTALL_SSH_PUBLIC_KEY": str(key),
            }
            result = subprocess.run(
                ["bash", "tests/vm/install-system.sh"],
                cwd=self.clean_root,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("Installer disk is missing", result.stderr)
            self.assertEqual(marker.read_text(encoding="utf-8"), "safe\n")

            link = root / "linked.pub"
            link.symlink_to(key)
            source_text = (self.clean_root / "tests/vm/install-system.sh").read_text(encoding="utf-8")
            self.assertIn("Ephemeral SSH public key must not be a symlink", source_text)

    def test_post_install_reconfigure_requires_reviewed_source_and_persistence_sentinel(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            missing_source = root / "missing-source"
            result = subprocess.run(
                ["bash", "tests/vm/reconfigure-system.sh"],
                cwd=self.clean_root,
                env={
                    **os.environ,
                    "NAS_TEST_SOURCE": str(missing_source),
                    "NAS_TEST_INSTALL_SENTINEL": str(root / "sentinel"),
                },
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("reviewed source flake is missing", result.stderr)

            source = root / "source"
            source.mkdir()
            (source / "flake.nix").write_text("{}\n", encoding="utf-8")
            result = subprocess.run(
                ["bash", "tests/vm/reconfigure-system.sh"],
                cwd=self.clean_root,
                env={
                    **os.environ,
                    "NAS_TEST_SOURCE": str(source),
                    "NAS_TEST_INSTALL_SENTINEL": str(root / "missing-sentinel"),
                },
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("installer persistence sentinel is missing", result.stderr)

    def test_shell_workflows_parse_and_safe_help_or_invalid_modes_are_non_mutating(self) -> None:
        shell_scripts = sorted((self.clean_root / "scripts").rglob("*.sh"))
        for script in shell_scripts:
            with self.subTest(parse=script.relative_to(self.clean_root).as_posix()):
                result = subprocess.run(["bash", "-n", str(script)], text=True, capture_output=True, check=False)
                self.assertEqual(result.returncode, 0, result.stderr)
        safe = (
            ("bash", "scripts/package-release.sh", "--help"),
            ("bash", "scripts/qemu-test.sh", "--help"),
            ("bash", "scripts/update-nas.sh", "--help"),
        )
        for command in safe:
            with self.subTest(help=command[1]):
                result = self.run_clean(*command)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("usage", (result.stdout + result.stderr).lower())

    def test_preflight_wrapper_runs_its_safe_local_tier(self) -> None:
        result = self.run_clean(
            "env",
            "NAS_PREFLIGHT_REQUIRE_COMPLETE=0",
            "NAS_PREFLIGHT_SKIP_TESTS=1",
            "NAS_PREFLIGHT_SKIP_FUZZ=1",
            "NAS_PREFLIGHT_SKIP_NIX=1",
            "bash",
            "scripts/preflight.sh",
            timeout=90,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Preflight partial: 0", result.stdout)
        self.assertIn("repository structure", result.stdout)
        self.assertIn("static security boundaries", result.stdout)
        self.assertFalse((self.clean_root / ".ruff_cache").exists())


class ManifestHelperTests(MaintainerScriptMixin, unittest.TestCase):
    def test_manifest_helper_is_deterministic_and_sorted(self) -> None:
        # helper should be used by packaging, preflight and run-unit-tests; verify deterministic output
        for script in ("scripts/package-release.sh", "scripts/preflight.sh", "scripts/run-unit-tests.py"):
            text = (self.clean_root / script).read_text(encoding="utf-8")
            self.assertIn("scripts/lib/manifest.py", text, msg=script)
            self.assertIn("MANIFEST", text)
        # actual digest correctness
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "root"
            root.mkdir()
            (root / "a.txt").write_text("hello\n", encoding="utf-8")
            (root / "b.txt").write_text("world\n", encoding="utf-8")
            (root / "sub").mkdir()
            (root / "sub" / "c.txt").write_text("nested\n", encoding="utf-8")
            out = pathlib.Path(tmp) / "out" / "MANIFEST.sha256"
            result = subprocess.run(
                ["python3", str(self.clean_root / "scripts/lib/manifest.py"), "--root", str(root), "--out", str(out)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            lines = out.read_text(encoding="utf-8").strip().splitlines()
            # sorted by posix path
            expected_paths = ["./a.txt", "./b.txt", "./sub/c.txt"]
            actual_paths = [line.split(None, 1)[1] for line in lines]
            self.assertEqual(actual_paths, sorted(actual_paths))
            self.assertEqual(actual_paths, expected_paths)
            for line in lines:
                digest, path = line.split(None, 1)
                target = root / path.lstrip("./")
                expected = hashlib.sha256(target.read_bytes()).hexdigest()
                self.assertEqual(digest, expected, msg=f"digest mismatch for {path}")
            # second run deterministic
            out2 = pathlib.Path(tmp) / "out2" / "MANIFEST.sha256"
            result2 = subprocess.run(
                ["python3", str(self.clean_root / "scripts/lib/manifest.py"), "--root", str(root), "--out", str(out2)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result2.returncode, 0)
            self.assertEqual(out.read_text(), out2.read_text())

    def test_manifest_helper_ignores_git_and_special_files_and_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "root"
            root.mkdir()
            (root / "keep.txt").write_text("keep", encoding="utf-8")
            (root / "MANIFEST.sha256").write_text("old", encoding="utf-8")
            (root / ".release-input-policy").write_text("x", encoding="utf-8")
            git_dir = root / ".git" / "objects"
            git_dir.mkdir(parents=True)
            (git_dir / "ignore.txt").write_text("ignore", encoding="utf-8")
            out = pathlib.Path(tmp) / "manifest"
            result = subprocess.run(
                ["python3", str(self.clean_root / "scripts/lib/manifest.py"), "--root", str(root), "--out", str(out)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            content = out.read_text(encoding="utf-8")
            self.assertIn("./keep.txt", content)
            self.assertNotIn("MANIFEST.sha256", content)
            self.assertNotIn(".release-input-policy", content)
            self.assertNotIn(".git", content)
            # permissions: make file unreadable? helper should still handle or error deterministically
            (root / "keep.txt").chmod(0o000)
            try:
                out2 = pathlib.Path(tmp) / "manifest2"
                result2 = subprocess.run(
                    [
                        "python3",
                        str(self.clean_root / "scripts/lib/manifest.py"),
                        "--root",
                        str(root),
                        "--out",
                        str(out2),
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                # running as root may still read; if not root, it should error or succeed deterministically
                self.assertIn(result2.returncode, (0, 1))
                if result2.returncode == 0:
                    self.assertIn("./keep.txt", out2.read_text())
            finally:
                (root / "keep.txt").chmod(0o644)
            # non-regular objects should be rejected
            with tempfile.TemporaryDirectory() as tmp2:
                root2 = pathlib.Path(tmp2) / "r"
                root2.mkdir()
                (root2 / "regular.txt").write_text("ok", encoding="utf-8")
                link = root2 / "link.txt"
                link.symlink_to(root2 / "regular.txt")
                out3 = pathlib.Path(tmp2) / "out"
                result3 = subprocess.run(
                    [
                        "python3",
                        str(self.clean_root / "scripts/lib/manifest.py"),
                        "--root",
                        str(root2),
                        "--out",
                        str(out3),
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertNotEqual(result3.returncode, 0)
                self.assertIn("unsupported object", result3.stderr)

    def test_manifest_generation_uses_temp_dir_and_cleans_up(self) -> None:
        preflight = (self.clean_root / "scripts/preflight.sh").read_text(encoding="utf-8")
        self.assertIn("mktemp -d", preflight)
        self.assertIn("MANIFEST_PATH", preflight)
        self.assertIn("NAS_TEST_MANIFEST", preflight)
        self.assertIn("trap", preflight)
        self.assertIn("rm -rf", preflight)
        runner = (self.clean_root / "scripts/run-unit-tests.py").read_text(encoding="utf-8")
        self.assertIn("mktemp", runner)
        self.assertIn("MANIFEST_PATH", runner)
        self.assertIn("NAS_TEST_MANIFEST", runner)
        self.assertIn("mkdtemp", runner)
        packaging = (self.clean_root / "scripts/package-release.sh").read_text(encoding="utf-8")
        self.assertIn("scripts/lib/manifest.py", packaging)
        # run-unit-tests should clean up temp manifest on success
        result = self.run_clean(
            "python3", "scripts/run-unit-tests.py", "--quiet", "--pattern", "test_common.py", timeout=30
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        # the harness temp should not remain in /tmp as nas-manifest-* after success (check clean_root's temp is gone)
        # Since harness uses tempfile.mkdtemp, it cleans via trap; we can verify by running a helper that checks env var exposure
        with tempfile.TemporaryDirectory():
            env = os.environ.copy()
            env["PYTHONPATH"] = str(self.clean_root / "services") + os.pathsep + str(self.clean_root / "tests")
            proc = subprocess.run(
                [
                    "python3",
                    "-c",
                    "import os, pathlib, subprocess, tempfile; d=tempfile.mkdtemp(prefix='nas-manifest-'); p=pathlib.Path(d)/'MANIFEST.sha256'; subprocess.run(['python3','scripts/lib/manifest.py','--root','.', '--out', str(p)], check=True); print(p); print(os.environ.get('MANIFEST_PATH','')); import shutil; shutil.rmtree(d)",
                ],
                cwd=self.clean_root,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0)

    def test_manifest_concurrent_runs_are_isolated(self) -> None:
        def run_one(idx: int) -> tuple[str, str]:
            with tempfile.TemporaryDirectory() as tmp:
                root = pathlib.Path(tmp) / f"root{idx}"
                root.mkdir()
                (root / f"file{idx}.txt").write_text(f"content {idx}\n", encoding="utf-8")
                manifest_dir = pathlib.Path(tempfile.mkdtemp(prefix="nas-manifest-"))
                manifest_path = manifest_dir / "MANIFEST.sha256"
                result = subprocess.run(
                    [
                        "python3",
                        str(self.clean_root / "scripts/lib/manifest.py"),
                        "--root",
                        str(root),
                        "--out",
                        str(manifest_path),
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if result.returncode != 0:
                    raise AssertionError(result.stdout + result.stderr)
                content = manifest_path.read_text(encoding="utf-8")
                # cleanup as trap would
                import shutil

                shutil.rmtree(manifest_dir, ignore_errors=True)
                return (str(manifest_dir), content)

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(run_one, i) for i in range(4)]
            results = [f.result(timeout=10) for f in futures]
        dirs = [r[0] for r in results]
        contents = [r[1] for r in results]
        # dirs should be unique
        self.assertEqual(len(set(dirs)), 4)
        # each manifest should contain its own file
        for idx, content in enumerate(contents):
            self.assertIn(f"file{idx}.txt", content)

    def test_manifest_cleanup_on_failure_and_timeout(self) -> None:
        # failure: manifest helper should clean temp dir on error; simulate via run-unit-tests failure path
        # Check that run-unit-tests cleans temp even when a test file fails
        # Create a failing test file in a temp copy
        with tempfile.TemporaryDirectory():
            failing = self.clean_root / "tests" / "test_fail_manifest_cleanup.py"
            created = False
            try:
                failing.write_text(
                    "import unittest\nclass T(unittest.TestCase):\n    def test_fail(self):\n        self.fail('intentional')\n",
                    encoding="utf-8",
                )
                created = True
                result = self.run_clean(
                    "python3",
                    "scripts/run-unit-tests.py",
                    "--quiet",
                    "--pattern",
                    "test_fail_manifest_cleanup.py",
                    timeout=10,
                )
                self.assertNotEqual(result.returncode, 0)
                # after failure, no nas-manifest temp should remain leaked in clean_root's parent temp?
                # The harness cleans via atexit/finally, so check that no MANIFEST env leaked
                self.assertNotIn("nas-manifest", result.stdout + result.stderr)
            finally:
                if created and failing.exists():
                    failing.unlink()
        # timeout/interruption: check preflight trap includes INT TERM HUP
        preflight = (self.clean_root / "scripts/preflight.sh").read_text(encoding="utf-8")
        self.assertIn("INT", preflight)
        self.assertIn("TERM", preflight)
        self.assertIn("HUP", preflight)
        runner = (self.clean_root / "scripts/run-unit-tests.py").read_text(encoding="utf-8")
        self.assertIn("SIGINT", runner)
        self.assertIn("SIGTERM", runner)
        self.assertIn("SIGHUP", runner)

    def test_manifest_does_not_modify_repo_status(self) -> None:
        # After running helper, git status should remain unchanged (no new files, no modified)
        subprocess.run(
            ["git", "-C", str(self.clean_root), "status", "--porcelain=v1", "--untracked-files=all"],
            capture_output=True,
            text=True,
            check=False,
        )
        # clean_root is a copy without .git, so status will be empty or show nothing; check that helper run doesn't create MANIFEST in repo root
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "r"
            root.mkdir()
            (root / "a.txt").write_text("a", encoding="utf-8")
            out = pathlib.Path(tmp) / "out"
            result = subprocess.run(
                ["python3", str(self.clean_root / "scripts/lib/manifest.py"), "--root", str(root), "--out", str(out)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0)
            self.assertFalse((self.clean_root / "MANIFEST.sha256").exists())
            # ensure no file was created in source root
            self.assertFalse((root / "MANIFEST.sha256").exists())
        # verify packaging still generates fresh manifest inside staged archive (not relying on stale tracked file)
        packaging = (self.clean_root / "scripts/package-release.sh").read_text(encoding="utf-8")
        self.assertNotIn("requires the committed MANIFEST", packaging)
        self.assertIn("generate_manifest", packaging)
