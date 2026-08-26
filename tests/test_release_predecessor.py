from __future__ import annotations

import importlib.util
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "wait-release-predecessor.py"
SPEC = importlib.util.spec_from_file_location("wait_release_predecessor", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"could not load {MODULE_PATH}")
wait_release_predecessor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(wait_release_predecessor)


class ReleasePredecessorTests(unittest.TestCase):
    def git(self, root: pathlib.Path, *args: str) -> str:
        return subprocess.check_output(["git", *args], cwd=root, text=True).strip()

    def commit(self, root: pathlib.Path, name: str) -> str:
        path = root / f"{name}.txt"
        path.write_text(name + "\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=root, check=True)
        subprocess.run(["git", "commit", "-qm", name], cwd=root, check=True)
        return self.git(root, "rev-parse", "HEAD")

    def make_repo(self, root: pathlib.Path) -> tuple[str, str, str]:
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
        first = self.commit(root, "first")
        second = self.commit(root, "second")
        third = self.commit(root, "third")
        return first, second, third

    def test_exact_main_merge_requires_recorded_merge_result(self) -> None:
        source = "a" * 40
        payload = [
            {
                "merged_at": "2026-08-26T00:00:00Z",
                "base": {"ref": "main"},
                "merge_commit_sha": source,
            }
        ]
        self.assertTrue(wait_release_predecessor.exact_main_merge_result(payload, source))
        self.assertFalse(wait_release_predecessor.exact_main_merge_result(payload, "b" * 40))
        payload[0]["base"]["ref"] = "development"
        self.assertFalse(wait_release_predecessor.exact_main_merge_result(payload, source))

    def test_ci_classification_prefers_success_then_active(self) -> None:
        classify = wait_release_predecessor.classify_ci_runs
        self.assertEqual(
            classify({"workflow_runs": [{"status": "completed", "conclusion": "failure"}]}),
            "not-qualified",
        )
        self.assertEqual(
            classify({"workflow_runs": [{"status": "in_progress", "conclusion": None}]}),
            "active",
        )
        self.assertEqual(
            classify(
                {
                    "workflow_runs": [
                        {"status": "in_progress", "conclusion": None},
                        {"status": "completed", "conclusion": "success"},
                    ]
                }
            ),
            "success",
        )

    def test_nearest_qualified_first_parent_merge_is_the_barrier(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            first, second, third = self.make_repo(root)
            merge_results = {first, second}
            states = {first: "success", second: "active"}
            with (
                mock.patch.object(
                    wait_release_predecessor,
                    "commit_is_exact_main_merge",
                    side_effect=lambda _repo, sha: sha in merge_results,
                ),
                mock.patch.object(
                    wait_release_predecessor,
                    "ci_state",
                    side_effect=lambda _repo, _workflow, sha: states[sha],
                ),
            ):
                predecessor, state = wait_release_predecessor.find_predecessor_state(
                    root,
                    "owner/repo",
                    "ci.yml",
                    third,
                )
            self.assertEqual(predecessor, second)
            self.assertEqual(state, "active")

    def test_failed_predecessor_does_not_block_later_qualified_merge(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            first, second, third = self.make_repo(root)
            merge_results = {first, second}
            states = {first: "success", second: "not-qualified"}
            with (
                mock.patch.object(
                    wait_release_predecessor,
                    "commit_is_exact_main_merge",
                    side_effect=lambda _repo, sha: sha in merge_results,
                ),
                mock.patch.object(
                    wait_release_predecessor,
                    "ci_state",
                    side_effect=lambda _repo, _workflow, sha: states[sha],
                ),
            ):
                predecessor, state = wait_release_predecessor.find_predecessor_state(
                    root,
                    "owner/repo",
                    "ci.yml",
                    third,
                )
            self.assertEqual(predecessor, first)
            self.assertEqual(state, "success")

    def test_published_descendant_rejects_late_older_release(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            first, second, _third = self.make_repo(root)
            subprocess.run(["git", "checkout", "-q", second], cwd=root, check=True)
            (root / "release.txt").write_text("generated release\n", encoding="utf-8")
            subprocess.run(["git", "add", "release.txt"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "release"], cwd=root, check=True)
            subprocess.run(["git", "tag", "-a", "v1.2.5", "-m", "release"], cwd=root, check=True)

            with self.assertRaisesRegex(RuntimeError, "refusing to publish older source"):
                wait_release_predecessor.reject_published_descendant(root, first)

    def test_published_predecessor_allows_release_immediately(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            _first, second, third = self.make_repo(root)
            with (
                mock.patch.object(wait_release_predecessor, "fetch_tags"),
                mock.patch.object(wait_release_predecessor, "reject_published_descendant"),
                mock.patch.object(
                    wait_release_predecessor,
                    "find_predecessor_state",
                    return_value=(second, "success"),
                ),
                mock.patch.object(wait_release_predecessor, "tag_for_source", return_value="v1.2.5"),
                mock.patch.object(wait_release_predecessor.time, "sleep") as sleep,
            ):
                wait_release_predecessor.wait_for_predecessor(
                    root,
                    "owner/repo",
                    third,
                    workflow="ci.yml",
                    poll_seconds=1,
                    timeout_seconds=5,
                )
            sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
