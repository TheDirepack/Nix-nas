from __future__ import annotations

import pathlib
import unittest

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


class ReleaseMergeProvenanceTests(unittest.TestCase):
    def test_release_requires_exact_pull_request_merge_result(self) -> None:
        text = RELEASE_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("commits/$SOURCE_SHA/pulls", text)
        self.assertIn(".merge_commit_sha == env.SOURCE_SHA", text)
        self.assertIn('.base.ref == "main"', text)
        self.assertIn(".merged_at != null", text)

    def test_release_tag_has_no_trigger_path_back_into_ci_or_release(self) -> None:
        release = yaml.load(RELEASE_WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
        ci = yaml.load(CI_WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)

        self.assertEqual(set(release["on"]), {"workflow_run"})
        self.assertEqual(release["on"]["workflow_run"]["workflows"], ["CI"])
        self.assertEqual(ci["on"]["push"]["branches"], ["main"])
        self.assertNotIn("tags", ci["on"]["push"])


if __name__ == "__main__":
    unittest.main()
