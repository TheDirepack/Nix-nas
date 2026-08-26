from __future__ import annotations

import importlib.util
import pathlib
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "wait-release-predecessor.py"
SPEC = importlib.util.spec_from_file_location("wait_release_predecessor_rerun", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"could not load {MODULE_PATH}")
wait_release_predecessor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(wait_release_predecessor)


class ReleasePredecessorRerunTests(unittest.TestCase):
    def test_existing_source_tag_bypasses_descendant_rejection_for_repairs(self) -> None:
        root = pathlib.Path("/tmp/release-rerun-contract")
        with (
            mock.patch.object(wait_release_predecessor, "release_series_anchor", return_value="a" * 40),
            mock.patch.object(wait_release_predecessor, "fetch_tags"),
            mock.patch.object(wait_release_predecessor, "tag_for_source", return_value="v1.2.4"),
            mock.patch.object(wait_release_predecessor, "reject_published_descendant") as reject,
            mock.patch.object(wait_release_predecessor, "find_predecessor_state") as find_predecessor,
        ):
            wait_release_predecessor.wait_for_predecessor(
                root,
                "owner/repo",
                "b" * 40,
                workflow="ci.yml",
                poll_seconds=1,
                timeout_seconds=5,
            )

        reject.assert_not_called()
        find_predecessor.assert_not_called()


if __name__ == "__main__":
    unittest.main()
