from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class MaintainerSplitContractTests(unittest.TestCase):
    def test_slow_maintainer_scenarios_are_split_into_bounded_groups(self) -> None:
        for name in (
            "test_maintainer_core.py",
            "test_maintainer_matrix.py",
            "test_maintainer_release.py",
        ):
            self.assertTrue((ROOT / "tests" / name).is_file(), name)


if __name__ == "__main__":
    unittest.main()
