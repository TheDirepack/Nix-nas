"""Keep the reusable VM bundle cache action in sync with the real Nix flake."""

from __future__ import annotations

import collections
import pathlib
import re
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
ACTION = ROOT / ".github/actions/prepare-vm-handoff/action.yml"
SCRIPT = ROOT / "scripts/vm-bundles.sh"


class VmBundleActionInventoryTests(unittest.TestCase):
    def test_cache_outputs_and_archives_match_declared_bundle_list(self) -> None:
        listed = subprocess.run(
            ["bash", str(SCRIPT), "list"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        ).stdout.splitlines()
        action = ACTION.read_text(encoding="utf-8")
        paths = re.findall(r"/vm-bundles/([a-z][a-z-]*)\.nar\.gz", action)
        keys = re.findall(r"steps\.keys\.outputs\.key_([a-z][a-z_]*)", action)
        expected = set(listed)
        self.assertEqual(set(paths), expected)
        self.assertEqual(set(key.replace("_", "-") for key in keys), expected)
        self.assertEqual(collections.Counter(paths), collections.Counter({name: 2 for name in listed}))
        self.assertEqual(
            collections.Counter(key.replace("_", "-") for key in keys),
            collections.Counter({name: 2 for name in listed}),
        )
        self.assertNotIn("vm-bundle-ai-", action)
        self.assertNotIn("key_ai", action)


if __name__ == "__main__":
    unittest.main()
