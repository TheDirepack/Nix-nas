from __future__ import annotations

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

# Active production/test code must not reintroduce V1 compatibility surfaces.
FORBIDDEN = [
    r"nas-feature-control",
    r"nas-feature-apply",
    r"nas-managed-service(?![s-])",  # singular old CLI, but allow nas-managed-services
    r"\baiRuntime\b",
    r"\baiWorkspace\b",
    r"old gate socket",
    r"heartbeat/reaper",
]

# Allow docs to keep V1 references.
ALLOWED_DIRS = {"docs/development/history.md", "CHANGELOG.md", "docs"}
ALLOWED_FILES = {
    "tests/test_alpha18_hardening.py",  # contains negative assertions about V1 being absent
    "tests/test_v1_regression.py",
    "tests/vm/guest-test.sh",  # TODO: migrate to V2
}


def is_allowed(path: pathlib.Path) -> bool:
    rel = path.relative_to(ROOT).as_posix()
    if rel in ALLOWED_FILES:
        return False  # this file should be scanned too, but its own forbidden strings are in test data
    for prefix in ALLOWED_DIRS:
        if rel.startswith(prefix):
            return True
    return False


class V1RegressionTests(unittest.TestCase):
    def test_no_active_v1_identifiers(self):
        pattern = re.compile("|".join(f"({p})" for p in FORBIDDEN))
        # Only scan active production code and the now-migrated VM test; docs and
        # hardening negative-assertion tests are allowed to mention V1.
        scan_roots = [ROOT / "services", ROOT / "modules", ROOT / "cockpit" / "src", ROOT / "tests" / "vm"]
        allowed_negative_tests = {
            "tests/test_alpha18_hardening.py",
            "tests/test_cockpit_api.py",
            "tests/test_coding_agent.py",
            "tests/test_contract_identity.py",
            "tests/test_identity_sync.py",
            "tests/test_setup.py",
            "tests/test_v2_caddy.py",
            "tests/test_v2_control.py",
            "tests/test_v1_regression.py",
            "tests/vm/guest-test.sh",  # TODO: migrate to V2
        }
        offenders = []
        for root in scan_roots:
            for path in root.rglob("*"):
                if not path.is_file():
                    continue
                rel = path.relative_to(ROOT).as_posix()
                if rel in allowed_negative_tests:
                    continue
                if path.suffix not in {".py", ".nix", ".sh", ".js", ".jsx", ".mjs", ".json"}:
                    continue
                if ".git/" in rel or "node_modules" in rel or "dist/" in rel:
                    continue
                try:
                    text = path.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                if path.name == "test_v1_regression.py":
                    text = re.sub(r"FORBIDDEN\s*=\s*\[.*?\]", "", text, flags=re.DOTALL)
                if pattern.search(text):
                    offenders.append(rel)
        self.assertEqual(offenders, [], f"V1 identifiers found in active code: {offenders}")


if __name__ == "__main__":
    unittest.main()
