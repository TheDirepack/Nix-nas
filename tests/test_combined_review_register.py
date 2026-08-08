from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTER = ROOT / "docs" / "development" / "combined-review-remediation.md"


class CombinedReviewRegisterTests(unittest.TestCase):
    def test_every_review_finding_is_deduplicated_exactly_once(self) -> None:
        text = REGISTER.read_text(encoding="utf-8")
        expected = [f"A18:C-{index:02d}" for index in range(1, 6)]
        expected += [f"A18:H-{index:02d}" for index in range(1, 32)]
        expected += [f"A18:M-{index:02d}" for index in range(1, 33)]
        expected += [f"A20:C{index:02d}" for index in range(1, 9)]
        expected += [f"A20:H{index:02d}" for index in range(1, 39)]
        expected += [f"A20:M{index:02d}" for index in range(1, 25)]
        found = re.findall(r"A(?:18|20):(?:C-|H-|M-)?\d{2}|A20:[CHM]\d{2}", text)
        self.assertEqual(sorted(found), sorted(expected))
        self.assertEqual(len(found), len(set(found)))

    def test_risk_register_does_not_reintroduce_retired_first_start_claim(self) -> None:
        risks = (ROOT / "docs" / "development" / "known-risks.md").read_text(encoding="utf-8")
        self.assertNotIn("first-start browser request remains synchronous", risks)
        self.assertIn("First-start is a detached systemd job", risks)

    def test_obsolete_firewall_schema_marker_and_update_check_name_are_absent(self) -> None:
        firewall = (ROOT / "modules" / "nas" / "config" / "network-firewall.nix").read_text(encoding="utf-8")
        self.assertNotIn("baseline-schema-version", firewall)
        sources = "\n".join(
            path.read_text(encoding="utf-8", errors="ignore")
            for root in (ROOT / "cockpit", ROOT / "services", ROOT / "modules")
            for path in root.rglob("*")
            if path.is_file()
            and "__pycache__" not in path.parts
            and path.suffix not in {".woff", ".woff2", ".png", ".jpg", ".jpeg", ".svg", ".ico"}
            and "assets" not in path.parts
        )
        self.assertNotIn("nas-update-check", sources)
        self.assertNotIn('"update-check"', sources)
        self.assertIn("nas-update-preview", sources)


if __name__ == "__main__":
    unittest.main()
