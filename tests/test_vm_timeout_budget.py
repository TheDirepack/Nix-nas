from __future__ import annotations

import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
INTEGRATION = ROOT / "tests" / "nixos" / "integration.nix"
GUEST_TEST = ROOT / "tests" / "vm" / "guest-test.sh"


def _seconds(pattern: str, text: str, description: str) -> int:
    match = re.search(pattern, text)
    if match is None:
        raise AssertionError(f"could not find {description}")
    return int(match.group(1))


class VmTimeoutBudgetTests(unittest.TestCase):
    def test_outer_guest_watchdog_covers_serial_bounded_stages(self) -> None:
        integration = INTEGRATION.read_text(encoding="utf-8")
        guest = GUEST_TEST.read_text(encoding="utf-8")

        outer = _seconds(
            r"timeout --verbose --kill-after=30s (\d+)s nas-vm-guest-test",
            integration,
            "full-stack guest watchdog",
        )
        first_run = _seconds(
            r"timeout (\d+) nas-setup first-run",
            guest,
            "first-run timeout",
        )
        secret_activation = _seconds(
            r"timeout (\d+) nas-secrets activate-stdin",
            guest,
            "secret activation timeout",
        )
        browser = _seconds(
            r"timeout (\d+) python3 .*tests/browser/authz\.py",
            guest,
            "browser authorization timeout",
        )
        ordinary_wait = _seconds(
            r"NAS_TEST_TIMEOUT:-([0-9]+)",
            guest,
            "ordinary guest wait timeout",
        )

        # These stages are serialized in one guest-test invocation.  Reserve two
        # ordinary service-wait windows in addition to the explicitly expensive
        # stages so the outer watchdog cannot undercut its own child budgets.
        minimum = first_run + secret_activation + browser + (2 * ordinary_wait)
        self.assertGreaterEqual(outer, minimum)
        self.assertNotIn("timeout 1800 nas-vm-guest-test", integration)
        self.assertIn("timeout --verbose --kill-after=30s", integration)


if __name__ == "__main__":
    unittest.main()
