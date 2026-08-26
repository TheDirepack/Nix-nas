from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SYSTEM = ROOT / "modules/nas/config/system.nix"
STATE = ROOT / "services/nas_state.py"


class StateRollbackSecurityTests(unittest.TestCase):
    def test_production_rollback_root_is_tmpfs_backed(self) -> None:
        source = SYSTEM.read_text(encoding="utf-8")
        self.assertIn('NAS_STATE_ROLLBACK_ROOT = "/run/nas-state/rollbacks"', source)
        self.assertIn('"d /run/nas-state/rollbacks 0700 root root -"', source)
        self.assertNotIn('NAS_STATE_ROLLBACK_ROOT = "/var/lib/nas-state', source)

    def test_automatic_rollback_is_not_the_durable_recovery_domain(self) -> None:
        source = STATE.read_text(encoding="utf-8")
        self.assertIn("export_bundle(rollback, include_sensitive=True, quiesce=False)", source)
        # The Python fallback may remain useful for isolated development tests;
        # production Nix wiring must override it into /run before execution.
        system = SYSTEM.read_text(encoding="utf-8")
        self.assertIn("tmpfs-backed /run", system)
        self.assertIn("transaction scratch state only", system)


if __name__ == "__main__":
    unittest.main()
