from __future__ import annotations

import unittest

from repo_test_utils import text


class V2FirewalldDeadmanWiringTests(unittest.TestCase):
    def test_reconcile_acknowledges_firewall_only_after_systemd_activation(self) -> None:
        managed = text("modules/nas/config/managed-services.nix")
        post_start = managed.split("      postStart = ''", 1)[1].split("      '';", 1)[0]

        firewall_reconcile = post_start.index("firewalldReconcileArgs")
        systemd_reconcile = post_start.index("systemdReconcileArgs")
        acknowledge = post_start.index("--acknowledge")

        self.assertLess(firewall_reconcile, systemd_reconcile)
        self.assertLess(systemd_reconcile, acknowledge)
        self.assertIn("pending.json", post_start)
        self.assertIn("jq -er", post_start)


if __name__ == "__main__":
    unittest.main()
