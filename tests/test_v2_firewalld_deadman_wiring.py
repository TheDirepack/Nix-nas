from __future__ import annotations

import unittest

from repo_test_utils import text


class V2TransactionWiringTests(unittest.TestCase):
    def test_core_apply_is_guarded_and_marks_git_revision_only_after_activation(self) -> None:
        managed = text("modules/nas/config/managed-services-transactions.nix")
        post_start = managed.split("postStart = lib.mkForce ''", 1)[1].split("    '';", 1)[0]

        arm = post_start.index("guardArmArgs")
        firewall_reconcile = post_start.index("statelessFirewalldArgs")
        systemd_reconcile = post_start.index("systemdReconcileArgs")
        mark_applied = post_start.index("mark-applied")
        cancel = post_start.index("guardCancelArgs")

        self.assertLess(arm, firewall_reconcile)
        self.assertLess(firewall_reconcile, systemd_reconcile)
        self.assertLess(systemd_reconcile, mark_applied)
        self.assertLess(mark_applied, cancel)
        self.assertIn("restore-applied", managed)
        self.assertIn("${pkgs.systemd}/bin/systemd-run", managed)

    def test_old_firewall_specific_ack_protocol_is_not_in_transaction_module(self) -> None:
        managed = text("modules/nas/config/managed-services-transactions.nix")
        self.assertNotIn("pending.json", managed)
        self.assertNotIn("--acknowledge", managed)
        self.assertNotIn("firewalldDeadmanStateDir", managed)
        self.assertNotIn("nas-v2-firewall-rollback.timer", managed)

    def test_desired_state_is_recorded_before_compile(self) -> None:
        managed = text("modules/nas/config/managed-services-transactions.nix")
        pre_start = managed.split("preStart = lib.mkBefore ''", 1)[1].split("    '';", 1)[0]
        self.assertIn("historyArgs", pre_start)
        self.assertIn("record", pre_start)


if __name__ == "__main__":
    unittest.main()
