from __future__ import annotations

import unittest

from repo_test_utils import text


class V2TransactionWiringTests(unittest.TestCase):
    def test_core_apply_is_guarded_before_compile_and_marks_compiled_revision_last(self) -> None:
        managed = text("modules/nas/config/managed-services-transactions.nix")
        pre_start = managed.split("preStart = lib.mkBefore ''", 1)[1].split("    '';", 1)[0]
        post_start = managed.split("postStart = lib.mkForce ''", 1)[1].split("    '';", 1)[0]

        self.assertIn("nas_guarded_apply.py", pre_start)
        self.assertIn("systemd-run", pre_start)
        self.assertIn("${guardUnitShell}", pre_start)
        self.assertNotIn(" record", pre_start)
        self.assertIn("desiredRevision", post_start)
        firewall_reconcile = post_start.index("statelessFirewalldArgs")
        systemd_reconcile = post_start.index("systemdReconcileArgs")
        mark_applied = post_start.index("mark-applied")
        cancel = post_start.index("cancel")
        self.assertLess(firewall_reconcile, systemd_reconcile)
        self.assertLess(systemd_reconcile, mark_applied)
        self.assertLess(mark_applied, cancel)
        self.assertIn('mark-applied --commit "$desired_head"', post_start)
        self.assertIn("restore-applied", managed)
        self.assertIn("nas-v2-apply-failed.service", managed)

    def test_old_firewall_specific_ack_protocol_is_not_in_transaction_module(self) -> None:
        managed = text("modules/nas/config/managed-services-transactions.nix")
        self.assertNotIn("pending.json", managed)
        self.assertNotIn("--acknowledge", managed)
        self.assertNotIn("firewalldDeadmanStateDir", managed)
        self.assertNotIn("nas-v2-firewall-rollback.timer", managed)

    def test_rollback_guard_is_scoped_to_systemd_invocation(self) -> None:
        managed = text("modules/nas/config/managed-services-transactions.nix")
        self.assertIn("INVOCATION_ID", managed)
        self.assertIn('guard_unit="nas-v2-apply-rollback-$guard_suffix"', managed)
        self.assertIn("systemctl stop 'nas-v2-apply-rollback-*.timer'", managed)
        self.assertIn("rev-parse --verify HEAD", managed)
        post_start = managed.split("postStart = lib.mkForce ''", 1)[1].split("    '';", 1)[0]
        self.assertNotIn("rev-parse --verify HEAD", post_start)

    def test_compiler_owns_git_recording_under_authority_lock(self) -> None:
        apply_source = text("services/nas_v2_apply.py").split("def apply(", 1)[1]
        lock_body = apply_source.split("with authority_lock(paths.desired):", 1)[1].split("return plan", 1)[0]
        self.assertLess(lock_body.index("record_desired_locked"), lock_body.index("_compile_paths_inner"))
        self.assertIn('plan["desiredRevision"] = desired_revision', lock_body)


if __name__ == "__main__":
    unittest.main()