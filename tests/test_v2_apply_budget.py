from __future__ import annotations

import hashlib
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))

import nas_v2_apply_budget as budget  # noqa: E402
import nas_v2_systemd_reconcile as reconcile  # noqa: E402
from nas_v2_apply import ApplyPaths, compile_paths  # noqa: E402
from nas_v2_systemd_native import SystemdProjectionError  # noqa: E402


class ApplyBudgetTests(unittest.TestCase):
    def test_diamond_dependencies_are_counted_once_and_malformed_services_fail(self):
        document = {
            "services": {
                "a": {"readiness": {"timeoutSeconds": 100}},
                "b": {"dependencies": [{"service": "a"}]},
                "c": {"dependencies": [{"service": "a"}]},
                "d": {
                    "dependencies": [{"service": "b", "condition": "started"}, {"service": "c", "condition": "started"}]
                },
            }
        }
        expected = budget.document_budget(document)
        document["services"]["d"]["dependencies"].append({"service": "a"})
        self.assertEqual(budget.document_budget(document), expected)
        with self.assertRaisesRegex(ValueError, "services must be an object"):
            budget.document_budget({"services": []})

    def test_ordered_gates_and_sequential_owners_fit_the_armed_budget(self):
        document = {
            "services": {
                "a": {"readiness": {"timeoutSeconds": 100}},
                "b": {"readiness": {"timeoutSeconds": 100}, "dependencies": [{"service": "a", "condition": "ready"}]},
                "c": {"dependencies": [{"service": "b", "condition": "ready"}]},
            }
        }
        limits = budget.document_budget(document)
        elapsed = 0

        def systemctl(argv, **kwargs):
            nonlocal elapsed
            if kwargs["timeout"] < 200:
                raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
            elapsed += 200
            return subprocess.CompletedProcess(argv, 0, "", "")

        with mock.patch.object(reconcile.subprocess, "run", side_effect=systemctl):
            with self.assertRaises(reconcile.SystemdReconcileError):
                reconcile._run_systemctl("systemctl", "restart", "dependent.service")
            for owner in ("dependent.service", "second.service"):
                reconcile._run_systemctl("systemctl", "restart", owner, timeout_seconds=limits["commandSeconds"])
        self.assertGreater(elapsed, 300)
        self.assertGreater(limits["transactionSeconds"], elapsed)
        document["services"]["c"]["dependencies"][0].pop("condition")
        self.assertEqual(budget.document_budget(document), limits)

    def test_previous_generation_and_callers_share_the_budget(self):
        with tempfile.TemporaryDirectory() as raw:
            desired = pathlib.Path(raw) / "services.yaml"
            state = pathlib.Path(raw) / "state.json"
            desired.write_text('{"schemaVersion":3,"services":{"demo":{}}}')
            initial = budget.authority_budget(desired, state)
            state.write_text(json.dumps({"ownedUnits": ["old.service"], "activationTimeoutSeconds": 900}))
            current = budget.authority_budget(desired, state)
            self.assertGreater(current["transactionSeconds"], initial["transactionSeconds"] + 900)
            self.assertEqual(current["commandSeconds"], 900)
            self.assertEqual(current["desiredSha256"], hashlib.sha256(desired.read_bytes()).hexdigest())
            with mock.patch.object(budget, "authority_budget", return_value=current):
                self.assertEqual(budget.client_timeout(), current["transactionSeconds"] + 30)

    def test_changed_authority_is_rejected_before_compilation(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            desired = root / "services.yaml"
            desired.write_text('{"schemaVersion":3,"services":{}}')
            packet = root / "budget.json"
            packet.write_text(json.dumps({"desiredSha256": "0" * 64}))
            with mock.patch.dict("os.environ", {"NAS_V2_APPLY_BUDGET": str(packet)}):
                with self.assertRaisesRegex(SystemdProjectionError, "changed after apply budgeting"):
                    compile_paths(
                        ApplyPaths(
                            desired=desired, schema=ROOT / "schemas/managed-services-v3.schema.json", platform=None
                        )
                    )

    def test_guard_preparation_cli_emits_revision_bound_finite_budget(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            desired = root / "services.yaml"
            state = root / "state.json"
            desired.write_text('{"schemaVersion":3,"services":{"demo":{}}}')
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "services/nas_v2_apply_budget.py"),
                    "--desired",
                    str(desired),
                    "--state",
                    str(state),
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=True,
            )
            self.assertEqual(json.loads(result.stdout), budget.authority_budget(desired, state))
            self.assertGreater(json.loads(result.stdout)["transactionSeconds"], 300)
            with (
                mock.patch.object(sys, "argv", ["budget", "--desired", str(desired), "--state", str(state)]),
                mock.patch.object(sys, "stdout", new_callable=io.StringIO) as output,
            ):
                self.assertEqual(budget.main(), 0)
            self.assertEqual(json.loads(output.getvalue()), json.loads(result.stdout))
            state.write_text('{"activationTimeoutSeconds":true}')
            with self.assertRaisesRegex(ValueError, "previous activation budget"):
                budget.authority_budget(desired, state)
            with mock.patch.object(budget, "authority_budget", side_effect=ValueError("invalid authority")):
                self.assertEqual(budget.client_timeout(), 330)
