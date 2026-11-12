"""Level-triggered recovery of V2 expected units after an unchanged or committed apply."""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from typing import Any
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_systemd_reconcile as reconcile  # noqa: E402

OWNER = "nas-v2-app.service"
GATE = "nas-v2-ready-app.service"
JOB = "nas-v2-job.service"
TIMER = "nas-v2-timer-job-0.timer"
SOCKET = "nas-v2-activate-ondemand-web.socket"
ON_DEMAND = "nas-v2-ondemand.service"
OFF = "nas-v2-off.service"
NEW = "nas-v2-new.service"


class FakeSystemd:
    """Records systemctl calls against a simple unit-state table."""

    def __init__(self, states: dict[str, str]) -> None:
        self.states = dict(states)
        self.calls: list[tuple[str, ...]] = []
        self.timeouts: dict[tuple[str, ...], int] = {}
        self.fail: set[tuple[str, ...]] = set()
        self.query_errors: set[str] = set()

    def __call__(
        self, _binary: str, *args: str, check: bool = True, timeout_seconds: int = 180
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append(args)
        self.timeouts[args] = timeout_seconds
        if args[0] == "is-active":
            unit = args[1]
            if unit in self.query_errors:
                return subprocess.CompletedProcess([], 1, "", "Failed to connect to bus")
            state = self.states.get(unit, "inactive")
            code = {"active": 0, "unknown": 4}.get(state, 3)
            return subprocess.CompletedProcess([], code, state + "\n", "")
        if args in self.fail:
            if check:
                raise reconcile.SystemdReconcileError(f"systemctl {' '.join(args)} failed")
            return subprocess.CompletedProcess([], 1, "", "Unit is masked.")
        if args[0] in {"start", "restart"}:
            for unit in args[1:]:
                self.states[unit] = "active"
        return subprocess.CompletedProcess([], 0, "", "")

    def mutations(self) -> list[tuple[str, ...]]:
        return [call for call in self.calls if call[0] != "is-active"]


class StartConvergenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self._tmp.name)
        self.projection = self.root / "projection"
        self.projection.mkdir()
        self.runtime = self.root / "systemd"
        self.quadlet = self.root / "quadlet"
        self.runtime.mkdir()
        self.quadlet.mkdir()
        self.state = self.root / "state.json"
        self.manifest = self.projection / "manifest.json"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def write(
        self,
        units: dict[str, str],
        *,
        start: list[str],
        stop: list[str] | None = None,
        gates: dict[str, str] | None = None,
    ):
        gates = gates or {}
        stop = stop or []
        links = []
        for unit, body in units.items():
            source = self.projection / unit
            source.write_text(body, encoding="utf-8")
            links.append({"target": unit, "source": str(source)})
        self.manifest.write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "links": links,
                    "quadletLinks": [],
                    "ownedUnits": sorted(units),
                    "startUnits": sorted(start),
                    "readinessUnits": sorted(gates),
                    "readinessOwners": gates,
                    "stopUnits": sorted(stop),
                    "fingerprints": {unit: "v1" for unit in units},
                }
            ),
            encoding="utf-8",
        )

    def apply(self, systemd: FakeSystemd) -> dict[str, Any]:
        with mock.patch.object(reconcile, "_run_systemctl", side_effect=systemd):
            return reconcile.reconcile(
                manifest_path=self.manifest,
                projection_root=self.projection,
                systemd_runtime_dir=self.runtime,
                quadlet_runtime_dir=self.quadlet,
                state_path=self.state,
                systemctl="systemctl",
            )

    def lifecycle_units(self) -> dict[str, str]:
        return {
            OWNER: "[Service]\nExecStart=/bin/sleep infinity\n",
            GATE: f"[Unit]\nRequires={OWNER}\nAfter={OWNER}\n[Service]\nType=oneshot\nExecStart=/bin/true\n",
            JOB: "[Service]\nType=oneshot\nExecStart=/bin/true\n",
            TIMER: f"[Timer]\nUnit={JOB}\nOnCalendar=daily\n",
            SOCKET: "[Socket]\nListenStream=/run/x.sock\n",
            ON_DEMAND: "[Unit]\nStopWhenUnneeded=yes\n[Service]\nExecStart=/bin/sleep infinity\n",
            OFF: "[Service]\nExecStart=/bin/sleep infinity\n",
        }

    def establish(self) -> tuple[FakeSystemd, bytes]:
        self.write(self.lifecycle_units(), start=[OWNER, GATE, TIMER, SOCKET], stop=[OFF], gates={GATE: OWNER})
        boot = FakeSystemd({})
        self.apply(boot)
        return boot, self.state.read_bytes()

    def test_unchanged_manifest_queues_stopped_expected_units_only(self) -> None:
        boot, committed = self.establish()
        # A protected-target stop or a failed secret swap leaves expected units
        # cleanly stopped. A completed job and an idle on-demand owner are also
        # inactive, which is their correct steady state.
        systemd = FakeSystemd({GATE: "inactive", JOB: "inactive", ON_DEMAND: "inactive", OFF: "inactive"})
        result = self.apply(systemd)
        self.assertTrue(result["noop"])
        self.assertEqual(result["started"], [])
        self.assertEqual(result["recovery"], {"queued": [SOCKET, OWNER, GATE, TIMER], "diagnostics": []})
        self.assertEqual(
            systemd.mutations(),
            [
                ("--no-block", "start", SOCKET),
                ("--no-block", "start", OWNER, GATE),
                ("--no-block", "start", TIMER),
            ],
        )
        queried = {call[1] for call in systemd.calls if call[0] == "is-active"}
        # Gates, job owners, on-demand owners and off units are not even
        # candidates, so a completed job can never be replayed by recovery.
        self.assertEqual(queried, {OWNER, SOCKET, TIMER})
        self.assertEqual(self.state.read_bytes(), committed)
        self.assertNotIn(("start", JOB), boot.mutations())

    def test_running_expected_units_are_left_untouched(self) -> None:
        self.establish()
        systemd = FakeSystemd({OWNER: "active", SOCKET: "active", TIMER: "active", GATE: "failed"})
        result = self.apply(systemd)
        self.assertEqual(result["recovery"], {"queued": [], "diagnostics": []})
        # An active owner's failed gate keeps its diagnostic state.
        self.assertEqual(systemd.mutations(), [])

    def test_stopped_owner_reruns_the_gate_that_failed_for_its_previous_instance(self) -> None:
        self.establish()
        systemd = FakeSystemd({SOCKET: "active", TIMER: "active", OWNER: "inactive", GATE: "failed"})
        result = self.apply(systemd)
        # The gate's failure describes the stopped instance; the restarted owner
        # needs its own observation, and dependents Require= the gate anyway.
        self.assertEqual(result["recovery"], {"queued": [OWNER, GATE], "diagnostics": []})
        self.assertEqual(systemd.mutations(), [("--no-block", "start", OWNER, GATE)])

    def test_recovery_is_bounded_and_reports_units_left_unprobed(self) -> None:
        self.establish()
        systemd = FakeSystemd({})
        clock = iter([0.0, 0.0, reconcile._RECOVERY_DEADLINE_SECONDS, reconcile._RECOVERY_DEADLINE_SECONDS])
        with mock.patch.object(reconcile.time, "monotonic", side_effect=lambda: next(clock)):
            result = self.apply(systemd)
        self.assertEqual(result["recovery"]["queued"], [SOCKET])
        self.assertEqual(
            result["recovery"]["diagnostics"],
            [
                f"{OWNER}: recovery time budget exhausted; not queued",
                f"{TIMER}: recovery time budget exhausted; not queued",
            ],
        )
        recovery_calls = [
            call for call in systemd.calls if call in {("is-active", SOCKET), ("--no-block", "start", SOCKET)}
        ]
        self.assertEqual(len(recovery_calls), 2)
        for call in recovery_calls:
            self.assertEqual(systemd.timeouts[call], reconcile._RECOVERY_CALL_TIMEOUT_SECONDS)

    def test_failed_transitional_and_unknown_units_are_reported_not_restarted(self) -> None:
        self.establish()
        systemd = FakeSystemd({OWNER: "failed", SOCKET: "activating"})
        systemd.query_errors.add(TIMER)
        result = self.apply(systemd)
        self.assertEqual(result["recovery"]["queued"], [])
        self.assertEqual(
            result["recovery"]["diagnostics"],
            [
                f"{SOCKET}: activating; not queued",
                f"{OWNER}: failed; not queued",
                f"{TIMER}: state unavailable; not queued",
            ],
        )
        self.assertEqual(systemd.mutations(), [])

    def test_enqueue_failure_is_a_diagnostic_not_an_apply_failure(self) -> None:
        _, committed = self.establish()
        systemd = FakeSystemd({SOCKET: "active", TIMER: "active"})
        systemd.fail.add(("--no-block", "start", OWNER, GATE))
        result = self.apply(systemd)
        self.assertTrue(result["noop"])
        self.assertEqual(result["recovery"]["queued"], [])
        self.assertEqual(len(result["recovery"]["diagnostics"]), 1)
        self.assertIn("start could not be queued: Unit is masked.", result["recovery"]["diagnostics"][0])
        self.assertEqual(self.state.read_bytes(), committed)
        self.assertNotIn("daemon-reload", {call[0] for call in systemd.calls})

    def test_unrelated_change_does_not_gate_on_unchanged_stopped_workload(self) -> None:
        self.establish()
        units = self.lifecycle_units() | {NEW: "[Service]\nExecStart=/bin/sleep infinity\n"}
        self.write(units, start=[OWNER, GATE, TIMER, SOCKET, NEW], stop=[OFF], gates={GATE: OWNER})
        systemd = FakeSystemd({SOCKET: "active", TIMER: "active"})
        # An unhealthy unchanged gate cannot reject the unrelated edit: it is
        # never restarted synchronously, only queued with its stopped owner.
        systemd.fail.add(("restart", GATE))
        result = self.apply(systemd)
        self.assertFalse(result["noop"])
        self.assertEqual(result["started"], [NEW])
        self.assertEqual(result["recovery"], {"queued": [OWNER, GATE], "diagnostics": []})
        mutations = systemd.mutations()
        self.assertNotIn(("restart", GATE), mutations)
        self.assertEqual(mutations[-1], ("--no-block", "start", OWNER, GATE))
        self.assertLess(mutations.index(("restart", NEW)), len(mutations) - 1)
        self.assertEqual(json.loads(self.state.read_text())["startUnits"], sorted([OWNER, GATE, TIMER, SOCKET, NEW]))

    def test_units_activated_by_the_apply_are_not_queued_again(self) -> None:
        self.write(self.lifecycle_units(), start=[OWNER, GATE, TIMER, SOCKET], stop=[OFF], gates={GATE: OWNER})
        systemd = FakeSystemd({})
        result = self.apply(systemd)
        self.assertEqual(result["recovery"], {"queued": [], "diagnostics": []})
        self.assertFalse(any(call[0] == "--no-block" for call in systemd.calls))

    def test_explicit_off_unit_is_never_started_by_recovery(self) -> None:
        self.establish()
        units = self.lifecycle_units()
        self.write(units, start=[TIMER, SOCKET], stop=[OFF, OWNER, GATE])
        systemd = FakeSystemd({TIMER: "active", SOCKET: "active", OWNER: "active"})
        result = self.apply(systemd)
        self.assertIn(("stop", OWNER), systemd.mutations())
        self.assertEqual(result["recovery"], {"queued": [], "diagnostics": []})
        systemd = FakeSystemd({TIMER: "active", SOCKET: "active"})
        result = self.apply(systemd)
        self.assertTrue(result["noop"])
        self.assertEqual(systemd.mutations(), [])


if __name__ == "__main__":
    unittest.main()
