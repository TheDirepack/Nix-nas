"""Installed V2 recovery checks across secret stop, activation and activation rollback.

The fixture is declared once, before the OCI qualification baseline is recorded,
and is never edited afterwards. Failure is injected through a runtime marker and a
runtime systemd drop-in, both removed by ``repair``.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import time

HEALTHY = "vm-lifecycle-healthy"
FLAKY = "vm-lifecycle-flaky"
OFF = "vm-lifecycle-off"
JOB = "vm-lifecycle-job"
UNITS = {name: f"nas-v2-{name}.service" for name in (HEALTHY, FLAKY, OFF, JOB)}
GATE = f"nas-v2-ready-{HEALTHY}.service"
TIMER = f"nas-v2-timer-{JOB}-0.timer"
BROKEN_MARKER = pathlib.Path("/run/nas-vm-lifecycle-broken")
OUTPOST = "nas-authentik-proxy-outpost.service"
OUTPOST_FAILURE = pathlib.Path(f"/run/systemd/system/{OUTPOST}.d/90-vm-lifecycle-failure.conf")
STATE = pathlib.Path("/var/lib/nas-test/lifecycle-probe.json")
SH = "/run/current-system/sw/bin/sh"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def command(*argv: str, input_text: str | None = None, timeout: float = 120, check: bool = True) -> str:
    result = subprocess.run(argv, input=input_text, capture_output=True, text=True, timeout=timeout, check=False)
    if check:
        require(result.returncode == 0, f"{' '.join(argv[:3])} failed ({result.returncode}): {result.stderr[-1200:]}")
    return result.stdout.strip()


def show(unit: str, prop: str) -> str:
    return command("systemctl", "show", unit, f"--property={prop}", "--value")


def start_jobs(unit: str, *, since_us: int = 0) -> list[dict]:
    """Return PID 1 start-job journal records for ``unit``.

    Inactive oneshot gates and never-started units are garbage-collected, after
    which systemctl show reports an empty InvocationID; the journal keeps an
    exact record of every start job instead.
    """
    argv = ["journalctl", "--no-pager", "--output=json", f"--unit={unit}"]
    if since_us:
        argv.append(f"--since=@{since_us // 1_000_000}")
    records = [json.loads(line) for line in command(*argv).splitlines() if line.startswith("{")]
    return [
        record
        for record in records
        if record.get("JOB_TYPE") == "start" and int(record["__REALTIME_TIMESTAMP"]) > since_us
    ]


def completed_starts(unit: str, *, since_us: int = 0) -> int:
    return sum(1 for record in start_jobs(unit, since_us=since_us) if record.get("JOB_RESULT") == "done")


def now_us() -> int:
    return time.time_ns() // 1000


def wait_for(description: str, predicate, timeout: float = 120.0) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            raise RuntimeError(f"timed out waiting for {description}")
        time.sleep(1)


def daemon(name: str, script: str, *, enabled: bool = True) -> dict:
    return {
        "name": name,
        "enabled": enabled,
        "workload": {"kind": "daemon", "activation": "persistent"},
        "runtime": {"type": "exec", "command": [SH, "-c", script], "restart": "no"},
    }


def fixture() -> dict[str, dict]:
    healthy = daemon("VM lifecycle healthy daemon", "exec /run/current-system/sw/bin/sleep infinity")
    healthy["readiness"] = {"timeoutSeconds": 30, "probes": [{"type": "systemd"}]}
    return {
        HEALTHY: healthy,
        FLAKY: daemon(
            "VM lifecycle flaky daemon",
            f"test ! -e {BROKEN_MARKER} && exec /run/current-system/sw/bin/sleep infinity; exit 1",
        ),
        OFF: daemon("VM lifecycle off daemon", "exec /run/current-system/sw/bin/sleep infinity", enabled=False),
        JOB: {
            "name": "VM lifecycle scheduled job",
            "workload": {"kind": "job", "schedules": [{"calendar": "*-01-01 00:00:00", "persistent": False}]},
            "runtime": {"type": "exec", "command": [SH, "-c", "true"]},
        },
    }


def save(value: dict) -> None:
    STATE.write_text(json.dumps(value, sort_keys=True) + "\n")
    STATE.chmod(0o600)


def create() -> None:
    require(not STATE.exists(), "lifecycle fixture already exists; use a fresh disposable VM")
    value = json.loads(command("nas-managed-services-control", "document"))
    desired = value["document"]
    for name in fixture():
        require(name not in desired["services"], f"lifecycle service already exists: {name}")
    desired["services"].update(fixture())
    command(
        "nas-managed-services-control",
        "replace-json-document",
        "-",
        value["revision"],
        input_text=json.dumps(desired),
        timeout=400,
    )
    wait_for("healthy daemon", lambda: show(UNITS[HEALTHY], "ActiveState") == "active")
    wait_for("flaky daemon", lambda: show(UNITS[FLAKY], "ActiveState") == "active")
    require(show(TIMER, "ActiveState") == "active", "job timer is not active")
    require(show(UNITS[OFF], "ActiveState") == "inactive", "off daemon started")
    command("systemctl", "start", UNITS[JOB])
    require(show(UNITS[JOB], "Result") == "success", "job did not complete")
    require(completed_starts(UNITS[JOB]) == 1, "job did not record exactly one completed run")
    require(not start_jobs(UNITS[OFF]), "off daemon received a start job")
    STATE.parent.mkdir(parents=True, exist_ok=True)
    save({"since": now_us()})
    print("PASS: V2 lifecycle fixture declared", flush=True)


def locked() -> None:
    # nas-secrets stop returns only after the target's members finished stopping.
    for name in (HEALTHY, FLAKY):
        state = show(UNITS[name], "ActiveState")
        require(state == "inactive", f"{UNITS[name]} remained {state} after nas-secrets stop returned")
    state = show(TIMER, "ActiveState")
    require(state == "inactive", f"{TIMER} remained {state} and could start its job while locked")
    require(not pathlib.Path("/run/nas-secrets").exists(), "secrets remain after stop")
    result = subprocess.run(["systemctl", "start", UNITS[HEALTHY]], capture_output=True, timeout=60, check=False)
    require(result.returncode == 0, "condition-skipped start should not fail")
    require(show(UNITS[HEALTHY], "ActiveState") == "inactive", "generated owner started while locked")
    require(show(UNITS[HEALTHY], "ConditionResult") == "no", "generated owner is not gated on secret readiness")
    mark_recovery_window()
    print("PASS: generated V2 owners stopped before secrets were removed and stay down while locked", flush=True)


def status_row(name: str) -> dict:
    rows = json.loads(command("nas-managed-services-control", "status"))["services"]
    return next(row for row in rows if row.get("id") == name)


def mark_recovery_window() -> None:
    save({"since": now_us()})


def recovered(*, flaky_failed: bool) -> None:
    since = json.loads(STATE.read_text())["since"]
    # Queued recovery is asynchronous; wait for observed runtime outcomes.
    wait_for("copyparty recovery", lambda: show("copyparty.service", "ActiveState") == "active")
    wait_for("healthy daemon recovery", lambda: show(UNITS[HEALTHY], "ActiveState") == "active")
    # The queued owner's gate runs again: queued recovery is observed, not assumed.
    wait_for(
        "healthy readiness gate",
        lambda: completed_starts(GATE, since_us=since) >= 1 and show(GATE, "ActiveState") == "inactive",
    )
    wait_for("job timer recovery", lambda: show(TIMER, "ActiveState") == "active")
    require(completed_starts(UNITS[JOB]) == 1, "completed job was replayed")
    # A replayed start that failed would not count as completed.
    require(not start_jobs(UNITS[JOB], since_us=since), "recovery queued a start job for the completed job")
    require(show(UNITS[OFF], "ActiveState") == "inactive", "off daemon was started")
    require(not start_jobs(UNITS[OFF]), "off daemon received a start job")
    if flaky_failed:
        wait_for("flaky daemon failure", lambda: show(UNITS[FLAKY], "ActiveState") == "failed")
        row = status_row(FLAKY)
        require(row["stateLabel"] == "Failed", f"V2 status did not report the failed app: {row['stateLabel']}")
        require(status_row(HEALTHY)["stateLabel"] == "Running", "V2 status did not report the healthy app")
    else:
        wait_for("flaky daemon recovery", lambda: show(UNITS[FLAKY], "ActiveState") == "active")
    print(
        f"PASS: V2 expected units recovered (flaky failed={flaky_failed}); off and completed job untouched", flush=True
    )


def break_flaky() -> None:
    BROKEN_MARKER.touch()
    mark_recovery_window()


def fail_outpost() -> None:
    OUTPOST_FAILURE.parent.mkdir(parents=True, exist_ok=True)
    OUTPOST_FAILURE.write_text("[Service]\nExecStartPre=/run/current-system/sw/bin/false\n")
    command("systemctl", "daemon-reload")
    mark_recovery_window()


def repair() -> None:
    BROKEN_MARKER.unlink(missing_ok=True)
    OUTPOST_FAILURE.unlink(missing_ok=True)
    command("systemctl", "daemon-reload")
    command("systemctl", "reset-failed", OUTPOST, UNITS[FLAKY], check=False)
    command("systemctl", "start", OUTPOST)
    # A failed workload keeps its diagnostic state until the operator clears it;
    # an unchanged reconcile then recovers it like any other stopped unit.
    command("systemctl", "start", "nas-managed-services-reconcile.service", timeout=400)
    wait_for("repaired flaky daemon", lambda: show(UNITS[FLAKY], "ActiveState") == "active")
    print("PASS: repaired workload recovered through the unchanged V2 reconcile", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "mode", choices=("create", "locked", "recovered", "recovered-failed", "break", "fail-outpost", "repair")
    )
    args = parser.parse_args()
    actions = {
        "create": create,
        "locked": locked,
        "recovered": lambda: recovered(flaky_failed=False),
        "recovered-failed": lambda: recovered(flaky_failed=True),
        "break": break_flaky,
        "fail-outpost": fail_outpost,
        "repair": repair,
    }
    try:
        actions[args.mode]()
    except (RuntimeError, OSError, ValueError, KeyError, StopIteration, subprocess.TimeoutExpired) as error:
        print(f"V2 lifecycle qualification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
