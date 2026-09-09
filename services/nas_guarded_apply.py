#!/usr/bin/env python3
"""Durable systemd-backed rollback guard with explicit outcome protocol.

Commit/cancel and timer firing coordinate against a per-guard JSON record
under the state directory. Exactly one outcome wins: armed, claimed,
completed, failed, cancelled, or collected.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Sequence

DEFAULT_UNIT = "nas-v2-apply-rollback"
DEFAULT_STATE_DIR = "/run/nas-control/rollback-guard"
SCHEMA_VERSION = 1

ARMED = "armed"
CLAIMED = "claimed"
COMPLETED = "completed"
FAILED = "failed"
CANCELLED = "cancelled"
COLLECTED = "collected"


class GuardedApplyError(RuntimeError):
    """Raised when the rollback guard cannot be armed or cancelled safely."""


def _run(command: Sequence[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            list(command),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GuardedApplyError(f"unable to execute {command[0]}: {exc}") from exc
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[:4000]
        raise GuardedApplyError(f"command failed ({result.returncode}): {' '.join(command)}: {detail}")
    return result


def _validate_unit(unit: str) -> str:
    if not unit or len(unit) > 128:
        raise GuardedApplyError("guard unit name is empty or too long")
    if any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.@:-" for ch in unit):
        raise GuardedApplyError(f"unsafe guard unit name: {unit!r}")
    if unit.endswith(".service") or unit.endswith(".timer"):
        unit = unit.rsplit(".", 1)[0]
    return unit


def _validate_state_dir(state_dir: str | os.PathLike[str]) -> Path:
    path = Path(state_dir)
    if not str(state_dir) or not path.is_absolute():
        raise GuardedApplyError(f"guard state directory must be an absolute path: {state_dir!r}")
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise GuardedApplyError(f"unable to create guard state directory {path}: {exc}") from exc
    return path


def _state_path(unit: str, state_root: Path) -> Path:
    return state_root / f"{unit}.json"


def _lock_path(unit: str, state_root: Path) -> Path:
    return state_root / f"{unit}.lock"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_state(path: Path) -> dict[str, Any] | None:
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise GuardedApplyError(f"unable to read guard state {path}: {exc}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise GuardedApplyError(f"guard state is corrupt: {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise GuardedApplyError(f"guard state is corrupt: {path}")
    return data


def _write_state(path: Path, payload: dict[str, Any]) -> None:
    tmp = path.with_name(f"{path.name}.tmp.{os.getpid()}")
    try:
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(tmp, path)
    except OSError as exc:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise GuardedApplyError(f"unable to persist guard state {path}: {exc}") from exc


@contextlib.contextmanager
def _locked(unit: str, state_root: Path) -> Iterator[None]:
    lock_file = _lock_path(unit, state_root)
    try:
        handle = open(lock_file, "a+")
    except OSError as exc:
        raise GuardedApplyError(f"unable to open guard lock {lock_file}: {exc}") from exc
    with handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        except OSError as exc:
            raise GuardedApplyError(f"unable to lock guard {unit}: {exc}") from exc
        try:
            yield
        finally:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass


def _describe_service(service: str, systemctl: str) -> dict[str, Any]:
    active = _run([systemctl, "is-active", service], check=False)
    failed = _run([systemctl, "is-failed", service], check=False)
    show = _run(
        [systemctl, "show", service, "-p", "LoadState", "-p", "ActiveState", "-p", "SubState", "-p", "Result"],
        check=False,
    )
    fields: dict[str, str] = {}
    if show.returncode == 0:
        for line in (show.stdout or "").splitlines():
            if "=" in line:
                key, _, value = line.partition("=")
                fields[key.strip()] = value.strip()
    else:
        fields["LoadState"] = "not-found"
    return {
        "isActive": active.returncode == 0,
        "isFailed": failed.returncode == 0,
        "loadState": fields.get("LoadState", "unknown"),
        "activeState": fields.get("ActiveState", "unknown"),
        "subState": fields.get("SubState", "unknown"),
        "result": fields.get("Result", ""),
    }


def _fired_wrapper(
    *, unit: str, state_dir: str, systemctl: str, rollback: list[str]
) -> list[str]:
    return [
        sys.executable,
        os.path.abspath(__file__),
        "--state-dir",
        state_dir,
        "--systemctl",
        systemctl,
        "fired",
        "--unit",
        unit,
        "--",
        *rollback,
    ]


def _terminal_error(state: str, unit: str) -> GuardedApplyError:
    if state == CLAIMED:
        return GuardedApplyError(f"rollback already claimed/running for guard: {unit}")
    if state == COMPLETED:
        return GuardedApplyError(f"rollback already completed for guard: {unit}")
    if state == FAILED:
        return GuardedApplyError(f"rollback already failed for guard: {unit}")
    if state == CANCELLED:
        return GuardedApplyError(f"guard already cancelled: {unit}")
    if state == COLLECTED:
        return GuardedApplyError(f"guard already collected: {unit}")
    return GuardedApplyError(f"guard is not armed (state={state}): {unit}")


def arm(
    rollback_command: Sequence[str],
    *,
    timeout_seconds: int = 60,
    unit: str = DEFAULT_UNIT,
    systemd_run: str = "systemd-run",
    systemctl: str = "systemctl",
    state_dir: str | os.PathLike[str] = DEFAULT_STATE_DIR,
) -> dict[str, Any]:
    """Arm a transient rollback timer with a durable armed record."""
    unit = _validate_unit(unit)
    if not isinstance(timeout_seconds, int) or isinstance(timeout_seconds, bool) or timeout_seconds <= 0:
        raise GuardedApplyError("guard timeout must be a positive integer")
    command = [str(item) for item in rollback_command]
    if not command or not command[0]:
        raise GuardedApplyError("rollback command must not be empty")
    state_root = _validate_state_dir(state_dir)

    timer = f"{unit}.timer"
    service = f"{unit}.service"
    with _locked(unit, state_root):
        path = _state_path(unit, state_root)
        prior = _read_state(path)
        if prior is not None:
            prior_state = str(prior.get("state", "unknown"))
            if prior_state in (ARMED, CLAIMED):
                raise GuardedApplyError(f"guard already active (state={prior_state}): {unit}")
            if prior_state in (COMPLETED, FAILED):
                raise GuardedApplyError(
                    f"unresolved prior guard outcome (state={prior_state}): {unit}; collect it first"
                )
        _run([systemctl, "stop", timer], check=False)
        live = _describe_service(service, systemctl)
        if live["isActive"] or live["activeState"] in ("active", "activating"):
            raise GuardedApplyError(f"rollback service is already active: {service}")
        if live["isFailed"] or live["activeState"] == "failed":
            raise GuardedApplyError(f"rollback service already failed before guard arming: {service}")
        if live["result"] not in ("", "unknown"):
            raise GuardedApplyError(
                f"rollback service already fired before guard arming (result={live['result']}): {service}"
            )
        payload = {
            "schemaVersion": SCHEMA_VERSION,
            "unit": unit,
            "timer": timer,
            "service": service,
            "state": ARMED,
            "rollbackCommand": command,
            "timeoutSeconds": timeout_seconds,
            "armedAt": _now(),
            "updatedAt": _now(),
        }
        _write_state(path, payload)

    trigger = _fired_wrapper(unit=unit, state_dir=str(state_root), systemctl=systemctl, rollback=command)
    result = _run(
        [
            systemd_run,
            f"--unit={unit}",
            f"--on-active={timeout_seconds}s",
            "--timer-property=AccuracySec=1s",
            "--collect",
            "--quiet",
            "--",
            *trigger,
        ],
        check=False,
    )
    if result.returncode != 0:
        with _locked(unit, state_root):
            path = _state_path(unit, state_root)
            current = _read_state(path)
            if current is not None and current.get("state") == ARMED and current.get("rollbackCommand") == command:
                try:
                    path.unlink()
                except OSError:
                    pass
        detail = (result.stderr or result.stdout).strip()[:4000]
        raise GuardedApplyError(f"unable to arm rollback timer {timer}: {detail}")
    return {
        "ok": True,
        "armed": True,
        "unit": unit,
        "timer": timer,
        "state": ARMED,
        "stateDir": str(state_root),
        "timeoutSeconds": timeout_seconds,
        "rollbackCommand": command,
    }


def cancel(
    *,
    unit: str = DEFAULT_UNIT,
    systemctl: str = "systemctl",
    state_dir: str | os.PathLike[str] = DEFAULT_STATE_DIR,
) -> dict[str, Any]:
    """Cancel an armed guard only after proving rollback never fired."""
    unit = _validate_unit(unit)
    state_root = _validate_state_dir(state_dir)
    timer = f"{unit}.timer"
    service = f"{unit}.service"
    with _locked(unit, state_root):
        path = _state_path(unit, state_root)
        current = _read_state(path)
        if current is None:
            raise GuardedApplyError(
                f"no durable guard state for {unit}; refusing to report success from unit activity alone"
            )
        state = str(current.get("state", "unknown"))
        if state != ARMED:
            raise _terminal_error(state, unit)
        stopped = _run([systemctl, "stop", timer], check=False)
        if stopped.returncode != 0:
            detail = (stopped.stderr or stopped.stdout).strip()[:4000]
            raise GuardedApplyError(f"unable to cancel rollback timer {timer}: {detail}")
        live = _describe_service(service, systemctl)
        if live["isActive"] or live["activeState"] in ("active", "activating"):
            raise GuardedApplyError(f"rollback service already started before guard cancellation: {service}")
        if live["isFailed"] or live["activeState"] == "failed":
            current.update(
                {
                    "state": FAILED,
                    "updatedAt": _now(),
                    "detail": "cancel observed failed rollback service",
                    "live": live,
                }
            )
            _write_state(path, current)
            raise GuardedApplyError(f"rollback already failed for guard: {unit}")
        if live["loadState"] == "not-found":
            raise GuardedApplyError(
                f"guard unit already collected for {unit}; cannot prove never-fired cancellation"
            )
        result_text = str(live.get("result", ""))
        if result_text not in ("", "unknown"):
            observed = COMPLETED if result_text == "success" else FAILED
            current.update(
                {
                    "state": observed,
                    "updatedAt": _now(),
                    "detail": f"cancel observed fired rollback (result={result_text})",
                    "live": live,
                }
            )
            _write_state(path, current)
            raise _terminal_error(observed, unit)
        current.update({"state": CANCELLED, "updatedAt": _now()})
        _write_state(path, current)
        return {"ok": True, "armed": False, "unit": unit, "timer": timer, "state": CANCELLED}


def fired(
    rollback_command: Sequence[str],
    *,
    unit: str = DEFAULT_UNIT,
    systemctl: str = "systemctl",
    state_dir: str | os.PathLike[str] = DEFAULT_STATE_DIR,
) -> dict[str, Any]:
    """Claim an armed guard, run rollback, and record the terminal outcome."""
    unit = _validate_unit(unit)
    command = [str(item) for item in rollback_command]
    if not command or not command[0]:
        raise GuardedApplyError("rollback command must not be empty")
    state_root = _validate_state_dir(state_dir)
    service = f"{unit}.service"
    with _locked(unit, state_root):
        path = _state_path(unit, state_root)
        current = _read_state(path)
        if current is None:
            claimed: dict[str, Any] = {
                "schemaVersion": SCHEMA_VERSION,
                "unit": unit,
                "timer": f"{unit}.timer",
                "service": service,
                "state": CLAIMED,
                "rollbackCommand": command,
                "armedAt": _now(),
                "updatedAt": _now(),
                "detail": "timer fired without prior armed record",
                "pid": os.getpid(),
            }
            _write_state(path, claimed)
        else:
            state = str(current.get("state", "unknown"))
            if state == CANCELLED:
                return {"ok": True, "unit": unit, "state": CANCELLED, "ranRollback": False}
            if state in (COMPLETED, FAILED, COLLECTED):
                return {"ok": True, "unit": unit, "state": state, "ranRollback": False}
            if state != ARMED:
                raise _terminal_error(state, unit)
            current.update({"state": CLAIMED, "updatedAt": _now(), "pid": os.getpid()})
            _write_state(path, current)
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
        exit_code = completed.returncode
        tail = ((completed.stderr or "") + ("\n" if completed.stderr else "") + (completed.stdout or "")).strip()[
            :4000
        ]
    except (OSError, subprocess.TimeoutExpired) as exc:
        exit_code = 127
        tail = str(exc)[:4000]
    with _locked(unit, state_root):
        path = _state_path(unit, state_root)
        current = _read_state(path) or {}
        terminal = COMPLETED if exit_code == 0 else FAILED
        current.update(
            {
                "schemaVersion": SCHEMA_VERSION,
                "unit": unit,
                "timer": f"{unit}.timer",
                "service": service,
                "state": terminal,
                "rollbackCommand": command,
                "updatedAt": _now(),
                "exitCode": exit_code,
                "outputTail": tail,
            }
        )
        _write_state(path, current)
        return {"ok": exit_code == 0, "unit": unit, "state": terminal, "exitCode": exit_code, "ranRollback": True}


def collect(
    *,
    unit: str = DEFAULT_UNIT,
    systemctl: str = "systemctl",
    state_dir: str | os.PathLike[str] = DEFAULT_STATE_DIR,
) -> dict[str, Any]:
    """Mark a terminal guard collected while retaining its prior outcome."""
    unit = _validate_unit(unit)
    state_root = _validate_state_dir(state_dir)
    with _locked(unit, state_root):
        path = _state_path(unit, state_root)
        current = _read_state(path)
        if current is None:
            raise GuardedApplyError(f"no durable guard state for {unit}")
        state = str(current.get("state", "unknown"))
        if state in (ARMED, CLAIMED):
            raise GuardedApplyError(f"cannot collect active guard (state={state}): {unit}")
        if state == COLLECTED:
            raise GuardedApplyError(f"guard already collected: {unit}")
        _run([systemctl, "stop", f"{unit}.timer"], check=False)
        current.update(
            {
                "priorState": state,
                "priorExitCode": current.get("exitCode"),
                "state": COLLECTED,
                "updatedAt": _now(),
                "collectedAt": _now(),
            }
        )
        _write_state(path, current)
        return {"ok": True, "unit": unit, "state": COLLECTED, "priorState": state}


def status(
    *,
    unit: str = DEFAULT_UNIT,
    systemctl: str = "systemctl",
    state_dir: str | os.PathLike[str] = DEFAULT_STATE_DIR,
) -> dict[str, Any]:
    """Report durable guard state with live systemd detail, without mutation."""
    unit = _validate_unit(unit)
    state_root = _validate_state_dir(state_dir)
    with _locked(unit, state_root):
        current = _read_state(_state_path(unit, state_root))
    live = _describe_service(f"{unit}.service", systemctl)
    if current is None:
        return {"ok": True, "unit": unit, "state": None, "live": live, "stateDir": str(state_root)}
    merged = dict(current)
    merged.update({"ok": True, "live": live, "stateDir": str(state_root)})
    return merged


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Arm or cancel a durable systemd rollback guard")
    parser.add_argument("--unit", default=DEFAULT_UNIT)
    parser.add_argument("--systemctl", default="systemctl")
    parser.add_argument("--state-dir", default=DEFAULT_STATE_DIR)
    subparsers = parser.add_subparsers(dest="command", required=True)
    arm_parser = subparsers.add_parser("arm")
    arm_parser.add_argument("--timeout", type=int, default=60)
    arm_parser.add_argument("--systemd-run", default="systemd-run")
    arm_parser.add_argument("rollback_command", nargs=argparse.REMAINDER)
    subparsers.add_parser("cancel")
    fired_parser = subparsers.add_parser("fired")
    fired_parser.add_argument("rollback_command", nargs=argparse.REMAINDER)
    subparsers.add_parser("collect")
    subparsers.add_parser("status")
    args = parser.parse_args(argv)

    try:
        if args.command == "arm":
            rollback = list(args.rollback_command)
            if rollback and rollback[0] == "--":
                rollback = rollback[1:]
            result = arm(
                rollback,
                timeout_seconds=args.timeout,
                unit=args.unit,
                systemd_run=args.systemd_run,
                systemctl=args.systemctl,
                state_dir=args.state_dir,
            )
        elif args.command == "cancel":
            result = cancel(unit=args.unit, systemctl=args.systemctl, state_dir=args.state_dir)
        elif args.command == "fired":
            rollback = list(args.rollback_command)
            if rollback and rollback[0] == "--":
                rollback = rollback[1:]
            result = fired(rollback, unit=args.unit, systemctl=args.systemctl, state_dir=args.state_dir)
            if result.get("state") in (FAILED, CLAIMED):
                print(json.dumps(result, indent=2, sort_keys=True))
                return 1
        elif args.command == "collect":
            result = collect(unit=args.unit, systemctl=args.systemctl, state_dir=args.state_dir)
        else:
            result = status(unit=args.unit, systemctl=args.systemctl, state_dir=args.state_dir)
    except GuardedApplyError as exc:
        print(f"nas-guarded-apply: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


__all__ = [
    "DEFAULT_UNIT",
    "DEFAULT_STATE_DIR",
    "GuardedApplyError",
    "arm",
    "cancel",
    "fired",
    "collect",
    "status",
]


if __name__ == "__main__":
    raise SystemExit(main())
