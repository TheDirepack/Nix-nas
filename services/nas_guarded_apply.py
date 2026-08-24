#!/usr/bin/env python3
"""Tiny systemd-backed rollback guard for destructive appliance mutations.

The guard knows nothing about firewalls, networking, Caddy, or V2 policy.  It
only arms a transient systemd timer before mutation and cancels it after the
caller has verified and committed the new state.  If the caller crashes or is
killed, systemd executes the supplied rollback command.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from typing import Any, Sequence

DEFAULT_UNIT = "nas-v2-apply-rollback"


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


def arm(
    rollback_command: Sequence[str],
    *,
    timeout_seconds: int = 60,
    unit: str = DEFAULT_UNIT,
    systemd_run: str = "systemd-run",
    systemctl: str = "systemctl",
) -> dict[str, Any]:
    """Arm a transient rollback timer before a dangerous mutation."""
    unit = _validate_unit(unit)
    if not isinstance(timeout_seconds, int) or isinstance(timeout_seconds, bool) or timeout_seconds <= 0:
        raise GuardedApplyError("guard timeout must be a positive integer")
    command = [str(item) for item in rollback_command]
    if not command or not command[0]:
        raise GuardedApplyError("rollback command must not be empty")

    timer = f"{unit}.timer"
    service = f"{unit}.service"
    # Remove a completed/failed prior transient unit before reusing the stable
    # name.  Failing to stop an old timer is harmless; failing to arm the new
    # timer is not.
    _run([systemctl, "stop", timer], check=False)
    _run([systemctl, "reset-failed", timer, service], check=False)
    active = _run([systemctl, "is-active", service], check=False)
    if active.returncode == 0:
        raise GuardedApplyError(f"rollback service is already active: {service}")

    result = _run(
        [
            systemd_run,
            f"--unit={unit}",
            f"--on-active={timeout_seconds}s",
            "--timer-property=AccuracySec=1s",
            "--collect",
            "--quiet",
            "--",
            *command,
        ],
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[:4000]
        raise GuardedApplyError(f"unable to arm rollback timer {timer}: {detail}")
    return {
        "ok": True,
        "armed": True,
        "unit": unit,
        "timer": timer,
        "timeoutSeconds": timeout_seconds,
        "rollbackCommand": command,
    }


def cancel(
    *,
    unit: str = DEFAULT_UNIT,
    systemctl: str = "systemctl",
) -> dict[str, Any]:
    """Cancel an armed rollback after apply, verify, and commit succeeded."""
    unit = _validate_unit(unit)
    timer = f"{unit}.timer"
    service = f"{unit}.service"
    result = _run([systemctl, "stop", timer], check=False)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[:4000]
        raise GuardedApplyError(f"unable to cancel rollback timer {timer}: {detail}")
    active = _run([systemctl, "is-active", service], check=False)
    if active.returncode == 0:
        raise GuardedApplyError(f"rollback service already started before guard cancellation: {service}")
    _run([systemctl, "reset-failed", timer, service], check=False)
    return {"ok": True, "armed": False, "unit": unit, "timer": timer}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Arm or cancel a generic systemd rollback guard")
    parser.add_argument("--unit", default=DEFAULT_UNIT)
    parser.add_argument("--systemctl", default="systemctl")
    subparsers = parser.add_subparsers(dest="command", required=True)
    arm_parser = subparsers.add_parser("arm")
    arm_parser.add_argument("--timeout", type=int, default=60)
    arm_parser.add_argument("--systemd-run", default="systemd-run")
    arm_parser.add_argument("rollback_command", nargs=argparse.REMAINDER)
    subparsers.add_parser("cancel")
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
            )
        else:
            result = cancel(unit=args.unit, systemctl=args.systemctl)
    except GuardedApplyError as exc:
        print(f"nas-guarded-apply: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


__all__ = ["DEFAULT_UNIT", "GuardedApplyError", "arm", "cancel"]


if __name__ == "__main__":
    raise SystemExit(main())
