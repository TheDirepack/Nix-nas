"""Single-flock coordination for privileged NAS mutations.

All privileged mutations serialize on one kernel flock. Operation classes are
kept only as diagnostic metadata and for nested-work validation; they no longer
create separate lock files or permit partially overlapping mutations.
"""

from __future__ import annotations

import argparse
import contextlib
import contextvars
import fcntl
import grp
import json
import os
import pathlib
import re
import secrets
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Any, Iterator, Sequence

OPERATION_ROOT = pathlib.Path(os.environ.get("NAS_OPERATION_ROOT", "/run/nas-operations"))
LOCK_PATH_NAME = "operation.lock"
KNOWN_CLASSES = frozenset(
    {
        "appliance",
        "first-start",
        "identity",
        "network",
        "runtime",
        "secrets",
        "state",
        "storage",
        "update",
    }
)
TOKEN_RE = re.compile(r"[0-9a-f]{32}")
COORDINATION_TOKEN_ENV = "NAS_OPERATION_COORDINATION_TOKEN"
_CURRENT_COORDINATION_TOKEN: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "nas_operation_coordination_token", default=None
)


class OperationBusyError(RuntimeError):
    """Another privileged mutation owns the appliance lock."""


@dataclass(frozen=True)
class ActiveOperation:
    action: str
    classes: tuple[str, ...]
    pid: int
    started_at: int
    boot_id: str
    process_start: str
    coordination_token: str

    def as_json(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "classes": list(self.classes),
            "pid": self.pid,
            "startedAt": self.started_at,
            "bootId": self.boot_id,
            "processStart": self.process_start,
        }


@dataclass(frozen=True)
class OperationReservation:
    action: str
    classes: tuple[str, ...]
    token: str

    def as_json(self) -> dict[str, Any]:
        return {"action": self.action, "classes": list(self.classes), "token": self.token}


def _validate_class(name: str) -> str:
    if name not in KNOWN_CLASSES:
        raise ValueError(f"Unknown appliance operation class: {name}")
    return name


def _normalize_classes(classes: Sequence[str]) -> tuple[str, ...]:
    normalized = tuple(sorted({_validate_class(str(name)) for name in classes}))
    if not normalized:
        raise ValueError("At least one operation class is required")
    return normalized


def ensure_root() -> None:
    """Validate/create the tmpfiles-owned lock directory without broadening it."""
    try:
        metadata = OPERATION_ROOT.lstat()
    except FileNotFoundError:
        if os.geteuid() != 0:
            if os.environ.get("NAS_STATE_ALLOW_UNPRIVILEGED") != "1":
                raise PermissionError(
                    f"NAS operation root is missing: {OPERATION_ROOT}; repair systemd-tmpfiles policy as root"
                )
            OPERATION_ROOT.mkdir(parents=True, mode=0o770)
            os.chmod(OPERATION_ROOT, 0o2770)
            return
        try:
            operation_gid = grp.getgrnam("nas-operations").gr_gid
        except KeyError as exc:
            raise RuntimeError("Required nas-operations group is unavailable") from exc
        OPERATION_ROOT.mkdir(parents=True, mode=0o770)
        os.chown(OPERATION_ROOT, 0, operation_gid)
        os.chmod(OPERATION_ROOT, 0o2770)
        metadata = OPERATION_ROOT.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise RuntimeError(f"NAS operation root is not a trusted directory: {OPERATION_ROOT}")
    if stat.S_IMODE(metadata.st_mode) & 0o007:
        raise RuntimeError(f"NAS operation root grants access to other users: {OPERATION_ROOT}")
    if not os.access(OPERATION_ROOT, os.R_OK | os.W_OK | os.X_OK):
        raise PermissionError(f"NAS operation root is not accessible to this operator: {OPERATION_ROOT}")


def _open_lock() -> Any:
    ensure_root()
    path = OPERATION_ROOT / LOCK_PATH_NAME
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o660)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError(f"NAS operation lock is not a regular file: {path}")
        if stat.S_IMODE(metadata.st_mode) & 0o007:
            raise RuntimeError(f"NAS operation lock grants access to other users: {path}")
        if os.geteuid() == 0 or metadata.st_uid == os.geteuid():
            os.fchmod(descriptor, 0o660)
        return os.fdopen(descriptor, "r+", encoding="utf-8")
    except Exception:
        os.close(descriptor)
        raise


def _try_lock(handle: Any, *, blocking: bool) -> None:
    flags = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
    fcntl.flock(handle, flags)


def _read_metadata(handle: Any) -> dict[str, Any] | None:
    try:
        handle.seek(0)
        raw = handle.read(4096)
        value = json.loads(raw) if raw.strip() else None
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _metadata(token: str, action: str, classes: tuple[str, ...]) -> str:
    return (
        json.dumps(
            {"token": token, "action": action, "classes": list(classes), "pid": os.getpid()},
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )


def _boot_id() -> str:
    try:
        return pathlib.Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip() or "unavailable"
    except OSError:
        return "unavailable"


def _classes_cover(held: Sequence[str], requested: Sequence[str]) -> bool:
    held_set = set(held)
    return "appliance" in held_set or set(requested).issubset(held_set)


def validate_coordination_token(token: str, classes: Sequence[str]) -> None:
    """Verify that the single appliance flock is live and owned by ``token``."""
    if TOKEN_RE.fullmatch(token) is None:
        raise OperationBusyError("The parent operation coordination token is malformed")
    requested = _normalize_classes(classes)
    handle = _open_lock()
    try:
        value = _read_metadata(handle)
        try:
            _try_lock(handle, blocking=False)
        except BlockingIOError:
            pass
        else:
            fcntl.flock(handle, fcntl.LOCK_UN)
            raise OperationBusyError("The parent operation no longer owns the appliance mutation lock")
        held = value.get("classes") if isinstance(value, dict) else None
        if value is None or value.get("token") != token:
            raise OperationBusyError("The appliance mutation lock is owned by a different operation")
        if (
            not isinstance(held, list)
            or not all(isinstance(item, str) for item in held)
            or not _classes_cover(held, requested)
        ):
            raise OperationBusyError("The parent operation does not cover the requested mutation class")
    finally:
        handle.close()


def current_coordination_token() -> str:
    token = _CURRENT_COORDINATION_TOKEN.get() or os.environ.get(COORDINATION_TOKEN_ENV)
    if token is None:
        raise RuntimeError("No active NAS operation coordination token is available")
    return token


def reserve_operation(
    action: str,
    classes: Sequence[str],
    *,
    ttl_seconds: int = 300,
) -> OperationReservation:
    """Check that the global mutation lock is currently available.

    systemd owns asynchronous job lifetime; the worker acquires the real flock
    when it starts. The returned token is only a request identifier for the
    current first-start handoff and carries no reservation state.
    """
    del ttl_seconds
    normalized = _normalize_classes(classes)
    handle = _open_lock()
    try:
        try:
            _try_lock(handle, blocking=False)
        except BlockingIOError as exc:
            raise OperationBusyError(f"Another privileged operation conflicts with {action}") from exc
        else:
            fcntl.flock(handle, fcntl.LOCK_UN)
    finally:
        handle.close()
    return OperationReservation(action=action, classes=normalized, token=secrets.token_hex(16))


def cancel_reservation(token: str) -> None:
    if TOKEN_RE.fullmatch(token) is None:
        raise ValueError("Invalid operation request token")


@contextlib.contextmanager
def acquire_operation(
    action: str,
    classes: Sequence[str],
    *,
    blocking: bool = False,
    publish: bool = True,
    reservation_token: str | None = None,
) -> Iterator[ActiveOperation]:
    """Hold the one appliance mutation lock for the complete operation."""
    del publish, reservation_token
    normalized = _normalize_classes(classes)

    inherited = os.environ.get(COORDINATION_TOKEN_ENV)
    if inherited:
        validate_coordination_token(inherited, normalized)
        now = int(time.time())
        yield ActiveOperation(action, normalized, os.getpid(), now, _boot_id(), str(now), inherited)
        return

    handle = _open_lock()
    try:
        try:
            _try_lock(handle, blocking=blocking)
        except BlockingIOError as exc:
            raise OperationBusyError(f"Another privileged operation conflicts with {action}") from exc
        token = secrets.token_hex(16)
        started = int(time.time())
        active = ActiveOperation(action, normalized, os.getpid(), started, _boot_id(), str(started), token)
        handle.seek(0)
        handle.truncate()
        handle.write(_metadata(token, action, normalized))
        handle.flush()
        os.fsync(handle.fileno())
        coordination_context = _CURRENT_COORDINATION_TOKEN.set(token)
        previous_env = os.environ.get(COORDINATION_TOKEN_ENV)
        os.environ[COORDINATION_TOKEN_ENV] = token
        try:
            yield active
        finally:
            if previous_env is None:
                os.environ.pop(COORDINATION_TOKEN_ENV, None)
            else:
                os.environ[COORDINATION_TOKEN_ENV] = previous_env
            _CURRENT_COORDINATION_TOKEN.reset(coordination_context)
            try:
                handle.seek(0)
                handle.truncate()
                handle.flush()
            except OSError:
                pass
            fcntl.flock(handle, fcntl.LOCK_UN)
    finally:
        handle.close()


def operation_state() -> dict[str, Any]:
    """Return an advisory snapshot from the single kernel flock."""
    handle = _open_lock()
    try:
        value = _read_metadata(handle)
        try:
            _try_lock(handle, blocking=False)
        except BlockingIOError:
            raw_classes = value.get("classes") if isinstance(value, dict) else None
            classes = raw_classes if isinstance(raw_classes, list) else []
            busy = sorted(item for item in classes if isinstance(item, str))
            active = (
                [
                    {
                        "action": value.get("action", "operation"),
                        "classes": busy,
                        "pid": value.get("pid"),
                    }
                ]
                if isinstance(value, dict)
                else []
            )
        else:
            fcntl.flock(handle, fcntl.LOCK_UN)
            busy = []
            active = []
    finally:
        handle.close()
    return {
        "busyClasses": busy,
        "active": active,
        "reservations": [],
        "snapshotSemantics": "advisory-single-kernel-flock",
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="nas-operation-run",
        description="Run a command while holding the NAS appliance mutation lock.",
    )
    parser.add_argument("--action", help="Human-readable operation name for diagnostics")
    parser.add_argument(
        "--class",
        dest="classes",
        action="append",
        required=True,
        choices=sorted(KNOWN_CLASSES),
        help="Diagnostic mutation class; repeat as needed.",
    )
    parser.add_argument(
        "--validate-current",
        action="store_true",
        help="Validate the inherited parent coordination token instead of launching a command.",
    )
    parser.add_argument("command", nargs=argparse.REMAINDER, help="Command argv after --")
    args = parser.parse_args(argv)
    token = os.environ.get(COORDINATION_TOKEN_ENV)

    if args.validate_current:
        if args.command:
            parser.error("--validate-current does not accept a command")
        if not token:
            print("nas-operation-run: no parent operation coordination token is present", file=sys.stderr)
            return 76
        try:
            validate_coordination_token(token, args.classes)
            return 0
        except OperationBusyError as exc:
            print(f"nas-operation-run: {exc}", file=sys.stderr)
            return 76

    if not args.action:
        parser.error("--action is required when launching a command")
    command = list(args.command)
    if command and command[0] == "--":
        command.pop(0)
    if not command:
        parser.error("a command is required after --")

    environment = os.environ.copy()
    if token:
        try:
            validate_coordination_token(token, args.classes)
        except OperationBusyError as exc:
            print(f"nas-operation-run: {exc}", file=sys.stderr)
            return 76
        return subprocess.run(command, env=environment, check=False).returncode

    try:
        with acquire_operation(args.action, args.classes) as active:
            environment[COORDINATION_TOKEN_ENV] = active.coordination_token
            return subprocess.run(command, env=environment, check=False).returncode
    except OperationBusyError as exc:
        print(f"nas-operation-run: {exc}", file=sys.stderr)
        return 75


if __name__ == "__main__":
    raise SystemExit(main())
