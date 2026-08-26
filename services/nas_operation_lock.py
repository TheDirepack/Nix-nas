"""Small flock-based conflict coordinator for privileged NAS operations.

The conflict policy is the only project-specific part: callers name one or more
classes and this module acquires the corresponding lock files in sorted order.
There is no reservation database, coordinator database, PID ancestry walk, or
/proc fd inspection.  Asynchronous work is launched by systemd and acquires the
same locks when its worker starts.

Nested commands inherit a random coordination token.  While the outer process
holds a class lock it writes that token into the locked file; a child validates
that the requested lock is still held with the same token before proceeding.
The kernel flock remains the actual lifetime/cleanup mechanism, including on
crash or SIGKILL.
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
RESERVATION_TOKEN_RE = re.compile(r"[0-9a-f]{32}")
COORDINATION_TOKEN_ENV = "NAS_OPERATION_COORDINATION_TOKEN"
DEFAULT_RESERVATION_TTL_SECONDS = 300
_CURRENT_COORDINATION_TOKEN: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "nas_operation_coordination_token", default=None
)


class OperationBusyError(RuntimeError):
    """Another operation currently owns at least one requested conflict class."""


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
    """Compatibility result for old asynchronous callers.

    Reservations are intentionally admission hints now: the systemd worker is
    the authority and acquires real flocks before mutation.  Keeping this small
    value avoids a flag-day change in callers while deleting reservation state.
    """

    action: str
    classes: tuple[str, ...]
    token: str
    created_at: int
    expires_at: int
    created_monotonic_ns: int
    expires_monotonic_ns: int

    def as_json(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "classes": list(self.classes),
            "token": self.token,
            "createdAt": self.created_at,
            "expiresAt": self.expires_at,
            "createdMonotonicNs": self.created_monotonic_ns,
            "expiresMonotonicNs": self.expires_monotonic_ns,
        }


def _validate_class(name: str) -> str:
    if name not in KNOWN_CLASSES:
        raise ValueError(f"Unknown appliance operation class: {name}")
    return name


def _normalize_classes(classes: Sequence[str]) -> tuple[str, ...]:
    normalized = tuple(sorted({_validate_class(str(name)) for name in classes}))
    if not normalized:
        raise ValueError("At least one operation class is required")
    # appliance is the wildcard class used for whole-appliance mutations.
    return tuple(sorted(KNOWN_CLASSES)) if "appliance" in normalized else normalized


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


def _open_lock(name: str) -> Any:
    ensure_root()
    path = OPERATION_ROOT / f"{_validate_class(name)}.lock"
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


def _lock_handle(handle: Any, *, blocking: bool) -> None:
    flags = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
    fcntl.flock(handle, flags)


def _release(handles: Sequence[Any], *, clear: bool = False) -> None:
    for handle in reversed(handles):
        try:
            if clear:
                try:
                    handle.seek(0)
                    handle.truncate()
                    handle.flush()
                except OSError:
                    pass
            fcntl.flock(handle, fcntl.LOCK_UN)
        finally:
            handle.close()


def _metadata(token: str, action: str, classes: tuple[str, ...]) -> str:
    return (
        json.dumps(
            {"token": token, "action": action, "classes": list(classes), "pid": os.getpid()},
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )


def _read_metadata(handle: Any) -> dict[str, Any] | None:
    try:
        handle.seek(0)
        raw = handle.read(4096)
        value = json.loads(raw) if raw.strip() else None
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _acquire_handles(classes: tuple[str, ...], *, blocking: bool, action: str) -> list[Any]:
    handles: list[Any] = []
    try:
        for name in classes:
            handle = _open_lock(name)
            try:
                _lock_handle(handle, blocking=blocking)
            except BlockingIOError as exc:
                handle.close()
                raise OperationBusyError(f"Another privileged operation conflicts with {action}: {name}") from exc
            handles.append(handle)
        return handles
    except Exception:
        _release(handles)
        raise


def _boot_id() -> str:
    try:
        return pathlib.Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip() or "unavailable"
    except OSError:
        return "unavailable"


def validate_coordination_token(token: str, classes: Sequence[str]) -> None:
    """Verify that every requested kernel flock is live with ``token`` metadata."""
    if RESERVATION_TOKEN_RE.fullmatch(token) is None:
        raise OperationBusyError("The parent operation coordination token is malformed")
    normalized = _normalize_classes(classes)
    for name in normalized:
        handle = _open_lock(name)
        try:
            value = _read_metadata(handle)
            try:
                _lock_handle(handle, blocking=False)
            except BlockingIOError:
                pass
            else:
                fcntl.flock(handle, fcntl.LOCK_UN)
                raise OperationBusyError(f"The parent operation no longer owns the required class: {name}")
            if value is None or value.get("token") != token:
                raise OperationBusyError(f"The requested class is owned by a different operation: {name}")
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
    ttl_seconds: int = DEFAULT_RESERVATION_TTL_SECONDS,
) -> OperationReservation:
    """Perform a non-binding admission check for an asynchronous systemd job.

    The previous implementation persisted a reservation database and later
    transferred it to a worker.  systemd already owns the job lifecycle, so the
    real serialization now happens when that worker acquires its class flocks.
    """
    normalized = _normalize_classes(classes)
    if ttl_seconds < 30 or ttl_seconds > 3600:
        raise ValueError("Operation reservation TTL must be between 30 and 3600 seconds")
    handles = _acquire_handles(normalized, blocking=False, action=action)
    _release(handles)
    now = int(time.time())
    monotonic = time.monotonic_ns()
    return OperationReservation(
        action=action,
        classes=normalized,
        token=secrets.token_hex(16),
        created_at=now,
        expires_at=now + ttl_seconds,
        created_monotonic_ns=monotonic,
        expires_monotonic_ns=monotonic + ttl_seconds * 1_000_000_000,
    )


def cancel_reservation(token: str) -> None:
    """Compatibility no-op: asynchronous reservation state no longer exists."""
    if RESERVATION_TOKEN_RE.fullmatch(token) is None:
        raise ValueError("Invalid operation reservation token")


@contextlib.contextmanager
def acquire_operation(
    action: str,
    classes: Sequence[str],
    *,
    blocking: bool = False,
    publish: bool = True,
    reservation_token: str | None = None,
) -> Iterator[ActiveOperation]:
    """Hold requested conflict classes for the complete mutation."""
    del publish
    normalized = _normalize_classes(classes)
    if reservation_token is not None and RESERVATION_TOKEN_RE.fullmatch(reservation_token) is None:
        raise OperationBusyError("The asynchronous operation admission token is malformed")

    inherited = os.environ.get(COORDINATION_TOKEN_ENV)
    if inherited:
        validate_coordination_token(inherited, normalized)
        now = int(time.time())
        yield ActiveOperation(action, normalized, os.getpid(), now, _boot_id(), str(now), inherited)
        return

    handles = _acquire_handles(normalized, blocking=blocking, action=action)
    token = secrets.token_hex(16)
    started = int(time.time())
    active = ActiveOperation(action, normalized, os.getpid(), started, _boot_id(), str(started), token)
    payload = _metadata(token, action, normalized)
    coordination_context = _CURRENT_COORDINATION_TOKEN.set(token)
    previous_env = os.environ.get(COORDINATION_TOKEN_ENV)
    try:
        for handle in handles:
            handle.seek(0)
            handle.truncate()
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.environ[COORDINATION_TOKEN_ENV] = token
        yield active
    finally:
        if previous_env is None:
            os.environ.pop(COORDINATION_TOKEN_ENV, None)
        else:
            os.environ[COORDINATION_TOKEN_ENV] = previous_env
        _CURRENT_COORDINATION_TOKEN.reset(coordination_context)
        _release(handles, clear=True)


def operation_state() -> dict[str, Any]:
    """Return an advisory snapshot derived directly from kernel class locks."""
    ensure_root()
    busy: list[str] = []
    by_token: dict[str, dict[str, Any]] = {}
    for name in sorted(KNOWN_CLASSES):
        handle = _open_lock(name)
        try:
            value = _read_metadata(handle)
            try:
                _lock_handle(handle, blocking=False)
            except BlockingIOError:
                busy.append(name)
                if value is not None and isinstance(value.get("token"), str):
                    token = value["token"]
                    item = by_token.setdefault(
                        token,
                        {
                            "action": value.get("action", "operation"),
                            "classes": [],
                            "pid": value.get("pid"),
                        },
                    )
                    item["classes"].append(name)
            else:
                fcntl.flock(handle, fcntl.LOCK_UN)
        finally:
            handle.close()
    return {
        "busyClasses": busy,
        "active": list(by_token.values()),
        "reservations": [],
        "snapshotSemantics": "advisory-kernel-flock",
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="nas-operation-run",
        description="Run a command while holding NAS appliance mutation locks.",
    )
    parser.add_argument("--action", help="Human-readable operation name for diagnostics")
    parser.add_argument(
        "--class",
        dest="classes",
        action="append",
        required=True,
        choices=sorted(KNOWN_CLASSES),
        help="Conflict class to hold; repeat as needed. appliance is globally exclusive.",
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
