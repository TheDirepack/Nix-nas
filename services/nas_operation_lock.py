"""Cross-process lock hierarchy for mutable NAS appliance operations.

Synchronous callers hold class locks for the complete mutation. Asynchronous
launchers create a short-lived reservation which the systemd job atomically
claims while acquiring the same class locks. This closes the admission race
between a browser response and the child process actually starting.
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
import tempfile
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
    """Another operation owns or reserved at least one requested conflict class."""


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
    # `appliance` is an exclusive wildcard, not an ordinary peer class.
    # Expanding it here makes reservations, synchronous acquisitions, status,
    # and asynchronous claims all share exactly the same conflict semantics.
    if "appliance" in normalized:
        return tuple(sorted(KNOWN_CLASSES))
    return normalized


def ensure_root() -> None:
    """Ensure the operation directory exists without mutating root-owned policy.

    Production ownership/mode is created by systemd-tmpfiles.  A non-root
    administrator may use the directory through the dedicated nas-operations
    group, but must never be required to chmod a root-owned parent directory.
    """

    try:
        metadata = OPERATION_ROOT.lstat()
    except FileNotFoundError:
        if os.geteuid() != 0:
            if os.environ.get("NAS_STATE_ALLOW_UNPRIVILEGED") == "1":
                # Host hermetic fallback: allow unprivileged test harness to
                # create a temp operation root without requiring root or the
                # nas-operations group. Use current user's gid and 2770.
                try:
                    gid = os.getgid()
                except OSError:
                    gid = 0
                OPERATION_ROOT.mkdir(parents=True, exist_ok=False, mode=0o770)
                try:
                    os.chown(OPERATION_ROOT, os.geteuid(), gid)
                except OSError:
                    pass
                os.chmod(OPERATION_ROOT, 0o2770)
                metadata = OPERATION_ROOT.lstat()
                return
            raise PermissionError(
                f"NAS operation root is missing: {OPERATION_ROOT}; repair systemd-tmpfiles policy as root"
            )
        try:
            operation_gid = grp.getgrnam("nas-operations").gr_gid
        except KeyError as exc:
            raise RuntimeError("Required nas-operations group is unavailable") from exc
        OPERATION_ROOT.mkdir(parents=True, exist_ok=False, mode=0o770)
        # mkdir is affected by umask. A root fallback must reconstruct the same
        # ownership/mode contract as tmpfiles instead of silently creating root:root.
        os.chown(OPERATION_ROOT, 0, operation_gid)
        os.chmod(OPERATION_ROOT, 0o2770)
        metadata = OPERATION_ROOT.lstat()
        if metadata.st_uid != 0 or metadata.st_gid != operation_gid or stat.S_IMODE(metadata.st_mode) != 0o2770:
            raise RuntimeError(f"Unable to reconstruct trusted NAS operation root policy: {OPERATION_ROOT}")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise RuntimeError(f"NAS operation root is not a trusted directory: {OPERATION_ROOT}")
    mode = stat.S_IMODE(metadata.st_mode)
    if mode & 0o007:
        raise RuntimeError(f"NAS operation root grants access to other users: {OPERATION_ROOT}")
    if not os.access(OPERATION_ROOT, os.R_OK | os.W_OK | os.X_OK):
        raise PermissionError(f"NAS operation root is not accessible to this operator: {OPERATION_ROOT}")


def _atomic_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    ensure_root()
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=OPERATION_ROOT)
    replaced = False
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o640)
        os.replace(temporary, path)
        replaced = True
        directory = os.open(OPERATION_ROOT, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if not replaced:
            pathlib.Path(temporary).unlink(missing_ok=True)


def _open_named_lock(path: pathlib.Path) -> Any:
    ensure_root()
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o660)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError(f"NAS operation lock is not a regular file: {path}")
        if stat.S_IMODE(metadata.st_mode) & 0o007:
            raise RuntimeError(f"NAS operation lock grants access to other users: {path}")
        return os.fdopen(descriptor, "a+", encoding="utf-8")
    except Exception:
        os.close(descriptor)
        raise


def _open_lock(name: str) -> Any:
    return _open_named_lock(OPERATION_ROOT / f"{_validate_class(name)}.lock")


def _open_coordinator() -> Any:
    return _open_named_lock(OPERATION_ROOT / ".coordinator.lock")


def _lock_handle(handle: Any, *, blocking: bool) -> None:
    flags = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
    fcntl.flock(handle, flags)


def _reservation_path(token: str) -> pathlib.Path:
    if not RESERVATION_TOKEN_RE.fullmatch(token):
        raise ValueError("Invalid operation reservation token")
    return OPERATION_ROOT / f"reservation-{token}.json"


def _load_reservation(path: pathlib.Path, *, now_monotonic_ns: int) -> OperationReservation | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        path.unlink(missing_ok=True)
        return None
    expected_fields = {
        "action",
        "classes",
        "token",
        "createdAt",
        "expiresAt",
        "createdMonotonicNs",
        "expiresMonotonicNs",
    }
    if not isinstance(value, dict) or set(value) != expected_fields:
        path.unlink(missing_ok=True)
        return None
    action = value.get("action")
    classes = value.get("classes")
    token = value.get("token")
    created_at = value.get("createdAt")
    expires_at = value.get("expiresAt")
    created_monotonic_ns = value.get("createdMonotonicNs")
    expires_monotonic_ns = value.get("expiresMonotonicNs")
    if (
        not isinstance(action, str)
        or not action
        or not isinstance(classes, list)
        or not classes
        or not all(isinstance(item, str) and item in KNOWN_CLASSES for item in classes)
        or not isinstance(token, str)
        or not RESERVATION_TOKEN_RE.fullmatch(token)
        or path != _reservation_path(token)
        or not isinstance(created_at, int)
        or not isinstance(expires_at, int)
        or expires_at <= created_at
        or not isinstance(created_monotonic_ns, int)
        or not isinstance(expires_monotonic_ns, int)
        or expires_monotonic_ns <= created_monotonic_ns
    ):
        path.unlink(missing_ok=True)
        return None
    if expires_monotonic_ns <= now_monotonic_ns:
        path.unlink(missing_ok=True)
        return None
    return OperationReservation(
        action,
        tuple(sorted(set(classes))),
        token,
        created_at,
        expires_at,
        created_monotonic_ns,
        expires_monotonic_ns,
    )


def _reservations(*, now_monotonic_ns: int | None = None) -> list[OperationReservation]:
    current = time.monotonic_ns() if now_monotonic_ns is None else now_monotonic_ns
    values: list[OperationReservation] = []
    for path in sorted(OPERATION_ROOT.glob("reservation-*.json")):
        value = _load_reservation(path, now_monotonic_ns=current)
        if value is not None:
            values.append(value)
    return values


def _conflicting_reservation(
    classes: tuple[str, ...], *, ignore_token: str | None = None
) -> OperationReservation | None:
    requested = set(classes)
    for reservation in _reservations():
        if reservation.token == ignore_token:
            continue
        if requested.intersection(reservation.classes):
            return reservation
    return None


def _acquire_class_handles(classes: tuple[str, ...], *, blocking: bool, action: str) -> list[Any]:
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
        for handle in reversed(handles):
            try:
                fcntl.flock(handle, fcntl.LOCK_UN)
            finally:
                handle.close()
        raise


def _release_handles(handles: Sequence[Any]) -> None:
    for handle in reversed(handles):
        try:
            fcntl.flock(handle, fcntl.LOCK_UN)
        finally:
            handle.close()


def _coordination_path(token: str) -> pathlib.Path:
    if not RESERVATION_TOKEN_RE.fullmatch(token):
        raise ValueError("Invalid operation coordination token")
    return OPERATION_ROOT / f"coordination-{token}.json"


def _parent_pid(pid: int) -> int | None:
    try:
        for line in pathlib.Path(f"/proc/{pid}/status").read_text(encoding="ascii").splitlines():
            if line.startswith("PPid:"):
                return int(line.split(":", 1)[1].strip())
    except (OSError, ValueError):
        return None
    return None


def _is_ancestor_pid(expected: int, current: int | None = None) -> bool:
    """Return whether expected is the current process or one of its live ancestors."""

    pid = os.getpid() if current is None else current
    seen: set[int] = set()
    while pid > 0 and pid not in seen:
        if pid == expected:
            return True
        seen.add(pid)
        parent = _parent_pid(pid)
        if parent is None or parent == pid:
            break
        pid = parent
    return False


def _write_coordination_claim(active: ActiveOperation) -> pathlib.Path:
    ensure_root()
    path = _coordination_path(active.coordination_token)
    value = {
        "action": active.action,
        "classes": list(active.classes),
        "pid": active.pid,
        "bootId": active.boot_id,
        "processStart": active.process_start,
    }
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return path


def _read_coordination_claim(token: str) -> dict[str, Any]:
    path = _coordination_path(token)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise OperationBusyError("The parent operation coordination proof is missing") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o007:
            raise OperationBusyError("The parent operation coordination proof is not trusted")
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            descriptor = -1
            value = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise OperationBusyError("The parent operation coordination proof is invalid") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    expected_fields = {"action", "classes", "pid", "bootId", "processStart"}
    if not isinstance(value, dict) or set(value) != expected_fields:
        raise OperationBusyError("The parent operation coordination proof has invalid fields")
    return value


def _lock_owner_pid(name: str) -> int | None:
    """Return the Linux PID that owns the class flock, or None when unlocked.

    Coordination tokens are only meaningful when the process named by the
    claim is the process that actually owns each physical flock. Merely seeing
    a busy lock would allow an unrelated operator to forge a claim while some
    other operation happened to be running.
    """

    path = OPERATION_ROOT / f"{_validate_class(name)}.lock"
    try:
        metadata = path.stat()
        lock_lines = pathlib.Path("/proc/locks").read_text(encoding="ascii").splitlines()
    except OSError:
        return None
    identity = f"{os.major(metadata.st_dev):x}:{os.minor(metadata.st_dev):02x}:{metadata.st_ino}"
    for line in lock_lines:
        fields = line.split()
        if len(fields) >= 6 and fields[1] == "FLOCK" and fields[3] == "WRITE" and fields[5].lower() == identity.lower():
            try:
                owner = int(fields[4])
            except ValueError:
                return None
            return owner if owner > 0 else None
    return None


def validate_coordination_token(token: str, classes: Sequence[str]) -> None:
    """Verify that a live ancestor currently owns every requested operation class."""

    normalized = _normalize_classes(classes)
    try:
        value = _read_coordination_claim(token)
    except ValueError as exc:
        raise OperationBusyError("The parent operation coordination token is malformed") from exc
    pid = value.get("pid")
    claimed_classes = value.get("classes")
    if (
        not isinstance(pid, int)
        or not isinstance(claimed_classes, list)
        or not all(isinstance(item, str) and item in KNOWN_CLASSES for item in claimed_classes)
        or not set(normalized).issubset(set(claimed_classes))
        or value.get("bootId") != _boot_id()
        or value.get("processStart") != _process_start(pid)
        or not _is_ancestor_pid(pid)
    ):
        raise OperationBusyError("The parent operation coordination proof is not valid for this process")
    for name in normalized:
        if _lock_owner_pid(name) != pid:
            raise OperationBusyError(f"The parent operation no longer owns the required class: {name}")


def current_coordination_token() -> str:
    token = _CURRENT_COORDINATION_TOKEN.get()
    if token is None:
        raise RuntimeError("No active NAS operation coordination token is available")
    return token


def reserve_operation(
    action: str,
    classes: Sequence[str],
    *,
    ttl_seconds: int = DEFAULT_RESERVATION_TTL_SECONDS,
) -> OperationReservation:
    """Reserve conflict classes for an asynchronous child before it starts."""

    normalized = _normalize_classes(classes)
    if ttl_seconds < 30 or ttl_seconds > 3600:
        raise ValueError("Operation reservation TTL must be between 30 and 3600 seconds")
    coordinator = _open_coordinator()
    handles: list[Any] = []
    try:
        _lock_handle(coordinator, blocking=True)
        conflict = _conflicting_reservation(normalized)
        if conflict is not None:
            shared = sorted(set(normalized).intersection(conflict.classes))[0]
            raise OperationBusyError(f"Another privileged operation conflicts with {action}: {shared}")
        handles = _acquire_class_handles(normalized, blocking=False, action=action)
        now = int(time.time())
        monotonic_now = time.monotonic_ns()
        reservation = OperationReservation(
            action=action,
            classes=normalized,
            token=secrets.token_hex(16),
            created_at=now,
            expires_at=now + ttl_seconds,
            created_monotonic_ns=monotonic_now,
            expires_monotonic_ns=monotonic_now + ttl_seconds * 1_000_000_000,
        )
        path = _reservation_path(reservation.token)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(reservation.as_json(), handle, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            path.unlink(missing_ok=True)
            raise
        directory = os.open(OPERATION_ROOT, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return reservation
    finally:
        _release_handles(handles)
        try:
            fcntl.flock(coordinator, fcntl.LOCK_UN)
        finally:
            coordinator.close()


def cancel_reservation(token: str) -> None:
    coordinator = _open_coordinator()
    try:
        _lock_handle(coordinator, blocking=True)
        _reservation_path(token).unlink(missing_ok=True)
    finally:
        try:
            fcntl.flock(coordinator, fcntl.LOCK_UN)
        finally:
            coordinator.close()


def _boot_id() -> str:
    try:
        value = pathlib.Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    except OSError:
        return "unavailable"
    return value or "unavailable"


def _process_start(pid: int) -> str:
    try:
        raw = pathlib.Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    except OSError:
        return "unavailable"
    closing = raw.rfind(")")
    if closing < 0:
        return "unavailable"
    fields = raw[closing + 2 :].split()
    return fields[19] if len(fields) > 19 else "unavailable"


@contextlib.contextmanager
def acquire_operation(
    action: str,
    classes: Sequence[str],
    *,
    blocking: bool = False,
    publish: bool = True,
    reservation_token: str | None = None,
) -> Iterator[ActiveOperation]:
    """Acquire conflict classes and atomically claim an optional reservation."""

    normalized = _normalize_classes(classes)
    handles: list[Any] = []
    pid = os.getpid()
    active = ActiveOperation(
        action,
        normalized,
        pid,
        int(time.time()),
        _boot_id(),
        _process_start(pid),
        secrets.token_hex(16),
    )
    metadata = OPERATION_ROOT / f"active-{os.getpid()}-{time.time_ns()}.json"
    coordination_path: pathlib.Path | None = None
    coordination_context: contextvars.Token[str | None] | None = None
    coordinator = _open_coordinator()
    try:
        _lock_handle(coordinator, blocking=True)
        conflict = _conflicting_reservation(normalized, ignore_token=reservation_token)
        if conflict is not None:
            shared = sorted(set(normalized).intersection(conflict.classes))[0]
            raise OperationBusyError(f"Another privileged operation conflicts with {action}: {shared}")
        if reservation_token is not None:
            path = _reservation_path(reservation_token)
            reservation = _load_reservation(path, now_monotonic_ns=time.monotonic_ns())
            if reservation is None:
                raise OperationBusyError("The asynchronous operation reservation is missing or expired")
            if reservation.action != action or reservation.classes != normalized:
                raise OperationBusyError("The asynchronous operation reservation does not match this request")
        handles = _acquire_class_handles(normalized, blocking=blocking, action=action)
        if reservation_token is not None:
            _reservation_path(reservation_token).unlink(missing_ok=True)
        coordination_path = _write_coordination_claim(active)
        coordination_context = _CURRENT_COORDINATION_TOKEN.set(active.coordination_token)
        if publish:
            _atomic_json(metadata, active.as_json())
        fcntl.flock(coordinator, fcntl.LOCK_UN)
        coordinator.close()
        coordinator = None
        yield active
    finally:
        if coordinator is not None:
            try:
                fcntl.flock(coordinator, fcntl.LOCK_UN)
            finally:
                coordinator.close()
        metadata.unlink(missing_ok=True)
        if coordination_path is not None:
            coordination_path.unlink(missing_ok=True)
        if coordination_context is not None:
            _CURRENT_COORDINATION_TOKEN.reset(coordination_context)
        _release_handles(handles)


def _lock_is_busy(name: str) -> bool:
    handle = _open_lock(name)
    try:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        fcntl.flock(handle, fcntl.LOCK_UN)
        return False
    finally:
        handle.close()


def operation_state() -> dict[str, Any]:
    """Return a coordinator-consistent snapshot of locks and reservations.

    This is diagnostic state only.  Admission decisions still happen inside
    reserve_operation()/acquire_operation(), never from this snapshot.
    """

    ensure_root()
    coordinator = _open_coordinator()
    try:
        _lock_handle(coordinator, blocking=True)
        reservations = _reservations()
        physical_busy = [name for name in sorted(KNOWN_CLASSES) if _lock_is_busy(name)]
        reserved_busy = {name for reservation in reservations for name in reservation.classes}
        busy = sorted(set(physical_busy).union(reserved_busy))
        active: list[dict[str, Any]] = []
        for path in sorted(OPERATION_ROOT.glob("active-*.json")):
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                path.unlink(missing_ok=True)
                continue
            if not isinstance(value, dict):
                path.unlink(missing_ok=True)
                continue
            classes = value.get("classes")
            pid = value.get("pid")
            boot_id = value.get("bootId")
            process_start = value.get("processStart")
            if (
                not isinstance(classes, list)
                or not all(isinstance(item, str) and item in KNOWN_CLASSES for item in classes)
                or not isinstance(pid, int)
                or not isinstance(boot_id, str)
                or not isinstance(process_start, str)
            ):
                path.unlink(missing_ok=True)
                continue
            if not any(item in physical_busy for item in classes):
                path.unlink(missing_ok=True)
                continue
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                path.unlink(missing_ok=True)
                continue
            except PermissionError:
                pass
            if boot_id != _boot_id() or process_start != _process_start(pid):
                path.unlink(missing_ok=True)
                continue
            active.append(value)
        return {
            "busyClasses": busy,
            "active": active,
            "reservations": [item.as_json() for item in reservations],
            "snapshotSemantics": "diagnostic-coordinator-consistent",
        }
    finally:
        try:
            fcntl.flock(coordinator, fcntl.LOCK_UN)
        finally:
            coordinator.close()


def main(argv: Sequence[str] | None = None) -> int:
    """Run one argv vector while holding or validating NAS mutation locks."""

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
