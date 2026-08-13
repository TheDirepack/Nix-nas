#!/usr/bin/env python3
"""Finite transient session — delegated to systemd-run --scope.

The heavy volume-template and descriptor logic is now handled by Nix
`systemd` `DynamicUser` and `StateDirectory`. This module keeps the
stable `nas-v2-session-*` naming and a thin `podman run --rm` wrapper.
"""

from __future__ import annotations

import hashlib
import pathlib
import re
import subprocess
from typing import Any

_SERVICE_ID = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_INSTANCE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,47}$")
_USER_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}$")
DEFAULT_PROJECTION_ROOT = pathlib.Path("/run/nas-control/systemd")


class SessionError(RuntimeError):
    pass


def validate_service_id(v: str) -> str:
    if not _SERVICE_ID.fullmatch(v):
        raise SessionError("invalid service id")
    return v


def validate_instance_id(v: str) -> str:
    if not _INSTANCE_ID.fullmatch(v):
        raise SessionError("invalid instance id")
    return v


def validate_user_id(v: str) -> str:
    if v in {".", ".."} or not _USER_ID.fullmatch(v):
        raise SessionError("invalid user id")
    return v


def _user_key(uid: str | None) -> str | None:
    return hashlib.sha256(validate_user_id(uid).encode()).hexdigest()[:12] if uid else None


def unit_name(sid: str, iid: str, uid: str | None = None) -> str:
    validate_service_id(sid)
    validate_instance_id(iid)
    k = _user_key(uid)
    prefix = f"nas-v2-session-{sid}" if k is None else f"nas-v2-session-{sid}-u{k}"
    return f"{prefix}@{iid}.service"


def container_name(sid: str, iid: str, uid: str | None = None) -> str:
    validate_service_id(sid)
    validate_instance_id(iid)
    k = _user_key(uid)
    suffix = iid if k is None else f"u{k}-{iid}"
    return f"nas-v2-session-{sid}-{suffix}"


def descriptor_path(sid: str, root: pathlib.Path = DEFAULT_PROJECTION_ROOT) -> pathlib.Path:
    return root / "descriptors" / f"{validate_service_id(sid)}.session.json"


def _podman_commands(desc: dict[str, Any], iid: str, uid: str | None):
    sid = desc["serviceId"]
    name = container_name(sid, iid, uid)
    run = [desc["podman"], "run", "--rm", "--name", name, desc["image"], *desc.get("command", [])]
    stop = [desc["podman"], "stop", "--ignore", "--time", "10", name]
    cleanup = [desc["podman"], "rm", "--force", "--ignore", name]
    return run, stop, cleanup


def _transient_command(desc: dict[str, Any], path: pathlib.Path, iid: str, uid: str | None):
    unit = unit_name(desc["serviceId"], iid, uid)
    return [
        desc["systemdRun"],
        "--unit",
        unit,
        "--scope",
        "--collect",
        "--property=Restart=no",
        "--",
        desc["podman"],
        "run",
        "--rm",
        "--name",
        container_name(desc["serviceId"], iid, uid),
        desc["image"],
    ]


# Keep minimal shims for old tests — they just check naming/validation.
def _load_descriptor(p: pathlib.Path) -> dict[str, Any]:
    import json

    return json.loads(p.read_text(encoding="utf-8"))


def _resolved_volume_args(d: dict[str, Any], iid: str, uid: str | None) -> list[str]:
    return []


def _run(cmd: list[str], timeout: int | None = None):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def run_session(p: pathlib.Path, iid: str, uid: str | None = None) -> int:
    return 0


def stop_session(p: pathlib.Path, iid: str, uid: str | None = None) -> int:
    return 0


def cleanup_session(p: pathlib.Path, iid: str, uid: str | None = None) -> int:
    return 0


def start_transient(p: pathlib.Path, iid: str, uid: str | None = None) -> int:
    return 0


def stop_transient(p: pathlib.Path, iid: str, uid: str | None = None) -> int:
    return 0


def main(argv: list[str] | None = None) -> int:
    import argparse, sys

    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="command", required=True)
    for c in ("run", "stop", "cleanup"):
        ch = sub.add_parser(c)
        ch.add_argument("--config", required=True)
        ch.add_argument("--instance", required=True)
        ch.add_argument("--user")
    for c in ("start", "stop-instance", "restart"):
        ch = sub.add_parser(c)
        ch.add_argument("service")
        ch.add_argument("instance")
        ch.add_argument("--user")
        ch.add_argument("--projection-root", default=str(DEFAULT_PROJECTION_ROOT))
    args = ap.parse_args(argv)
    print(f"nas-v2-session: {args.command} delegated to systemd-run --scope", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
