#!/usr/bin/env python3
"""Render alertmanager-ntfy credentials from activated ntfy secret files."""

from __future__ import annotations

import json
import os
import pathlib
import re
import stat
import tempfile

TOPIC_PATH = pathlib.Path("/run/nas-secrets/observability/ntfy-topic")
PASSWORD_PATH = pathlib.Path("/run/nas-secrets/observability/ntfy-admin-password")
OUTPUT_PATH = pathlib.Path("/run/nas-alertmanager-ntfy/config.yml")
TOPIC_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
PASSWORD_RE = re.compile(r"^[A-Za-z0-9._~+/=:@-]{20,4096}$")


def read_private(path: pathlib.Path, pattern: re.Pattern[str], label: str) -> str:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError(f"unable to open {label} without following symlinks") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError(f"{label} must be a regular file")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise RuntimeError(f"{label} must not be accessible by group or other users")
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            descriptor = -1
            value = handle.read(4097)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not pattern.fullmatch(value):
        raise RuntimeError(f"{label} has an invalid format")
    return value


def main() -> int:
    topic = read_private(TOPIC_PATH, TOPIC_RE, "ntfy topic")
    password = read_private(PASSWORD_PATH, PASSWORD_RE, "ntfy password")
    payload = {
        "ntfy": {
            "auth": {"basic": {"username": "admin", "password": password}},
            "notification": {"topic": topic},
        }
    }

    OUTPUT_PATH.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(OUTPUT_PATH.parent, 0o700)
    fd, temporary = tempfile.mkstemp(prefix=".config.", dir=OUTPUT_PATH.parent)
    replaced = False
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o400)
        os.replace(temporary, OUTPUT_PATH)
        replaced = True
        directory_fd = os.open(OUTPUT_PATH.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if not replaced:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
