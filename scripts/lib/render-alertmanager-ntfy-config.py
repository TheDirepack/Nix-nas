#!/usr/bin/env python3
"""Render the alertmanager-ntfy credential file from activated ntfy secrets."""

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
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"{label} must be a regular non-symlink file")
    value = path.read_text(encoding="utf-8")
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
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o400)
        os.replace(temporary, OUTPUT_PATH)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
