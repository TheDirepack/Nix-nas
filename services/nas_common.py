"""Shared identity-policy and subprocess helpers for NAS service scripts.

Application authorization is Managed Services V2-native: Authentik groups are
named ``application.<service>.<capability>``. The only non-application groups
owned here are the base identity roles used by the appliance itself.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import signal
import subprocess
import sys
import threading
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

ADMIN_GROUP = os.environ.get("NAS_IDENTITY_ADMIN_GROUP", "nas_admin")
USER_GROUP = os.environ.get("NAS_IDENTITY_USER_GROUP", "nas_users")
GUEST_GROUP = os.environ.get("NAS_IDENTITY_GUEST_GROUP", "nas_guests")
DISABLED_GROUP = os.environ.get("NAS_IDENTITY_DISABLED_GROUP", "nas_disabled")

MAX_GROUP_HEADER_BYTES = max(256, int(os.environ.get("NAS_MAX_GROUP_HEADER_BYTES", "8192")))
MAX_GROUPS = max(8, int(os.environ.get("NAS_MAX_GROUPS", "256")))
MAX_GROUP_NAME_LENGTH = max(16, int(os.environ.get("NAS_MAX_GROUP_NAME_LENGTH", "256")))
_APPLICATION_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_CAPABILITY_ID_RE = re.compile(r"^[a-z][a-z0-9.-]{0,127}$")


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


def run_command(
    cmd: Sequence[str],
    *,
    timeout_seconds: float = 120.0,
    input_text: str | None = None,
    env: Mapping[str, str] | None = None,
    max_output_bytes: int = 1024 * 1024,
    capture: bool = True,
) -> CommandResult:
    """Run a command with bounded streaming output and process-group timeout cleanup.

    Both output streams are drained continuously so an untrusted/noisy child cannot
    make the parent buffer arbitrary output in memory. A timed-out command runs in
    its own session and the entire process group is terminated, preventing wrapper
    descendants from surviving a privileged orchestration timeout.

    When stdin is supplied, successful output remains available to callers that
    intentionally read a value from a child process, but failure output is replaced
    with a fixed diagnostic. Secret-bearing children must never be able to reflect
    protected stdin into an exception, journal entry, syslog message, or UI error.
    """
    command = [str(item) for item in cmd]
    merged_env = None
    if env is not None:
        merged_env = os.environ.copy()
        merged_env.update({str(key): str(value) for key, value in env.items()})
    limit = max(0, int(max_output_bytes))
    stdout_buffer = bytearray()
    stderr_buffer = bytearray()
    stdout_truncated = False
    stderr_truncated = False

    proc = subprocess.Popen(
        command,
        stdin=subprocess.PIPE if input_text is not None else None,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        env=merged_env,
        start_new_session=True,
    )

    def drain(stream: Any, destination: bytearray, stream_name: str) -> None:
        nonlocal stdout_truncated, stderr_truncated
        if stream is None:
            return
        try:
            while True:
                block = stream.read(64 * 1024)
                if not block:
                    break
                remaining = max(0, limit - len(destination))
                if remaining:
                    destination.extend(block[:remaining])
                if len(block) > remaining:
                    if stream_name == "stdout":
                        stdout_truncated = True
                    else:
                        stderr_truncated = True
        finally:
            stream.close()

    readers: list[threading.Thread] = []
    if capture:
        readers = [
            threading.Thread(target=drain, args=(proc.stdout, stdout_buffer, "stdout"), daemon=True),
            threading.Thread(target=drain, args=(proc.stderr, stderr_buffer, "stderr"), daemon=True),
        ]
        for thread in readers:
            thread.start()

    writer: threading.Thread | None = None
    if input_text is not None and proc.stdin is not None:
        payload = input_text.encode("utf-8")
        stdin = proc.stdin

        def write_input() -> None:
            try:
                stdin.write(payload)
                stdin.flush()
            except BrokenPipeError:
                pass
            finally:
                stdin.close()

        writer = threading.Thread(target=write_input, daemon=True)
        writer.start()

    timed_out = False
    try:
        proc.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
    finally:
        if writer is not None:
            writer.join(timeout=1.0)
        for thread in readers:
            thread.join(timeout=2.0)

    def decoded(value: bytearray, truncated: bool) -> str:
        text = bytes(value).decode("utf-8", errors="replace")
        return text + ("\n[output truncated]" if truncated else "")

    if timed_out:
        if input_text is not None:
            return CommandResult(124, "", "Command timed out after receiving protected standard input")
        return CommandResult(124, decoded(stdout_buffer, stdout_truncated), "Command timed out")
    if proc.returncode != 0 and input_text is not None:
        return CommandResult(proc.returncode, "", "Command failed after receiving protected standard input")
    return CommandResult(
        proc.returncode,
        decoded(stdout_buffer, stdout_truncated),
        decoded(stderr_buffer, stderr_truncated),
    )


def parse_systemd_show(output: str) -> dict[str, dict[str, str]]:
    """Parse block-separated ``systemctl show`` output by the unit Id field."""
    records: dict[str, dict[str, str]] = {}
    stripped = output.strip()
    if not stripped:
        return records
    for block in re.split(r"(?:\r?\n)[ \t]*(?:\r?\n)+", stripped):
        values: dict[str, str] = {}
        for line in block.splitlines():
            key, separator, value = line.partition("=")
            if separator:
                values[key] = value
        unit = values.get("Id")
        if unit:
            records[unit] = values
    return records


def split_groups(raw: str) -> set[str]:
    """Parse a proxy group header with explicit resource bounds."""
    byte_count = len(raw.encode("utf-8", errors="ignore"))
    if any(ord(character) < 32 or ord(character) == 127 for character in raw):
        print("nas-identity-policy: rejected group header containing control characters", file=sys.stderr)
        return set()
    if byte_count > MAX_GROUP_HEADER_BYTES:
        print(
            f"nas-identity-policy: rejected oversized group header ({byte_count} bytes; limit {MAX_GROUP_HEADER_BYTES})",
            file=sys.stderr,
        )
        return set()
    parts = [part.strip() for part in raw.replace(";", ",").replace("|", ",").split(",")]
    names = [name for name in parts if name]
    if len(names) > MAX_GROUPS:
        print(
            f"nas-identity-policy: rejected group header containing {len(names)} groups; limit {MAX_GROUPS}",
            file=sys.stderr,
        )
        return set()
    output: set[str] = set()
    for name in names:
        if len(name) > MAX_GROUP_NAME_LENGTH:
            print(
                f"nas-identity-policy: rejected group header containing a name longer than {MAX_GROUP_NAME_LENGTH} characters",
                file=sys.stderr,
            )
            return set()
        if any(ord(character) < 32 or ord(character) == 127 for character in name):
            print("nas-identity-policy: rejected group header containing control characters", file=sys.stderr)
            return set()
        output.add(name)
    return output


def account_enabled(groups: set[str]) -> bool:
    return DISABLED_GROUP not in groups


def account_is_admin(groups: set[str]) -> bool:
    return account_enabled(groups) and ADMIN_GROUP in groups


def account_has_portal_access(groups: set[str]) -> bool:
    """Authenticated enabled accounts may reach the neutral landing/settings page."""
    return account_enabled(groups)


def application_capability_group(service_id: str, capability: str = "access") -> str:
    if not _APPLICATION_ID_RE.fullmatch(service_id):
        raise ValueError(f"Invalid V2 service id {service_id!r}")
    if not _CAPABILITY_ID_RE.fullmatch(capability):
        raise ValueError(f"Invalid V2 capability id {capability!r}")
    return f"application.{service_id}.{capability}"


def application_capability_allowed(
    groups: set[str],
    service_id: str,
    capability: str = "access",
    *,
    administrator_bypass: bool = True,
) -> bool:
    if not account_enabled(groups):
        return False
    if administrator_bypass and ADMIN_GROUP in groups:
        return True
    return application_capability_group(service_id, capability) in groups


def account_has_personal_share(groups: set[str]) -> bool:
    return GUEST_GROUP not in groups and application_capability_allowed(groups, "copyparty", "files")


def read_json_object(
    path: pathlib.Path,
    *,
    missing: Mapping[str, Any] | None = None,
    warn: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Read a JSON object, optionally returning a fail-closed fallback."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("top-level value is not an object")
        return value
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        if warn is not None:
            warn(f"Unable to read {path}: {exc}")
        if missing is None:
            raise
        return dict(missing)
