"""Shared identity-policy and feature-state helpers for NAS service scripts."""

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

_DEFAULT_CAPABILITY_REGISTRY: dict[str, dict[str, Any]] = {
    name: {
        "id": name,
        "allowGroup": f"nas_allow_{name}",
        "denyGroup": f"nas_deny_{name}",
        "description": f"Development fallback for {name} capability.",
        "owner": owner,
        "routes": routes,
        "administratorBypass": True,
        "canWakeService": name == "ai",
        "exposedInSetup": True,
        "exposedInCockpit": True,
        "authentikClaims": ["groups"],
        "available": True,
    }
    for name, owner, routes in (
        ("files", "copyparty", ["/shares/"]),
        ("webdav", "copyparty", ["/dav/"]),
        ("ai", "open-webui", ["/ai/"]),
        ("vault", "vaultwarden", ["/vault/"]),
        ("syncthing", "syncthing", ["/settings/syncthing"]),
    )
}

_CAPABILITY_FIELDS = frozenset(
    {
        "id",
        "allowGroup",
        "denyGroup",
        "description",
        "owner",
        "routes",
        "administratorBypass",
        "canWakeService",
        "exposedInSetup",
        "exposedInCockpit",
        "authentikClaims",
        "available",
    }
)
_REGISTRY_REQUIRED = os.environ.get("NAS_CAPABILITY_REGISTRY_REQUIRED") == "1"


def _load_capability_registry() -> tuple[dict[str, str], dict[str, dict[str, Any]]]:
    path_value = os.environ.get("NAS_CAPABILITY_REGISTRY_FILE", "")
    if not path_value:
        if _REGISTRY_REQUIRED:
            raise RuntimeError("NAS capability registry is required in installed/production execution")
        return {}, {name: dict(entry) for name, entry in _DEFAULT_CAPABILITY_REGISTRY.items()}
    path = pathlib.Path(path_value)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Unable to load NAS capability registry {path}: {exc}") from exc
    if not isinstance(raw, Mapping) or raw.get("schemaVersion") != 1:
        raise RuntimeError(f"Invalid NAS capability registry header in {path}")
    identity_groups = raw.get("identityGroups")
    capabilities = raw.get("capabilities")
    if not isinstance(identity_groups, Mapping) or not isinstance(capabilities, Mapping):
        raise RuntimeError(f"Invalid NAS capability registry structure in {path}")
    required_identity_groups = {"administrator", "user", "guest", "disabled"}
    if set(identity_groups) != required_identity_groups:
        raise RuntimeError(f"Invalid identity groups in {path}")
    group_pattern = re.compile(r"^[a-z_][a-z0-9_-]*$")
    groups: dict[str, str] = {}
    for key in sorted(required_identity_groups):
        value = identity_groups.get(key)
        if not isinstance(value, str) or not group_pattern.fullmatch(value):
            raise RuntimeError(f"Invalid identity group {key!r} in {path}")
        groups[key] = value
    if len(set(groups.values())) != len(groups):
        raise RuntimeError(f"Duplicate identity group names in {path}")

    capability_pattern = re.compile(r"^[a-z][a-z0-9-]*$")
    allow_pattern = re.compile(r"^nas_allow_[a-z0-9_]+$")
    deny_pattern = re.compile(r"^nas_deny_[a-z0-9_]+$")
    normalized: dict[str, dict[str, Any]] = {}
    reserved_groups = set(groups.values())
    capability_groups: set[str] = set()
    for name, entry in capabilities.items():
        if not isinstance(name, str) or not capability_pattern.fullmatch(name) or not isinstance(entry, Mapping):
            raise RuntimeError(f"Invalid capability entry in {path}")
        capability_id = entry.get("id")
        allow_group = entry.get("allowGroup")
        deny_group = entry.get("denyGroup")
        administrator_bypass = entry.get("administratorBypass")
        routes = entry.get("routes")
        claims = entry.get("authentikClaims")
        if (
            set(entry) != _CAPABILITY_FIELDS
            or capability_id != name
            or not isinstance(allow_group, str)
            or allow_pattern.fullmatch(allow_group) is None
            or not isinstance(deny_group, str)
            or deny_pattern.fullmatch(deny_group) is None
            or not isinstance(entry.get("description"), str)
            or not entry["description"]
            or not isinstance(entry.get("owner"), str)
            or not entry["owner"]
            or not isinstance(routes, list)
            or not all(isinstance(route, str) and route.startswith("/") for route in routes)
            or not isinstance(administrator_bypass, bool)
            or not isinstance(entry.get("canWakeService"), bool)
            or not isinstance(entry.get("exposedInSetup"), bool)
            or not isinstance(entry.get("exposedInCockpit"), bool)
            or not isinstance(claims, list)
            or not all(isinstance(claim, str) and claim for claim in claims)
            or not isinstance(entry.get("available"), bool)
            or allow_group == deny_group
            or allow_group in reserved_groups
            or deny_group in reserved_groups
            or allow_group in capability_groups
            or deny_group in capability_groups
        ):
            raise RuntimeError(f"Invalid capability {name!r} in {path}")
        capability_groups.update((allow_group, deny_group))
        normalized[name] = dict(entry)
    if not normalized:
        raise RuntimeError(f"Capability registry contains no capabilities in {path}")
    return groups, normalized


_IDENTITY_GROUPS, CAPABILITY_REGISTRY = _load_capability_registry()


def _policy_value(environment_name: str, registry_value: str) -> str:
    if _REGISTRY_REQUIRED:
        return registry_value
    return os.environ.get(environment_name, registry_value)


ADMIN_GROUP = _policy_value("NAS_IDENTITY_ADMIN_GROUP", _IDENTITY_GROUPS.get("administrator", "nas_admin"))
USER_GROUP = _policy_value("NAS_IDENTITY_USER_GROUP", _IDENTITY_GROUPS.get("user", "nas_users"))
GUEST_GROUP = _policy_value("NAS_IDENTITY_GUEST_GROUP", _IDENTITY_GROUPS.get("guest", "nas_guests"))
DISABLED_GROUP = _policy_value("NAS_IDENTITY_DISABLED_GROUP", _IDENTITY_GROUPS.get("disabled", "nas_disabled"))

CAPABILITY_GROUPS: dict[str, tuple[str, str]] = {
    name: (
        _policy_value(f"NAS_IDENTITY_ALLOW_{name.upper()}_GROUP", str(entry["allowGroup"])),
        _policy_value(f"NAS_IDENTITY_DENY_{name.upper()}_GROUP", str(entry["denyGroup"])),
    )
    for name, entry in CAPABILITY_REGISTRY.items()
}


MAX_GROUP_HEADER_BYTES = max(256, int(os.environ.get("NAS_MAX_GROUP_HEADER_BYTES", "8192")))
MAX_GROUPS = max(8, int(os.environ.get("NAS_MAX_GROUPS", "256")))
MAX_GROUP_NAME_LENGTH = max(16, int(os.environ.get("NAS_MAX_GROUP_NAME_LENGTH", "128")))
_MISSING = object()


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

        def write_input() -> None:
            try:
                proc.stdin.write(payload)
                proc.stdin.flush()
            except BrokenPipeError:
                pass
            finally:
                proc.stdin.close()

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
    """Parse block-separated `systemctl show` output by the unit Id field."""

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


class FeatureStateError(ValueError):
    """Persistent feature state contains a type that cannot be interpreted safely."""


def split_groups(raw: str) -> set[str]:
    """Parse a proxy group header with explicit resource bounds.

    Caddy removes client-provided identity headers and writes trusted values, but
    bounded parsing still keeps malformed directory data from consuming
    unbounded memory or CPU in the portal and on-demand authorization gate.
    """

    byte_count = len(raw.encode("utf-8", errors="ignore"))
    if any(ord(character) < 32 or ord(character) == 127 for character in raw):
        print(
            "nas-identity-policy: rejected group header containing control characters",
            file=sys.stderr,
        )
        return set()
    if byte_count > MAX_GROUP_HEADER_BYTES:
        print(
            f"nas-identity-policy: rejected oversized group header ({byte_count} bytes; "
            f"limit {MAX_GROUP_HEADER_BYTES})",
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
                f"nas-identity-policy: rejected group header containing a name longer than "
                f"{MAX_GROUP_NAME_LENGTH} characters",
                file=sys.stderr,
            )
            return set()
        if any(ord(character) < 32 or ord(character) == 127 for character in name):
            print(
                "nas-identity-policy: rejected group header containing control characters",
                file=sys.stderr,
            )
            return set()
        output.add(name)
    return output


def account_enabled(groups: set[str]) -> bool:
    return DISABLED_GROUP not in groups


def account_is_admin(groups: set[str]) -> bool:
    return account_enabled(groups) and ADMIN_GROUP in groups


def account_has_portal_access(groups: set[str]) -> bool:
    """Authenticated accounts may reach the neutral landing/settings page only."""
    return account_enabled(groups)


def account_has_personal_share(groups: set[str]) -> bool:
    return capability_allowed(groups, "files") and GUEST_GROUP not in groups


def capability_allowed(groups: set[str], name: str) -> bool:
    if name not in CAPABILITY_GROUPS or not account_enabled(groups):
        return False
    if ADMIN_GROUP in groups and bool(CAPABILITY_REGISTRY[name].get("administratorBypass", True)):
        return True
    allow_group, deny_group = CAPABILITY_GROUPS[name]
    if deny_group in groups:
        return False
    return allow_group in groups


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


def feature_requested_mode(entry: Mapping[str, Any], value: Any = _MISSING) -> str:
    """Normalize schema-v1 booleans and schema-v2 modes without unsafe fallbacks."""

    if value is _MISSING:
        default = entry.get("defaultMode")
        if isinstance(default, str):
            return default
        return "always" if bool(entry.get("default", False)) else "off"
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        if not value:
            return "off"
        preferred = entry.get("legacyTrueMode")
        if isinstance(preferred, str):
            return preferred
        return "always"
    raise FeatureStateError(f"Unsupported feature mode value: {value!r}")


def effective_feature_modes(catalog: Mapping[str, Any], state: Mapping[str, Any]) -> dict[str, str]:
    """Evaluate feature availability, requested modes, and parent closure once."""

    raw_features = catalog.get("features", {})
    raw_state = state.get("features", {})
    if not isinstance(raw_features, Mapping) or not isinstance(raw_state, Mapping):
        return {}
    features = {str(key): value for key, value in raw_features.items() if isinstance(value, Mapping)}
    requested = {
        feature_id: feature_requested_mode(entry, raw_state[feature_id] if feature_id in raw_state else _MISSING)
        for feature_id, entry in features.items()
    }
    output: dict[str, str] = {}
    for feature_id, entry in features.items():
        mode = requested[feature_id]
        if not bool(entry.get("available", False)) or mode == "off":
            output[feature_id] = "off"
            continue
        seen = {feature_id}
        parent = entry.get("parent")
        enabled = True
        while isinstance(parent, str):
            if parent in seen or parent not in features:
                enabled = False
                break
            seen.add(parent)
            parent_entry = features[parent]
            if not bool(parent_entry.get("available", False)) or requested[parent] == "off":
                enabled = False
                break
            parent = parent_entry.get("parent")
        output[feature_id] = mode if enabled else "off"
    return output


def effective_feature_flags(catalog: Mapping[str, Any], state: Mapping[str, Any]) -> dict[str, bool]:
    return {feature_id: mode != "off" for feature_id, mode in effective_feature_modes(catalog, state).items()}
