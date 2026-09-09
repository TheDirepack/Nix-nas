#!/usr/bin/env python3
"""Small GUI-oriented editor for the sole Managed Services V2 authority.

``services.yaml`` is the only mutable authority.  Git owns history/rollback, so
this module only validates, performs a round-trip YAML edit, and atomically
replaces that one file.  It intentionally does not implement a general YAML
merge/history engine.
"""

from __future__ import annotations

import fcntl
import hashlib
import io
import json
import os
import pathlib
import tempfile
from contextlib import contextmanager
from typing import Any, Iterator

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from nas_v2_spec import (
    DEFAULT_EFFECTIVE_PATH,
    DEFAULT_PLATFORM_PATH,
    DEFAULT_SCHEMA_PATH,
    DEFAULT_SPEC_PATH,
    ManagedServicesV2Error,
    compile_document,
    load_platform_capabilities,
    load_schema,
    parse_yaml_text,
)

_MANAGED_PREAMBLE = (
    "# Nix NAS Managed Services V2\n# This file is primarily edited by the Nix NAS GUI. Git stores its history.\n"
)


class ManagedServicesEditorError(RuntimeError):
    """Raised when the desired-state authority cannot be edited safely."""


def _revision(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _round_trip_yaml() -> YAML:
    parser = YAML(typ="rt", pure=True)
    parser.version = (1, 2)
    parser.allow_duplicate_keys = False
    parser.preserve_quotes = True
    parser.indent(mapping=2, sequence=4, offset=2)
    return parser


def _render(value: Any) -> str:
    buffer = io.StringIO()
    _round_trip_yaml().dump(value, buffer)
    return buffer.getvalue()


def _render_gui_document(value: Any) -> str:
    """Render the GUI document with the one comment block Nix NAS owns."""
    return _MANAGED_PREAMBLE + _render(value).lstrip()


def _load_round_trip(text: str) -> Any:
    try:
        return _round_trip_yaml().load(text)
    except YAMLError as exc:
        raise ManagedServicesEditorError(f"Unable to parse Managed Services V2 authority: {exc}") from exc


def _read_text(path: pathlib.Path) -> str:
    if path.is_dir():
        raise ManagedServicesEditorError(
            f"Managed Services V2 authority must be one YAML file, not a directory: {path}"
        )
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ManagedServicesEditorError(f"Unable to read Managed Services V2 authority: {exc}") from exc


def _revision_for_path(path: pathlib.Path) -> str:
    return _revision(_read_text(path))


@contextmanager
def authority_lock(path: pathlib.Path) -> Iterator[None]:
    lock_path = path.with_name(f".{path.name}.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


_authority_lock = authority_lock


def _validate_text(
    text: str,
    *,
    schema_path: pathlib.Path,
    platform_path: pathlib.Path | None,
) -> dict[str, Any]:
    schema = load_schema(schema_path)
    platform = None if platform_path is None else load_platform_capabilities(platform_path)
    return compile_document(
        parse_yaml_text(text, source="<managed-services-editor>"),
        schema,
        platform_capabilities=platform,
    )


def _atomic_replace(path: pathlib.Path, text: str) -> None:
    if path.is_dir():
        raise ManagedServicesEditorError(
            f"Managed Services V2 authority must be one YAML file, not a directory: {path}"
        )
    try:
        before = path.stat()
        mode = before.st_mode & 0o777
        uid = before.st_uid
        gid = before.st_gid
    except FileNotFoundError:
        mode = 0o640
        uid = 0
        gid = 0

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, raw_temp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp = pathlib.Path(raw_temp)
    replaced = False
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp, mode)
        if os.geteuid() == 0:
            os.chown(temp, uid, gid)
        os.replace(temp, path)
        replaced = True
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if not replaced:
            temp.unlink(missing_ok=True)


def _desired_mode(service: dict[str, Any]) -> str:
    if service.get("enabled", True) is False:
        return "off"
    workload = service.get("workload")
    if isinstance(workload, dict) and workload.get("activation", "persistent") == "on-demand":
        return "on-demand"
    return "always"


def _allowed_modes(service: dict[str, Any]) -> list[str]:
    workload = service.get("workload")
    modes = ["off", "always"]
    if (
        isinstance(workload, dict)
        and workload.get("kind") == "daemon"
        and isinstance(workload.get("idleSeconds"), int)
        and workload["idleSeconds"] > 0
    ):
        modes.insert(1, "on-demand")
    return modes


def _set_mode(service_id: str, service: Any, mode: str) -> None:
    if not isinstance(service, dict):
        raise ManagedServicesEditorError(f"Unknown Managed Services V2 service {service_id!r}")
    workload = service.get("workload")
    if not isinstance(workload, dict):
        raise ManagedServicesEditorError(f"Service {service_id!r} is missing its workload policy")
    if mode == "off":
        service["enabled"] = False
        return
    if mode == "always":
        service["enabled"] = True
        if workload.get("kind") == "daemon":
            workload["activation"] = "persistent"
        return
    if mode != "on-demand":
        raise ManagedServicesEditorError("Service mode must be off, on-demand, or always")
    if workload.get("kind") != "daemon":
        raise ManagedServicesEditorError("Only daemon workloads can use on-demand activation")
    idle_seconds = workload.get("idleSeconds")
    if not isinstance(idle_seconds, int) or idle_seconds <= 0:
        raise ManagedServicesEditorError(
            "On-demand activation requires an explicit positive workload.idleSeconds value"
        )
    service["enabled"] = True
    workload["activation"] = "on-demand"


def owner_unit(service_id: str, service: dict[str, Any]) -> str | None:
    runtime = service.get("runtime")
    if not isinstance(runtime, dict):
        return None
    if runtime.get("type") == "systemd":
        unit = runtime.get("unit")
        return unit if isinstance(unit, str) and unit else None
    return f"nas-v2-{service_id}.service"


def _status_units(service_id: str, service: dict[str, Any]) -> list[dict[str, str]]:
    units: list[dict[str, str]] = []
    owner = owner_unit(service_id, service)
    if owner is not None:
        units.append({"unit": owner, "role": "owner"})
    workload = service.get("workload")
    if isinstance(workload, dict) and workload.get("kind") == "job":
        schedules = workload.get("schedules", [])
        if isinstance(schedules, list):
            for index in range(len(schedules)):
                units.append({"unit": f"nas-v2-timer-{service_id}-{index}.timer", "role": "schedule"})
    return units


def _is_valid_effective_service(entry: Any) -> bool:
    if not isinstance(entry, dict):
        return False
    workload = entry.get("workload")
    if not isinstance(workload, dict):
        return False
    kind = workload.get("kind")
    if kind not in {"daemon", "job", "session"}:
        return False
    runtime = entry.get("runtime")
    if not isinstance(runtime, dict):
        return False
    return True


def _load_effective_value(effective_path: pathlib.Path) -> dict[str, Any] | None:
    try:
        raw = effective_path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(value, dict):
        return None
    if value.get("schemaVersion") != 3:
        return None
    services = value.get("services")
    if not isinstance(services, dict):
        return None
    # Derived runtime is optional for validity but helps distinguish complete documents
    return value


def status(
    *,
    desired_path: pathlib.Path = DEFAULT_SPEC_PATH,
    effective_path: pathlib.Path = DEFAULT_EFFECTIVE_PATH,
) -> dict[str, Any]:
    try:
        desired = parse_yaml_text(_read_text(desired_path), source=str(desired_path))
    except ManagedServicesV2Error as exc:
        raise ManagedServicesEditorError(str(exc)) from exc
    effective_value = _load_effective_value(effective_path)
    # Stale/revision-inconsistent check via mtime: effective older than desired is stale
    is_stale = False
    if effective_value is not None:
        try:
            eff_mtime = effective_path.stat().st_mtime
            des_mtime = desired_path.stat().st_mtime
            if eff_mtime < des_mtime - 0.001:
                is_stale = True
        except OSError:
            pass
    effective_services: dict[str, Any] = {}
    if effective_value is not None and not is_stale:
        candidate = effective_value.get("services")
        if isinstance(candidate, dict):
            effective_services = candidate
    services = desired.get("services")
    if not isinstance(services, dict):
        raise ManagedServicesEditorError("Managed Services V2 authority is missing its services mapping")

    rows: list[dict[str, Any]] = []
    for service_id in sorted(services):
        service = services[service_id]
        if not isinstance(service, dict):
            continue
        entry = effective_services.get(service_id)
        verified = entry is not None and _is_valid_effective_service(entry) and not is_stale
        # Incomplete: missing entry already unverified; stale already handled
        if verified:
            effective_service = entry  # type: ignore[assignment]
            workload = effective_service.get("workload")
            effective_mode = _desired_mode(effective_service)
            effective_flag = effective_service.get("enabled", True) is not False
            available = True
            runtime_available = True
            workload_kind = workload.get("kind") if isinstance(workload, dict) else None
            idle = workload.get("idleSeconds") if isinstance(workload, dict) else None
            units = _status_units(service_id, effective_service)
        else:
            # Desired remains visible; compiled availability is unknown/false
            workload = service.get("workload")
            effective_mode = None
            effective_flag = False
            available = False
            runtime_available = False
            workload_kind = workload.get("kind") if isinstance(workload, dict) else None
            idle = workload.get("idleSeconds") if isinstance(workload, dict) else None
            units = _status_units(service_id, service)
        rows.append(
            {
                "id": service_id,
                "label": service.get("name", service_id),
                "description": service.get("description", ""),
                "requestedMode": _desired_mode(service),
                "effectiveMode": effective_mode,
                "effective": effective_flag,
                "available": available,
                "runtimeAvailable": runtime_available,
                "verified": verified,
                "managed": service.get("managed", True) is not False,
                "workloadKind": workload_kind,
                "allowedModes": _allowed_modes(service),
                "idleSeconds": idle,
                "units": units,
            }
        )
    return {
        "ok": True,
        "schemaVersion": desired.get("schemaVersion"),
        "authority": str(desired_path),
        "services": rows,
    }


def read_document(
    *,
    desired_path: pathlib.Path = DEFAULT_SPEC_PATH,
    schema_path: pathlib.Path = DEFAULT_SCHEMA_PATH,
) -> dict[str, Any]:
    text = _read_text(desired_path)
    try:
        document = parse_yaml_text(text, source=str(desired_path))
        schema = load_schema(schema_path)
    except ManagedServicesV2Error as exc:
        raise ManagedServicesEditorError(str(exc)) from exc
    return {
        "ok": True,
        "authority": str(desired_path),
        "revision": _revision(text),
        "yaml": text,
        "document": document,
        "schema": schema,
    }


def replace_document(
    yaml_text: str,
    *,
    desired_path: pathlib.Path = DEFAULT_SPEC_PATH,
    schema_path: pathlib.Path = DEFAULT_SCHEMA_PATH,
    platform_path: pathlib.Path | None = DEFAULT_PLATFORM_PATH,
    expected_revision: str | None = None,
) -> dict[str, Any]:
    try:
        effective = _validate_text(yaml_text, schema_path=schema_path, platform_path=platform_path)
    except ManagedServicesV2Error as exc:
        raise ManagedServicesEditorError(f"Desired-state update is invalid at {exc.path}: {exc}") from exc
    with authority_lock(desired_path):
        if expected_revision is not None:
            current_revision = _revision_for_path(desired_path)
            if current_revision != expected_revision:
                raise ManagedServicesEditorError(
                    f"Desired-state revision conflict: expected {expected_revision}, got {current_revision}"
                )
        _atomic_replace(desired_path, yaml_text)
    return {
        "ok": True,
        "authority": str(desired_path),
        "revision": _revision(yaml_text),
        "schemaVersion": effective["schemaVersion"],
        "services": len(effective["services"]),
    }


def replace_document_value(
    value: Any,
    *,
    desired_path: pathlib.Path = DEFAULT_SPEC_PATH,
    schema_path: pathlib.Path = DEFAULT_SCHEMA_PATH,
    platform_path: pathlib.Path | None = DEFAULT_PLATFORM_PATH,
    expected_revision: str | None = None,
) -> dict[str, Any]:
    """Render a GUI value to canonical YAML with the Nix NAS comment preamble."""
    if not isinstance(value, dict):
        raise ManagedServicesEditorError("Managed Services V2 JSON document must be an object")
    return replace_document(
        _render_gui_document(value),
        desired_path=desired_path,
        schema_path=schema_path,
        platform_path=platform_path,
        expected_revision=expected_revision,
    )


def set_service_modes(
    modes: dict[str, str],
    *,
    desired_path: pathlib.Path = DEFAULT_SPEC_PATH,
    schema_path: pathlib.Path = DEFAULT_SCHEMA_PATH,
    platform_path: pathlib.Path | None = DEFAULT_PLATFORM_PATH,
) -> dict[str, Any]:
    """Round-trip one GUI mode mutation while preserving existing YAML comments."""
    if not modes:
        return {"ok": True, "changed": [], "authority": str(desired_path)}
    with authority_lock(desired_path):
        document = _load_round_trip(_read_text(desired_path))
        if not isinstance(document, dict):
            raise ManagedServicesEditorError("Managed Services V2 authority must be a mapping")
        services = document.get("services")
        if not isinstance(services, dict):
            raise ManagedServicesEditorError("Managed Services V2 authority is missing its services mapping")
        for service_id, mode in sorted(modes.items()):
            if not isinstance(service_id, str) or not isinstance(mode, str):
                raise ManagedServicesEditorError("Service policy document must map service IDs to string modes")
            _set_mode(service_id, services.get(service_id), mode)
        rendered = _render(document)
        try:
            effective = _validate_text(rendered, schema_path=schema_path, platform_path=platform_path)
        except ManagedServicesV2Error as exc:
            raise ManagedServicesEditorError(f"Desired-state update is invalid at {exc.path}: {exc}") from exc
        _atomic_replace(desired_path, rendered)
    return {
        "ok": True,
        "changed": sorted(modes),
        "authority": str(desired_path),
        "effectiveModes": {
            service_id: _desired_mode(effective["services"][service_id]) for service_id in sorted(modes)
        },
    }


def set_service_mode(
    service_id: str,
    mode: str,
    *,
    desired_path: pathlib.Path = DEFAULT_SPEC_PATH,
    schema_path: pathlib.Path = DEFAULT_SCHEMA_PATH,
    platform_path: pathlib.Path | None = DEFAULT_PLATFORM_PATH,
) -> dict[str, Any]:
    result = set_service_modes(
        {service_id: mode},
        desired_path=desired_path,
        schema_path=schema_path,
        platform_path=platform_path,
    )
    return {
        "ok": True,
        "service": service_id,
        "requestedMode": mode,
        "effectiveMode": result["effectiveModes"][service_id],
        "authority": str(desired_path),
    }


__all__ = [
    "ManagedServicesEditorError",
    "authority_lock",
    "owner_unit",
    "read_document",
    "replace_document",
    "replace_document_value",
    "set_service_mode",
    "set_service_modes",
    "status",
]
