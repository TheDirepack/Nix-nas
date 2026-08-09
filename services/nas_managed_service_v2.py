#!/usr/bin/env python3
"""Managed Services V2 compatibility, projection, and lifecycle layer.

V2 owns cross-system application intent. Native runtimes still own execution,
while this module translates V2 lifecycle/storage policy into those runtimes.
There is deliberately no resident controller: reconcile and idle reaping are
oneshot operations driven by systemd paths/timers or explicit commands.
"""

from __future__ import annotations

import copy
import json
import os
import pathlib
import tempfile
import time
from typing import Any

import nas_managed_service as _legacy
from nas_managed_resources import (
    ManagedResourceError,
    application_principal,
    backup_resource_ids,
    validate_application_principal,
    validate_capability_reference,
    validate_storage_attachment,
    validate_storage_resources,
)

_ORIGINAL_LOAD_STORE = _legacy.load_store
_ORIGINAL_EFFECTIVE_REGISTRY = _legacy.effective_registry

LIFECYCLE_MODES = frozenset({"persistent", "on-demand", "session"})
_START_POLICY_TO_LIFECYCLE = {
    "boot": "persistent",
    "on-demand": "on-demand",
    "manual": "session",
}
DEFAULT_IDLE_SECONDS = 600
LIFECYCLE_STATE_PATH = pathlib.Path(
    os.environ.get("NAS_MANAGED_LIFECYCLE_STATE", "/run/nas-control/lifecycle.json")
)


def _runtime_mode(required_capabilities: list[str]) -> str:
    return "rw" if set(required_capabilities) & {"write", "move", "delete", "admin"} else "ro"


def _normalize_lifecycle(service_id: str, service: dict[str, Any]) -> dict[str, Any]:
    """Return canonical runtime-lifetime policy while accepting old startPolicy input.

    ``enabled`` controls whether the application is available at all. Lifecycle
    controls what happens while it is enabled:

    * persistent: reconcile keeps the runtime running;
    * on-demand: authorized access starts it and a timer reaps it after idle time;
    * session: an explicit session launcher owns a disposable runtime instance.

    Runtime lifetime and storage lifetime are deliberately independent. Stopping
    or destroying a runtime never implies deleting authoritative V2 storage.
    """

    runtime = service.get("runtime") or {}
    start_policy = runtime.get("startPolicy")
    lifecycle = service.get("lifecycle")
    enabled = service.get("enabled")

    if lifecycle is None:
        if start_policy == "disabled":
            if enabled is not False:
                raise ManagedResourceError(
                    f"Service {service_id}: runtime.startPolicy='disabled' requires enabled=false"
                )
            mode = "persistent"
        else:
            mode = _START_POLICY_TO_LIFECYCLE.get(start_policy)
        if mode is None:
            raise ManagedResourceError(f"Service {service_id}: cannot derive lifecycle from runtime.startPolicy")
        normalized = {"mode": mode}
        if mode == "on-demand":
            normalized["idleSeconds"] = DEFAULT_IDLE_SECONDS
        return normalized

    if not isinstance(lifecycle, dict):
        raise ManagedResourceError(f"Service {service_id}: lifecycle must be an object")
    mode = lifecycle.get("mode")
    if mode not in LIFECYCLE_MODES:
        raise ManagedResourceError(f"Service {service_id}: invalid lifecycle mode {mode!r}")

    normalized: dict[str, Any] = {"mode": mode}
    idle_seconds = lifecycle.get("idleSeconds")
    if mode == "on-demand":
        if isinstance(idle_seconds, bool) or not isinstance(idle_seconds, int) or not 30 <= idle_seconds <= 604800:
            raise ManagedResourceError(
                f"Service {service_id}: on-demand lifecycle requires idleSeconds between 30 and 604800"
            )
        normalized["idleSeconds"] = idle_seconds
    elif idle_seconds is not None:
        raise ManagedResourceError(f"Service {service_id}: idleSeconds is only valid for on-demand lifecycle")

    if start_policy == "disabled":
        if enabled is not False:
            raise ManagedResourceError(
                f"Service {service_id}: runtime.startPolicy='disabled' requires enabled=false"
            )
    elif start_policy is not None:
        migrated = _START_POLICY_TO_LIFECYCLE.get(start_policy)
        if migrated != mode:
            raise ManagedResourceError(
                f"Service {service_id}: runtime.startPolicy={start_policy!r} conflicts with lifecycle.mode={mode!r}"
            )
    return normalized


def _resolved_mount(
    service_id: str,
    attachment: dict[str, Any],
    resources: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    normalized = validate_storage_attachment(service_id, attachment, resources)
    resource = resources[normalized["resource"]]
    mount: dict[str, Any] = {
        "resource": normalized["resource"],
        "hostPath": resource["path"],
        "guestPath": normalized["guestPath"],
        "mode": _runtime_mode(normalized["requiredCapabilities"]),
        "requiredCapabilities": normalized["requiredCapabilities"],
        "stateClass": resource["stateClass"],
        "scope": resource["scope"],
    }
    if resource.get("dataset"):
        mount["dataset"] = resource["dataset"]
    if resource.get("pathTemplate"):
        mount["pathTemplate"] = resource["pathTemplate"]
    return mount


def normalize_document(data: dict[str, Any]) -> dict[str, Any]:
    resources = validate_storage_resources(data.get("storageResources"))
    normalized = copy.deepcopy(data)
    normalized["storageResources"] = resources

    network_profiles = normalized.get("networkProfiles", {})
    if network_profiles is not None and not isinstance(network_profiles, dict):
        raise ManagedResourceError("networkProfiles must be an object")

    services = normalized.get("services", {})
    if not isinstance(services, dict):
        raise ManagedResourceError("services must be an object")

    for service_id, service in services.items():
        if not isinstance(service, dict):
            raise ManagedResourceError(f"Service {service_id!r} must be an object")
        principal = service.get("principal", application_principal(service_id))
        service["principal"] = validate_application_principal(principal, service_id=service_id)
        service["lifecycle"] = _normalize_lifecycle(service_id, service)

        resolved_storage: list[dict[str, Any]] = []
        for attachment in service.get("storage", []):
            if isinstance(attachment, dict) and "resource" in attachment:
                resolved_storage.append(_resolved_mount(service_id, attachment, resources))
            else:
                resolved_storage.append(copy.deepcopy(attachment))
        service["resolvedStorage"] = resolved_storage

        network_profile = service.get("networkProfile")
        if network_profile is not None and network_profile not in network_profiles:
            raise ManagedResourceError(f"Service {service_id}: unknown network profile {network_profile!r}")

        for endpoint_id, endpoint in (service.get("endpoints") or {}).items():
            auth = endpoint.get("auth") or {}
            capability = auth.get("capability")
            if capability is not None:
                validate_capability_reference(capability)
                expected_prefix = f"application.{service_id}."
                if not capability.startswith(expected_prefix):
                    raise ManagedResourceError(
                        f"Service {service_id}: endpoint {endpoint_id!r} capability must start with {expected_prefix!r}"
                    )
    return normalized


def _legacy_validation_copy(data: dict[str, Any]) -> dict[str, Any]:
    validated = copy.deepcopy(data)
    validated.pop("storageResources", None)
    validated.pop("networkProfiles", None)
    for service in validated.get("services", {}).values():
        service.pop("principal", None)
        service.pop("lifecycle", None)
        service.pop("networkProfile", None)
        resolved = service.pop("resolvedStorage", service.get("storage", []))
        legacy_mounts = []
        for mount in resolved:
            if isinstance(mount, dict) and "hostPath" in mount:
                legacy_mounts.append(
                    {
                        key: value
                        for key, value in mount.items()
                        if key in {"hostPath", "guestPath", "mode", "dataset"}
                    }
                )
            else:
                legacy_mounts.append(mount)
        service["storage"] = legacy_mounts
        for endpoint in (service.get("endpoints") or {}).values():
            auth = endpoint.get("auth")
            if isinstance(auth, dict):
                auth.pop("capability", None)
    return validated


def load_store(path: pathlib.Path = _legacy.STORE_PATH) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {
            "schemaVersion": _legacy.SCHEMA_VERSION,
            "generation": 1,
            "storageResources": {},
            "networkProfiles": {},
            "services": {},
        }
    except OSError as exc:
        raise _legacy.ManagedServiceError(f"Unable to read {path}: {exc}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise _legacy.ManagedServiceError(f"Invalid JSON in {path}: {exc}") from exc

    _legacy._schema_validate_document(data)
    try:
        normalized = normalize_document(data)
    except ManagedResourceError as exc:
        raise _legacy.ManagedServiceError(str(exc)) from exc

    validation_copy = _legacy_validation_copy(normalized)
    for service_id, service in validation_copy.get("services", {}).items():
        _legacy.validate_service(service_id, service)
    return normalized


def effective_registry(
    builtin_path: pathlib.Path = _legacy.BUILTIN_REGISTRY,
    store_path: pathlib.Path = _legacy.STORE_PATH,
) -> dict[str, Any]:
    effective = _ORIGINAL_EFFECTIVE_REGISTRY(builtin_path, store_path)
    store = load_store(store_path)
    effective["storageResources"] = store.get("storageResources", {})
    effective["networkProfiles"] = store.get("networkProfiles", {})
    effective["backupResources"] = backup_resource_ids(effective["storageResources"])
    for service_id, service in store.get("services", {}).items():
        if service_id not in effective["services"]:
            continue
        effective_service = effective["services"][service_id]
        effective_service["principal"] = service["principal"]
        effective_service["lifecycle"] = service["lifecycle"]
        effective_service["resolvedStorage"] = service.get("resolvedStorage", [])
        if service.get("networkProfile") is not None:
            effective_service["networkProfile"] = service["networkProfile"]
    return effective


def _read_lifecycle_state(path: pathlib.Path = LIFECYCLE_STATE_PATH) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {"schemaVersion": 1, "services": {}}
    if value.get("schemaVersion") != 1 or not isinstance(value.get("services"), dict):
        return {"schemaVersion": 1, "services": {}}
    return value


def _write_lifecycle_state(value: dict[str, Any], path: pathlib.Path = LIFECYCLE_STATE_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    tmp = pathlib.Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o640)
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def touch_service(service_id: str, *, now: int | None = None) -> dict[str, Any]:
    effective = effective_registry()
    service = effective.get("services", {}).get(service_id)
    if not isinstance(service, dict):
        raise ManagedResourceError(f"Unknown managed service {service_id!r}")
    if not service.get("enabled"):
        raise ManagedResourceError(f"Service {service_id!r} is disabled")
    if service.get("lifecycle", {}).get("mode") != "on-demand":
        raise ManagedResourceError(f"Service {service_id!r} is not on-demand")
    state = _read_lifecycle_state()
    record = state["services"].setdefault(service_id, {})
    record["lastAccess"] = int(time.time()) if now is None else int(now)
    _write_lifecycle_state(state)
    return record


def _apply_runtime(service_id: str, service: dict[str, Any], *, enabled: bool) -> dict[str, Any]:
    runtime_type = (service.get("runtime") or {}).get("type")
    candidate = copy.deepcopy(service)
    candidate["enabled"] = enabled
    if runtime_type == "quadlet":
        from nas_service_runtime_podman import apply_podman

        return apply_podman(service_id, candidate)
    if runtime_type == "compose":
        from nas_service_runtime_compose import apply_compose

        return apply_compose(service_id, candidate)
    if runtime_type == "vm":
        from nas_service_runtime_libvirt import apply_libvirt

        return apply_libvirt(service_id, candidate)
    raise ManagedResourceError(
        f"Service {service_id}: runtime type {runtime_type!r} has no native lifecycle adapter yet"
    )


def start_service(service_id: str) -> dict[str, Any]:
    service = effective_registry().get("services", {}).get(service_id)
    if not isinstance(service, dict):
        raise ManagedResourceError(f"Unknown managed service {service_id!r}")
    if not service.get("enabled"):
        raise ManagedResourceError(f"Service {service_id!r} is disabled")
    lifecycle = service.get("lifecycle", {})
    if lifecycle.get("mode") == "session":
        raise ManagedResourceError(
            f"Service {service_id!r} is session-scoped and must be started by its session launcher"
        )
    result = _apply_runtime(service_id, service, enabled=True)
    if lifecycle.get("mode") == "on-demand":
        touch_service(service_id)
    return result


def stop_service(service_id: str) -> dict[str, Any]:
    service = effective_registry().get("services", {}).get(service_id)
    if not isinstance(service, dict):
        raise ManagedResourceError(f"Unknown managed service {service_id!r}")
    return _apply_runtime(service_id, service, enabled=False)


def reconcile_lifecycle(effective: dict[str, Any] | None = None) -> dict[str, Any]:
    if effective is None:
        effective = effective_registry()
    actions: list[dict[str, Any]] = []
    for service_id, service in sorted((effective.get("services") or {}).items()):
        if not isinstance(service, dict):
            continue
        mode = (service.get("lifecycle") or {}).get("mode")
        if not service.get("enabled"):
            actions.append(
                {
                    "service": service_id,
                    "mode": mode,
                    "enabled": False,
                    "result": _apply_runtime(service_id, service, enabled=False),
                }
            )
        elif mode == "persistent":
            actions.append(
                {
                    "service": service_id,
                    "mode": mode,
                    "enabled": True,
                    "result": _apply_runtime(service_id, service, enabled=True),
                }
            )
        elif mode == "session":
            # Session runtimes must never survive a reconcile/reboot merely
            # because the app is enabled. A dedicated launcher owns each session.
            actions.append(
                {
                    "service": service_id,
                    "mode": mode,
                    "enabled": True,
                    "result": _apply_runtime(service_id, service, enabled=False),
                }
            )
    return {"actions": actions}


def reap_lifecycle(*, now: int | None = None) -> dict[str, Any]:
    current = int(time.time()) if now is None else int(now)
    effective = effective_registry()
    state = _read_lifecycle_state()
    stopped: list[str] = []
    for service_id, service in sorted((effective.get("services") or {}).items()):
        if not isinstance(service, dict) or not service.get("enabled"):
            continue
        lifecycle = service.get("lifecycle") or {}
        if lifecycle.get("mode") != "on-demand":
            continue
        record = state.get("services", {}).get(service_id, {})
        last_access = record.get("lastAccess")
        if not isinstance(last_access, int):
            continue
        if current - last_access < int(lifecycle["idleSeconds"]):
            continue
        _apply_runtime(service_id, service, enabled=False)
        stopped.append(service_id)
        state["services"].pop(service_id, None)
    if stopped:
        _write_lifecycle_state(state)
    return {"stopped": stopped}


def _install_compatibility_layer() -> None:
    _legacy.load_store = load_store
    _legacy.effective_registry = effective_registry


def main(argv: list[str] | None = None) -> int:
    import argparse
    import sys

    _install_compatibility_layer()
    parser = argparse.ArgumentParser(prog="nas-managed-service")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("reconcile", help="Rebuild projections and enforce application lifecycle")
    sub.add_parser("validate", help="Validate V2 store and effective registry")
    show = sub.add_parser("show", help="Show effective registry")
    show.add_argument("--json", action="store_true")
    for command in ("start", "stop", "restart", "touch"):
        action = sub.add_parser(command)
        action.add_argument("service")
    sub.add_parser("reap", help="Stop idle on-demand applications")
    for command in ("plan", "create", "update", "delete", "adopt", "export", "import"):
        sub.add_parser(command)
    args = parser.parse_args(argv)

    try:
        if args.command == "reconcile":
            effective = _legacy.write_effective()
            portal = _legacy.write_portal()
            lifecycle = reconcile_lifecycle(effective)
            print(json.dumps({"effective": effective, "portal": portal, "lifecycle": lifecycle}, indent=2))
            return 0
        if args.command == "validate":
            load_store()
            effective_registry()
            print("store and effective registry are valid")
            return 0
        if args.command == "show":
            print(json.dumps(effective_registry(), indent=2, sort_keys=not args.json))
            return 0
        if args.command == "start":
            print(json.dumps(start_service(args.service), indent=2, default=str))
            return 0
        if args.command == "stop":
            print(json.dumps(stop_service(args.service), indent=2, default=str))
            return 0
        if args.command == "restart":
            stop_service(args.service)
            print(json.dumps(start_service(args.service), indent=2, default=str))
            return 0
        if args.command == "touch":
            print(json.dumps(touch_service(args.service), indent=2))
            return 0
        if args.command == "reap":
            print(json.dumps(reap_lifecycle(), indent=2))
            return 0
        print(f"nas-managed-service: {args.command} is not yet implemented", file=sys.stderr)
        return 2
    except (ManagedResourceError, _legacy.ManagedServiceError, OSError) as exc:
        print(f"nas-managed-service: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
