#!/usr/bin/env python3
"""Managed Services V2 compatibility and projection layer.

This module is intentionally thin.  It preserves the proven file-backed
reconciler from ``nas_managed_service`` while making the new resource-authority
model executable.  Persisted V2 documents keep named resource references; only
a validation copy is converted to the legacy hostPath mount shape.  Effective
state exposes both the authoritative resource reference and a resolved runtime
mount projection so adapters can migrate independently.
"""

from __future__ import annotations

import copy
import json
import pathlib
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


def _runtime_mode(required_capabilities: list[str]) -> str:
    return "rw" if set(required_capabilities) & {"write", "move", "delete", "admin"} else "ro"


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
    """Validate V2 cross-system policy and return a normalized copy."""

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

        resolved_storage: list[dict[str, Any]] = []
        for attachment in service.get("storage", []):
            if isinstance(attachment, dict) and "resource" in attachment:
                resolved_storage.append(_resolved_mount(service_id, attachment, resources))
            else:
                # Legacy inline mounts remain migration input.  Preserve them in
                # effective state until the owning service is converted.
                resolved_storage.append(copy.deepcopy(attachment))
        service["resolvedStorage"] = resolved_storage

        network = service.get("network") or {}
        if isinstance(network, dict) and "profile" in network:
            profile = network["profile"]
            if profile not in network_profiles:
                raise ManagedResourceError(f"Service {service_id}: unknown network profile {profile!r}")

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
    """Build a copy consumable by the pre-resource V2 validator.

    This is migration glue only; it is never persisted and never becomes the
    authorization source of truth.
    """

    validated = copy.deepcopy(data)
    validated.pop("storageResources", None)
    validated.pop("networkProfiles", None)
    for service in validated.get("services", {}).values():
        service.pop("principal", None)
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
        network = service.get("network")
        if isinstance(network, dict):
            network.pop("profile", None)
        for endpoint in (service.get("endpoints") or {}).values():
            auth = endpoint.get("auth")
            if isinstance(auth, dict):
                auth.pop("capability", None)
    return validated


def load_store(path: pathlib.Path = _legacy.STORE_PATH) -> dict[str, Any]:
    """Load, schema-validate, normalize, then exercise legacy hardening checks."""

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
    """Return effective state including resource and runtime projections."""

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
        effective_service["resolvedStorage"] = service.get("resolvedStorage", [])
    return effective


def _install_compatibility_layer() -> None:
    _legacy.load_store = load_store
    _legacy.effective_registry = effective_registry


def main(argv: list[str] | None = None) -> int:
    _install_compatibility_layer()
    return _legacy.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
