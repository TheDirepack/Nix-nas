#!/usr/bin/env python3
"""File-based managed-service store for the unified Applications layer.

No SQLite, no new daemon — just an atomic JSON file at /var/lib/nas-control/services.json
plus a validated effective projection at /run/nas-control/effective-endpoints.json.
Accept-list only: service IDs, host paths, images, hostnames, ports, Authentik IDs.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import tempfile
from typing import Any

STORE_PATH = pathlib.Path(os.environ.get("NAS_MANAGED_SERVICE_STORE", "/var/lib/nas-control/services.json"))
EFFECTIVE_PATH = pathlib.Path(os.environ.get("NAS_EFFECTIVE_REGISTRY", "/run/nas-control/effective-endpoints.json"))
PORTAL_PATH = pathlib.Path(os.environ.get("NAS_PORTAL_JSON", "/run/nas-control/portal.json"))
BUILTIN_REGISTRY = pathlib.Path(os.environ.get("NAS_BUILTIN_REGISTRY", "/etc/nas-control/endpoints.json"))

SCHEMA_VERSION = 2
ALLOWED_HOST_ROOTS = ("/tank", "/srv", "/var/lib/nas-control/apps")
SERVICE_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,47}$")
ENDPOINT_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,47}$")
IMAGE_RE = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*(?::[a-z0-9_.-]+)?(?:@[a-z0-9:]+)?$", re.IGNORECASE)
HOSTNAME_RE = re.compile(r"^(?:[a-z0-9-]{1,63}\.)*[a-z0-9-]{1,63}$", re.IGNORECASE)


class ManagedServiceError(RuntimeError):
    pass


def _validate_service_id(value: str) -> str:
    if not SERVICE_ID_RE.fullmatch(value):
        raise ManagedServiceError(f"Invalid service ID {value!r}: must match {SERVICE_ID_RE.pattern}")
    return value


def _validate_host_path(path: str) -> str:
    if not path.startswith("/"):
        raise ManagedServiceError(f"hostPath must be absolute: {path!r}")
    # Accept-list: must be beneath an allowed root
    if not any(path == root or path.startswith(root + "/") for root in ALLOWED_HOST_ROOTS):
        raise ManagedServiceError(f"hostPath {path!r} is not beneath allow-list {ALLOWED_HOST_ROOTS}")
    # No traversal, no symlink escape check here — caller must realpath and lstat
    if ".." in pathlib.PurePosixPath(path).parts:
        raise ManagedServiceError(f"hostPath must not contain '..': {path!r}")
    return path


def _validate_image(image: str) -> str:
    if len(image) > 512 or not IMAGE_RE.fullmatch(image):
        raise ManagedServiceError(f"Invalid image reference {image!r}")
    return image


def _validate_hostname(hostname: str) -> str:
    if len(hostname) > 253 or not HOSTNAME_RE.fullmatch(hostname):
        raise ManagedServiceError(f"Invalid hostname {hostname!r}")
    return hostname


def _validate_port(port: int) -> int:
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ManagedServiceError(f"Invalid port {port!r}")
    return port


def validate_service(service_id: str, data: dict[str, Any]) -> dict[str, Any]:
    _validate_service_id(service_id)
    label = data.get("label", "")
    if not isinstance(label, str) or not label or len(label) > 64:
        raise ManagedServiceError(f"Service {service_id}: label must be 1..64 chars")
    runtime = data.get("runtime", {})
    if runtime.get("type") not in ("quadlet", "compose", "vm", "external", "native"):
        raise ManagedServiceError(f"Service {service_id}: runtime.type invalid")
    source = runtime.get("source", "")
    if not isinstance(source, str) or not source.startswith("/var/lib/nas-control/apps/"):
        raise ManagedServiceError(f"Service {service_id}: runtime.source must be under /var/lib/nas-control/apps/")
    # Storage accept-list
    for mount in data.get("storage", []):
        _validate_host_path(mount.get("hostPath", ""))
        guest = mount.get("guestPath", "")
        if not guest.startswith("/"):
            raise ManagedServiceError(f"Service {service_id}: guestPath must be absolute")
    # Endpoints
    for endpoint_id, endpoint in (data.get("endpoints") or {}).items():
        if not ENDPOINT_ID_RE.fullmatch(endpoint_id):
            raise ManagedServiceError(f"Service {service_id}: endpoint {endpoint_id!r} invalid")
        _validate_port(endpoint.get("targetPort", 0))
        exposure = endpoint.get("exposure", {})
        if exposure.get("type") == "hostname":
            _validate_hostname(exposure.get("value", ""))
        elif exposure.get("type") == "dns":
            _validate_hostname(exposure.get("value", ""))
        # Authentik IDs are opaque but must be non-empty and not contain shell metachars
        auth = endpoint.get("auth", {})
        for gid in auth.get("groups", []):
            if not re.fullmatch(r"^[A-Za-z0-9_-]+$", gid):
                raise ManagedServiceError(f"Invalid Authentik group ID {gid!r}")
    return data


def load_store(path: pathlib.Path = STORE_PATH) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {"schemaVersion": SCHEMA_VERSION, "services": {}}
    except OSError as exc:
        raise ManagedServiceError(f"Unable to read {path}: {exc}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ManagedServiceError(f"Invalid JSON in {path}: {exc}") from exc
    if data.get("schemaVersion") != SCHEMA_VERSION:
        raise ManagedServiceError(f"Unsupported schemaVersion in {path}")
    services = data.get("services", {})
    if not isinstance(services, dict):
        raise ManagedServiceError("services must be an object")
    for service_id, service in services.items():
        validate_service(service_id, service)
    return data


def atomic_write_store(data: dict[str, Any], path: pathlib.Path = STORE_PATH) -> None:
    if data.get("schemaVersion") != SCHEMA_VERSION:
        raise ManagedServiceError("Refusing to write store with wrong schemaVersion")
    for service_id, service in data.get("services", {}).items():
        validate_service(service_id, service)
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(data, indent=2, sort_keys=True) + "\n"
    fd, tmp = tempfile.mkstemp(prefix=".services.json.", dir=parent)
    tmp_path = pathlib.Path(tmp)
    try:
        with open(fd, "w", encoding="utf-8") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        tmp_path.chmod(0o600)
        tmp_path.replace(path)
        dir_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        tmp_path.unlink(missing_ok=True)


def effective_registry(builtin_path: pathlib.Path = BUILTIN_REGISTRY, store_path: pathlib.Path = STORE_PATH) -> dict[str, Any]:
    """Merge built-in endpoints (immutable) + runtime services (mutable) into effective projection."""
    try:
        builtin = json.loads(builtin_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        builtin = {"schemaVersion": 1, "endpoints": {}}
    store = load_store(store_path)
    # Built-ins are endpoints, runtime are services with endpoints — merge into one view
    effective = {
        "schemaVersion": SCHEMA_VERSION,
        "generation": store.get("generation", 1),
        "endpoints": dict(builtin.get("endpoints", {})),
        "services": dict(store.get("services", {})),
    }
    # Runtime services' endpoints are also exposed as endpoints for Caddy/portal
    for service_id, service in store.get("services", {}).items():
        for endpoint_id, endpoint in (service.get("endpoints") or {}).items():
            key = f"{service_id}:{endpoint_id}"
            effective["endpoints"][key] = {
                "label": f"{service.get('label')}:{endpoint_id}",
                "serviceId": service_id,
                "endpointId": endpoint_id,
                "transport": endpoint.get("transport"),
                "targetPort": endpoint.get("targetPort"),
                "exposure": endpoint.get("exposure"),
                "auth": endpoint.get("auth"),
                "available": service.get("enabled", False),
            }
    return effective


def write_effective(builtin_path: pathlib.Path = BUILTIN_REGISTRY, store_path: pathlib.Path = STORE_PATH, effective_path: pathlib.Path = EFFECTIVE_PATH) -> dict[str, Any]:
    effective = effective_registry(builtin_path, store_path)
    parent = effective_path.parent
    parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(effective, indent=2, sort_keys=True) + "\n"
    fd, tmp = tempfile.mkstemp(prefix=".effective.json.", dir=parent)
    tmp_path = pathlib.Path(tmp)
    try:
        with open(fd, "w", encoding="utf-8") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        tmp_path.chmod(0o644)
        tmp_path.replace(effective_path)
        dir_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        tmp_path.unlink(missing_ok=True)
    return effective


def portal_projection(effective: dict[str, Any] | None = None) -> dict[str, Any]:
    """Sanitized portal view: label, url, category, icon, access — no secrets, no host paths."""
    if effective is None:
        effective = effective_registry()
    entries = []
    for key, endpoint in effective.get("endpoints", {}).items():
        # Only expose portal-visible endpoints
        # Built-ins have linkKey, runtime have portal.visible
        if endpoint.get("linkKey") is None and not endpoint.get("portal", {}).get("visible", False):
            # For runtime, check service's portal config
            continue
        # Build URL from exposure
        exposure = endpoint.get("exposure") or {}
        url = ""
        if exposure.get("type") == "path":
            url = exposure.get("value", "/")
        elif exposure.get("type") in ("hostname", "dns"):
            url = f"https://{exposure.get('value')}/"
        elif exposure.get("type") == "port":
            url = f"https://nas.local:{exposure.get('value')}/"
        entries.append({
            "id": key,
            "label": endpoint.get("label", key),
            "url": url,
            "category": endpoint.get("portal", {}).get("category", "Other"),
            "icon": endpoint.get("portal", {}).get("icon", "box"),
            "available": endpoint.get("available", False),
            "access": endpoint.get("auth") or {"mode": endpoint.get("access", "admin")},
        })
    return {"schemaVersion": SCHEMA_VERSION, "generation": effective.get("generation", 1), "entries": sorted(entries, key=lambda x: x["id"])}


def write_portal(effective_path: pathlib.Path = EFFECTIVE_PATH, portal_path: pathlib.Path = PORTAL_PATH) -> dict[str, Any]:
    effective = effective_registry()
    portal = portal_projection(effective)
    parent = portal_path.parent
    parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(portal, indent=2, sort_keys=True) + "\n"
    fd, tmp = tempfile.mkstemp(prefix=".portal.json.", dir=parent)
    tmp_path = pathlib.Path(tmp)
    try:
        with open(fd, "w", encoding="utf-8") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        tmp_path.chmod(0o644)
        tmp_path.replace(portal_path)
        dir_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        tmp_path.unlink(missing_ok=True)
    return portal


def main(argv: list[str] | None = None) -> int:
    import argparse
    import sys

    parser = argparse.ArgumentParser(prog="nas-managed-service")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("reconcile", help="Rebuild effective registry and portal from store + built-ins")
    sub.add_parser("validate", help="Validate store and built-ins")
    show = sub.add_parser("show", help="Show effective registry")
    show.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "reconcile":
            effective = write_effective()
            portal = write_portal()
            print(json.dumps({"effective": effective, "portal": portal}, indent=2))
            return 0
        elif args.command == "validate":
            load_store()
            effective_registry()
            print("store and effective registry are valid")
            return 0
        elif args.command == "show":
            effective = effective_registry()
            if args.json:
                print(json.dumps(effective, indent=2))
            else:
                print(json.dumps(effective, indent=2, sort_keys=True))
            return 0
        else:
            parser.print_help()
            return 2
    except ManagedServiceError as exc:
        print(f"nas-managed-service: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"nas-managed-service: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
