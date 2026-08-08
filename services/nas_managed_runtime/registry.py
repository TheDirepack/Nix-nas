#!/usr/bin/env python3
"""Managed-service store, effective-registry, and portal projections."""
from __future__ import annotations
import copy, hashlib, ipaddress, json, pathlib, re
from typing import Any, Mapping
from nas_operation_journal import atomic_write_json
from nas_managed_runtime.model import (
    STORE_PATH, BUILTIN_REGISTRY, EFFECTIVE_PATH, PORTAL_PATH, LAN_HOST,
    HOST_PORT_MIN, HOST_PORT_MAX, VM_POOL, SCHEMA_VERSION, SERVICE_ID_RE, ENDPOINT_ID_RE,
    ManagedServiceError, normalize_service, _validate_schema_if_available, _validate_image,
    _validate_port, _validate_hostname,
)

RESERVED_PATHS = (
    "/api", "/outpost.goauthentik.io", "/identity", "/console", "/shares",
    "/share", "/dav", "/vault", "/ai", "/syncthing", "/metrics",
    "/victoriametrics", "/alerts", "/ups", "/notifications", "/settings",
)


def normalize_store(raw: Mapping[str, Any]) -> dict[str, Any]:
    store = copy.deepcopy(dict(raw))
    store.setdefault("schemaVersion", 2)
    store.setdefault("generation", 1)
    store.setdefault("services", {})
    if store["schemaVersion"] != 2 or not isinstance(store["services"], dict):
        raise ManagedServiceError("managed service store must be schemaVersion=2 with services object")
    store["services"] = {sid: normalize_service(sid, svc) for sid, svc in store["services"].items()}
    _validate_schema_if_available(store)
    return store


def load_store(path: pathlib.Path | None = None) -> dict[str, Any]:
    path = STORE_PATH if path is None else path
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raw = {"schemaVersion": 2, "generation": 1, "services": {}}
    except (OSError, json.JSONDecodeError) as exc:
        raise ManagedServiceError(f"unable to read {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ManagedServiceError("managed-service store must be a JSON object")
    return normalize_store(raw)


def atomic_write_store(store: Mapping[str, Any], path: pathlib.Path | None = None) -> None:
    atomic_write_json(STORE_PATH if path is None else path, normalize_store(store), mode=0o600)


def _vm_mac(service_id: str) -> str:
    digest = hashlib.sha256(("nas-vm:" + service_id).encode()).digest()
    return "52:54:00:" + ":".join(f"{value:02x}" for value in digest[:3])


def allocate_runtime_addresses(store: dict[str, Any]) -> None:
    used_subnets = {
        ipaddress.ip_network(svc["network"]["vmSubnet"], strict=True)
        for svc in store["services"].values()
        if svc["runtime"]["type"] == "vm" and svc["network"].get("vmSubnet")
    }
    free = (subnet for subnet in VM_POOL.subnets(new_prefix=24) if subnet not in used_subnets)
    for sid, svc in sorted(store["services"].items()):
        if svc["runtime"]["type"] != "vm":
            continue
        network_config = svc["network"]
        if not network_config.get("vmSubnet"):
            network_config["vmSubnet"] = str(next(free))
        subnet = ipaddress.ip_network(network_config["vmSubnet"], strict=True)
        network_config.setdefault("vmAddress", str(subnet.network_address + 10))
        network_config.setdefault("vmMac", _vm_mac(sid))
        for endpoint in svc["endpoints"].values():
            if endpoint["exposure"]["type"] != "none":
                endpoint.setdefault("targetHost", network_config["vmAddress"])

    used_ports = {
        int(endpoint["hostPort"])
        for svc in store["services"].values()
        for endpoint in svc["endpoints"].values()
        if isinstance(endpoint.get("hostPort"), int)
    }
    cursor = HOST_PORT_MIN
    for _sid, svc in sorted(store["services"].items()):
        if svc["runtime"]["type"] not in {"container", "compose"}:
            continue
        for _eid, endpoint in sorted(svc["endpoints"].items()):
            kind = endpoint["exposure"]["type"]
            web = endpoint["transport"] in {"http", "https", "ws"}
            if kind in {"path", "hostname", "dns"} or (kind == "port" and web):
                if not endpoint.get("hostPort"):
                    while cursor in used_ports and cursor <= HOST_PORT_MAX:
                        cursor += 1
                    if cursor > HOST_PORT_MAX:
                        raise ManagedServiceError("managed backend port pool exhausted")
                    endpoint["hostPort"] = cursor
                    used_ports.add(cursor)
                    cursor += 1
            elif kind == "port" and not endpoint.get("hostPort"):
                endpoint["hostPort"] = int(endpoint["exposure"]["value"])


def effective_registry(
    builtin_path: pathlib.Path | None = None,
    store_path: pathlib.Path | None = None,
) -> dict[str, Any]:
    builtin_path = BUILTIN_REGISTRY if builtin_path is None else builtin_path
    store_path = STORE_PATH if store_path is None else store_path
    try:
        builtin = json.loads(builtin_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        builtin = {"schemaVersion": 2, "services": {}}
    runtime_store = load_store(store_path)
    services: dict[str, Any] = {}
    endpoints: dict[str, Any] = {}

    if isinstance(builtin, dict) and builtin.get("schemaVersion") == 2 and isinstance(builtin.get("services"), dict):
        for sid, svc0 in builtin["services"].items():
            if not isinstance(svc0, dict):
                continue
            svc = copy.deepcopy(svc0)
            svc["builtin"] = True
            svc["ownership"] = "system"
            services[sid] = svc
            for eid, ep0 in (svc.get("endpoints") or {}).items():
                if not isinstance(ep0, dict):
                    continue
                key = f"{sid}:{eid}"
                ep = copy.deepcopy(ep0)
                ep.update({
                    "id": key,
                    "serviceId": sid,
                    "endpointId": eid,
                    "label": ep.get("label") or svc.get("label", sid),
                    "description": ep.get("description") or svc.get("description", ""),
                    "runtimeType": svc.get("runtime", {}).get("type", "systemd"),
                    "available": bool(svc.get("enabled")),
                    "builtin": True,
                })
                endpoints[key] = ep
    elif isinstance(builtin, dict):
        for key, ep0 in (builtin.get("endpoints") or {}).items():
            if not isinstance(ep0, dict):
                continue
            ep = copy.deepcopy(ep0)
            access = str(ep.get("access", "admin"))
            ep.setdefault("exposure", {"type": "path", "value": ep.get("publicPath", "/")})
            ep.setdefault("portal", {
                "visible": ep.get("linkKey") is not None,
                "category": "Administration" if access == "admin" else "Other",
                "icon": ep.get("linkKey") or "box",
            })
            ep.setdefault(
                "auth",
                {"mode": "public"}
                if access in {"public", "native", "network"}
                else {
                    "mode": "forward-auth",
                    "allow": "groups" if access == "admin" else "any",
                    "groups": ["nas_admin"] if access == "admin" else [],
                    "users": [],
                    "adminBypass": True,
                },
            )
            ep.update({
                "id": key,
                "serviceId": str(ep.get("owner") or key),
                "endpointId": key,
                "available": bool(ep.get("available", True)),
                "builtin": True,
            })
            endpoints[key] = ep

    for sid, svc in runtime_store["services"].items():
        services[sid] = copy.deepcopy(svc)
        for eid, ep0 in svc["endpoints"].items():
            key = f"{sid}:{eid}"
            ep = copy.deepcopy(ep0)
            ep.update({
                "id": key,
                "serviceId": sid,
                "endpointId": eid,
                "label": ep.get("label") or svc["label"],
                "description": ep.get("description") or svc.get("description", ""),
                "runtimeType": svc["runtime"]["type"],
                "available": bool(svc["enabled"]),
                "builtin": False,
            })
            endpoints[key] = ep
    return {"schemaVersion": 2, "generation": runtime_store["generation"], "services": services, "endpoints": endpoints}


def validate_conflicts(effective: Mapping[str, Any]) -> None:
    paths: list[tuple[str, str]] = []
    hosts: dict[str, str] = {}
    ports: dict[int, str] = {}
    backend: dict[int, str] = {}
    reserved_paths = [
        str(ep.get("exposure", {}).get("value"))
        for ep in effective["endpoints"].values()
        if ep.get("builtin") and ep.get("exposure", {}).get("type") == "path"
    ]
    for key, endpoint in effective["endpoints"].items():
        if endpoint.get("builtin"):
            continue
        host_port = endpoint.get("hostPort")
        if isinstance(host_port, int):
            if host_port in backend:
                raise ManagedServiceError(f"backend port {host_port} conflicts between {backend[host_port]} and {key}")
            backend[host_port] = key
        exposure = endpoint.get("exposure") or {}
        kind = exposure.get("type")
        value = exposure.get("value")
        if kind == "path":
            normalized = "/" + str(value).strip("/") + "/"
            if normalized == "//":
                raise ManagedServiceError("managed endpoint may not replace portal root")
            for other_key, other in [("built-in", path) for path in reserved_paths] + paths:
                existing = "/" + other.strip("/") + "/"
                if normalized == existing or normalized.startswith(existing) or existing.startswith(normalized):
                    raise ManagedServiceError(f"path {value} overlaps {other_key}:{other}")
            paths.append((key, str(value)))
        elif kind in {"hostname", "dns"}:
            host = str(value).lower().rstrip(".")
            if host == LAN_HOST.lower().rstrip("."):
                raise ManagedServiceError("managed endpoint may not claim primary NAS hostname")
            if host in hosts:
                raise ManagedServiceError(f"hostname {host} claimed by {hosts[host]} and {key}")
            hosts[host] = key
        elif kind == "port":
            port = int(value)
            if port in {80, 443}:
                raise ManagedServiceError(f"reserved public port {port}")
            if port in ports:
                raise ManagedServiceError(f"public port {port} claimed by {ports[port]} and {key}")
            ports[port] = key
    for sid, svc in effective["services"].items():
        if svc.get("builtin"):
            continue
        for rule in (svc.get("network") or {}).get("allowedServices", []):
            if rule["service"] not in effective["services"]:
                raise ManagedServiceError(f"service {sid}: allowedServices references unknown {rule['service']}")


def portal_projection(effective: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if effective is None:
        effective = effective_registry()
    entries = []
    for key, endpoint in effective["endpoints"].items():
        portal = endpoint.get("portal") or {}
        if portal.get("visible") is not True and endpoint.get("linkKey") is None:
            continue
        exposure = endpoint.get("exposure") or {}
        kind = exposure.get("type")
        value = exposure.get("value")
        url = ""
        if kind == "path":
            url = str(value)
        elif kind in {"hostname", "dns"}:
            url = f"https://{value}/"
        elif kind == "port":
            url = f"https://{LAN_HOST}:{value}/"
        if not url:
            continue
        entries.append({
            "id": key,
            "label": endpoint.get("label", key),
            "description": endpoint.get("description", ""),
            "url": url,
            "category": portal.get("category", "Other"),
            "icon": portal.get("icon", "box"),
            "available": bool(endpoint.get("available")),
            "access": copy.deepcopy(endpoint.get("auth") or {"mode": endpoint.get("access", "admin")}),
            "builtin": bool(endpoint.get("builtin")),
        })
    return {
        "schemaVersion": 2,
        "generation": effective.get("generation", 1),
        "entries": sorted(entries, key=lambda entry: (entry["category"], entry["label"], entry["id"])),
    }


def _write_projection(path: pathlib.Path, value: Mapping[str, Any], mode: int = 0o644) -> None:
    atomic_write_json(path, dict(value), mode=mode)


def validate_service(service_id: str, data: Mapping[str, Any]) -> dict[str, Any]:
    """Validate without mutating or default-filling the caller's document.

    Persistence paths call ``normalize_service`` separately.  Keeping this
    function non-mutating preserves the public validation contract and makes it
    safe for preview/property-test callers.
    """
    if SERVICE_ID_RE.fullmatch(service_id) is None:
        raise ManagedServiceError(f"Invalid service ID {service_id!r}")
    value = copy.deepcopy(dict(data))
    label = value.get("label")
    if not isinstance(label, str) or not 1 <= len(label) <= 64:
        raise ManagedServiceError("label must be 1..64 characters")
    if "enabled" in value and not isinstance(value["enabled"], bool):
        raise ManagedServiceError("enabled must be boolean")

    runtime = value.get("runtime")
    if not isinstance(runtime, dict):
        raise ManagedServiceError("runtime must be object")
    runtime_type = runtime.get("type")
    # Legacy validation-only alias retained for older exported definitions.
    if runtime_type == "quadlet":
        runtime_type = "compose"
    if runtime_type not in {"container", "compose", "vm", "native", "external"}:
        raise ManagedServiceError("runtime.type invalid")
    if runtime_type in {"compose", "vm"}:
        source = runtime.get("source")
        if (
            not isinstance(source, str)
            or not source.startswith(f"/var/lib/nas-control/apps/{service_id}/")
            or ".." in pathlib.PurePosixPath(source).parts
        ):
            raise ManagedServiceError("runtime.source must be below the service application root")
    if "image" in runtime:
        _validate_image(runtime["image"])

    for mount in value.get("storage", []) or []:
        if not isinstance(mount, dict):
            raise ManagedServiceError("storage entry must be object")
        host_path = mount.get("hostPath")
        if not isinstance(host_path, str) or not host_path.startswith("/"):
            raise ManagedServiceError("hostPath must be absolute")
        if ".." in pathlib.PurePosixPath(host_path).parts:
            raise ManagedServiceError("hostPath must not contain '..'")

    endpoints = value.get("endpoints", {})
    if not isinstance(endpoints, dict):
        raise ManagedServiceError("endpoints must be object")
    for eid, endpoint in endpoints.items():
        if ENDPOINT_ID_RE.fullmatch(str(eid)) is None or not isinstance(endpoint, dict):
            raise ManagedServiceError(f"endpoint {eid!r} invalid")
        _validate_port(endpoint.get("targetPort"))
        exposure = endpoint.get("exposure")
        if not isinstance(exposure, dict):
            raise ManagedServiceError(f"endpoint {eid!r} exposure must be object")
        kind = exposure.get("type", "none")
        if kind not in {"none", "path", "hostname", "dns", "port"}:
            raise ManagedServiceError(f"endpoint {eid!r} exposure type invalid")
        if kind in {"hostname", "dns"}:
            hostname = exposure.get("value")
            _validate_hostname(hostname)
            normalized_host = str(hostname).lower().rstrip(".")
            primary = LAN_HOST.lower().rstrip(".")
            if normalized_host == primary or normalized_host.endswith("." + primary):
                raise ManagedServiceError(f"endpoint {eid!r} hostname {hostname!r} collides with NAS host")
        elif kind == "path":
            path = exposure.get("value")
            if not isinstance(path, str) or not path.startswith("/") or ".." in pathlib.PurePosixPath(path).parts:
                raise ManagedServiceError(f"endpoint {eid!r} path exposure invalid")
            if any(path == reserved or path.startswith(reserved + "/") for reserved in RESERVED_PATHS):
                raise ManagedServiceError(f"endpoint {eid!r} path {path!r} conflicts with reserved NAS path")
        elif kind == "port":
            raw_port = exposure.get("value")
            _validate_port(int(raw_port) if isinstance(raw_port, str) and raw_port.isdigit() else raw_port)

        auth = endpoint.get("auth")
        if not isinstance(auth, dict):
            raise ManagedServiceError(f"endpoint {eid!r} auth must be object")
        mode = auth.get("mode")
        if mode not in {"public", "forward-auth", "native", "oidc"}:
            raise ManagedServiceError(f"endpoint {eid!r} auth mode invalid")
        for key in ("groups", "users"):
            refs = auth.get(key, []) or []
            if not isinstance(refs, list):
                raise ManagedServiceError(f"endpoint {eid!r} auth.{key} must be array")
            for reference in refs:
                if not isinstance(reference, str) or not re.fullmatch(r"^[A-Za-z0-9._-]{1,128}$", reference):
                    raise ManagedServiceError(f"Invalid Authentik {key[:-1]} ID {reference!r}")
    return copy.deepcopy(dict(data))


def write_effective(
    builtin_path: pathlib.Path | None = None,
    store_path: pathlib.Path | None = None,
    effective_path: pathlib.Path | None = None,
) -> dict[str, Any]:
    builtin_path = BUILTIN_REGISTRY if builtin_path is None else builtin_path
    store_path = STORE_PATH if store_path is None else store_path
    effective_path = EFFECTIVE_PATH if effective_path is None else effective_path
    effective = effective_registry(builtin_path, store_path)
    validate_conflicts(effective)
    _write_projection(effective_path, effective)
    return effective


def write_portal(
    effective_path: pathlib.Path | None = None,
    portal_path: pathlib.Path | None = None,
) -> dict[str, Any]:
    effective_path = EFFECTIVE_PATH if effective_path is None else effective_path
    portal_path = PORTAL_PATH if portal_path is None else portal_path
    try:
        effective = json.loads(effective_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        effective = effective_registry()
    portal = portal_projection(effective)
    _write_projection(portal_path, portal)
    return portal
