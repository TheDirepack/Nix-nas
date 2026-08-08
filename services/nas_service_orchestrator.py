#!/usr/bin/env python3
"""Short-lived orchestrator for the unified managed-services control plane.

This module is intentionally not a daemon.  It owns mutation/reconciliation of
NAS-managed service definitions and dispatches to the existing Podman, Compose,
libvirt, firewalld, Authentik and Caddy adapters under the appliance-wide
operation lock.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import pathlib
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

import nas_managed_service as store
from nas_operation_journal import JournalError, OperationJournal
from nas_operation_lock import OperationBusyError, acquire_operation
import nas_service_authentik
import nas_service_caddy
import nas_service_firewall
import nas_service_runtime_compose
import nas_service_runtime_libvirt
import nas_service_runtime_podman

JOURNAL_PATH = pathlib.Path(
    os.environ.get(
        "NAS_MANAGED_SERVICE_JOURNAL",
        "/var/lib/nas-control/managed-services.transaction.json",
    )
)


class OrchestratorError(store.ManagedServiceError):
    pass


def _flatten_service(service_id: str, service: dict[str, Any], endpoints: dict[str, Any]) -> None:
    for endpoint_id, endpoint in (service.get("endpoints") or {}).items():
        key = f"{service_id}:{endpoint_id}"
        endpoints[key] = {
            "label": endpoint.get("label") or f"{service.get('label', service_id)}:{endpoint_id}",
            "serviceId": service_id,
            "endpointId": endpoint_id,
            "transport": endpoint.get("transport"),
            "targetService": endpoint.get("targetService"),
            "targetPort": endpoint.get("targetPort"),
            "exposure": copy.deepcopy(endpoint.get("exposure")),
            "auth": copy.deepcopy(endpoint.get("auth")),
            "portal": copy.deepcopy(endpoint.get("portal", service.get("portal", {}))),
            "available": bool(service.get("enabled", False)),
            "ownership": service.get("ownership", "runtime"),
        }


def effective_registry(
    builtin_path: pathlib.Path = store.BUILTIN_REGISTRY,
    store_path: pathlib.Path = store.STORE_PATH,
) -> dict[str, Any]:
    """Merge both legacy v1 and production v2 built-ins with runtime state."""
    try:
        builtin = json.loads(builtin_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        builtin = {"schemaVersion": 2, "services": {}}
    except (OSError, json.JSONDecodeError) as exc:
        raise OrchestratorError(f"Unable to load built-in service registry: {exc}") from exc

    runtime = store.load_store(store_path)
    services: dict[str, Any] = {}
    endpoints: dict[str, Any] = {}

    if builtin.get("schemaVersion") == 2 and isinstance(builtin.get("services"), dict):
        for service_id, service in builtin["services"].items():
            if not isinstance(service, dict):
                continue
            services[service_id] = copy.deepcopy(service)
            _flatten_service(service_id, service, endpoints)
    else:
        for endpoint_id, endpoint in (builtin.get("endpoints") or {}).items():
            if not isinstance(endpoint, dict):
                continue
            normalized = copy.deepcopy(endpoint)
            if "publicPath" in normalized and "exposure" not in normalized:
                normalized["exposure"] = {"type": "path", "value": normalized["publicPath"]}
            if "portal" not in normalized and normalized.get("linkKey"):
                normalized["portal"] = {
                    "visible": True,
                    "category": "Administration" if normalized.get("access") == "admin" else "Other",
                    "icon": normalized.get("linkKey", "box"),
                }
            endpoints[endpoint_id] = normalized

    for service_id, service in runtime.get("services", {}).items():
        services[service_id] = copy.deepcopy(service)
        _flatten_service(service_id, service, endpoints)

    effective = {
        "schemaVersion": store.SCHEMA_VERSION,
        "generation": int(runtime.get("generation", 1)),
        "services": services,
        "endpoints": endpoints,
    }
    _resolve_authentik_references(effective)
    return effective


def _authentik_get(path: str) -> dict[str, Any] | None:
    api = os.environ.get("NAS_AUTHENTIK_API", "http://127.0.0.1:9000/api/v3").rstrip("/")
    token = os.environ.get("NAS_AUTHENTIK_TOKEN", "")
    if not token:
        return None
    request = urllib.request.Request(
        f"{api}/{path.lstrip('/')}",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:  # nosec B310 - fixed local/configured Authentik API
            if response.status != 200:
                return None
            value = json.loads(response.read().decode("utf-8"))
            return value if isinstance(value, dict) else None
    except (OSError, urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError):
        return None


def _looks_stable_id(value: str) -> bool:
    import re

    return bool(re.fullmatch(r"(?:\d+|[0-9a-fA-F-]{36})", value))


def _resolve_authentik_references(effective: dict[str, Any]) -> None:
    """Keep stable IDs in source state while projecting request-time names.

    Authentik proxy headers expose group names and a stable user UID.  For group
    UUID/PK references we resolve the current name into the effective runtime
    projection.  Failure to resolve leaves the opaque ID in place, which fails
    closed at request time instead of granting access accidentally.
    """
    group_cache: dict[str, str | None] = {}
    user_cache: dict[str, str | None] = {}
    for endpoint in effective.get("endpoints", {}).values():
        auth = endpoint.get("auth")
        if not isinstance(auth, dict):
            continue
        groups = auth.get("groups") or []
        if isinstance(groups, list):
            resolved_groups: list[str] = []
            stable_groups: list[str] = []
            for raw in groups:
                value = str(raw)
                if _looks_stable_id(value):
                    stable_groups.append(value)
                    if value not in group_cache:
                        record = _authentik_get(f"core/groups/{urllib.parse.quote(value, safe='')}/")
                        group_cache[value] = str(record.get("name")) if record and record.get("name") else None
                    resolved_groups.append(group_cache[value] or value)
                else:
                    resolved_groups.append(value)
            auth["groups"] = resolved_groups
            if stable_groups:
                auth["groupIds"] = stable_groups
        users = auth.get("users") or []
        if isinstance(users, list):
            resolved_users: list[str] = []
            stable_users: list[str] = []
            for raw in users:
                value = str(raw)
                if _looks_stable_id(value):
                    stable_users.append(value)
                    if value not in user_cache:
                        record = _authentik_get(f"core/users/{urllib.parse.quote(value, safe='')}/")
                        user_cache[value] = str(record.get("username")) if record and record.get("username") else None
                    resolved_users.append(user_cache[value] or value)
                else:
                    resolved_users.append(value)
            auth["users"] = resolved_users
            if stable_users:
                auth["userIds"] = stable_users


def _atomic_json(path: pathlib.Path, value: dict[str, Any], mode: int = 0o644) -> None:
    from nas_operation_journal import atomic_write_json

    atomic_write_json(path, value, mode=mode)


def write_effective(effective: dict[str, Any] | None = None) -> dict[str, Any]:
    if effective is None:
        effective = effective_registry()
    _atomic_json(store.EFFECTIVE_PATH, effective, mode=0o644)
    return effective


def write_portal(effective: dict[str, Any] | None = None) -> dict[str, Any]:
    if effective is None:
        effective = effective_registry()
    portal = store.portal_projection(effective)
    _atomic_json(store.PORTAL_PATH, portal, mode=0o644)
    return portal


def _runtime_adapter(service: dict[str, Any]):
    runtime_type = (service.get("runtime") or {}).get("type")
    if runtime_type == "quadlet":
        return nas_service_runtime_podman
    if runtime_type == "compose":
        return nas_service_runtime_compose
    if runtime_type == "vm":
        return nas_service_runtime_libvirt
    if runtime_type in {"external", "native"}:
        return None
    raise OrchestratorError(f"Unsupported runtime type: {runtime_type!r}")


def plan_service(service_id: str, service: dict[str, Any]) -> dict[str, Any]:
    store.validate_service(service_id, service)
    runtime = _runtime_adapter(service)
    return {
        "service": service_id,
        "runtime": runtime.plan_podman(service_id, service)
        if runtime is nas_service_runtime_podman
        else runtime.plan_compose(service_id, service)
        if runtime is nas_service_runtime_compose
        else runtime.plan_libvirt(service_id, service)
        if runtime is nas_service_runtime_libvirt
        else {"actions": []},
        "firewall": nas_service_firewall.plan_firewall(service_id, service),
        "authentik": nas_service_authentik.plan_authentik(service_id, service),
    }


def apply_service(service_id: str, service: dict[str, Any]) -> dict[str, Any]:
    runtime = _runtime_adapter(service)
    results: dict[str, Any] = {}
    if runtime is nas_service_runtime_podman:
        results["runtime"] = runtime.apply_podman(service_id, service)
    elif runtime is nas_service_runtime_compose:
        results["runtime"] = runtime.apply_compose(service_id, service)
    elif runtime is nas_service_runtime_libvirt:
        results["runtime"] = runtime.apply_libvirt(service_id, service)
    else:
        results["runtime"] = {"actions": []}
    results["firewall"] = nas_service_firewall.apply_firewall(service_id, service)
    results["authentik"] = nas_service_authentik.apply_authentik(service_id, service)
    return results


def remove_service(service_id: str, service: dict[str, Any]) -> None:
    runtime = _runtime_adapter(service)
    nas_service_authentik.remove_authentik(service_id)
    nas_service_firewall.remove_firewall(service_id)
    if runtime is nas_service_runtime_podman:
        runtime.remove_podman(service_id)
    elif runtime is nas_service_runtime_compose:
        runtime.remove_compose(service_id)
    elif runtime is nas_service_runtime_libvirt:
        runtime.remove_libvirt(service_id)


def reconcile(*, apply_runtimes: bool = False) -> dict[str, Any]:
    state = store.load_store()
    applied: dict[str, Any] = {}
    if apply_runtimes:
        for service_id, service in state.get("services", {}).items():
            if service.get("enabled"):
                applied[service_id] = apply_service(service_id, service)
    effective = write_effective(effective_registry())
    caddy = nas_service_caddy.write_caddy_fragment(effective=effective)
    portal = write_portal(effective)
    return {"effective": effective, "portal": portal, "caddy": caddy, "applied": applied}


def _fingerprint(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _load_definition(path: str) -> dict[str, Any]:
    try:
        value = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise OrchestratorError(f"Unable to load service definition {path!r}: {exc}") from exc
    if not isinstance(value, dict):
        raise OrchestratorError("Service definition must be a JSON object")
    return value


def mutate(action: str, service_id: str, definition: dict[str, Any] | None = None) -> dict[str, Any]:
    with acquire_operation(f"managed-service-{action}", ("runtime", "network", "identity"), blocking=False):
        before = store.load_store()
        after = copy.deepcopy(before)
        services = after.setdefault("services", {})
        old_service = copy.deepcopy(services.get(service_id))
        if action in {"create", "adopt"}:
            if service_id in services:
                raise OrchestratorError(f"Service {service_id!r} already exists")
            if definition is None:
                raise OrchestratorError("Service definition is required")
            store.validate_service(service_id, definition)
            services[service_id] = definition
        elif action == "update":
            if service_id not in services:
                raise OrchestratorError(f"Unknown service {service_id!r}")
            if definition is None:
                raise OrchestratorError("Service definition is required")
            store.validate_service(service_id, definition)
            services[service_id] = definition
        elif action == "delete":
            if service_id not in services:
                raise OrchestratorError(f"Unknown service {service_id!r}")
            del services[service_id]
        else:
            raise OrchestratorError(f"Unsupported mutation {action!r}")

        journal = OperationJournal.open(
            JOURNAL_PATH,
            workflow="managed-service",
            fingerprint=_fingerprint({"action": action, "service": service_id, "after": after}),
            metadata={"action": action, "service": service_id},
        )
        try:
            journal.start_step("store")
            store.atomic_write_store(after)
            journal.complete_step("store")

            journal.start_step("runtime")
            if action == "delete" and old_service is not None:
                remove_service(service_id, old_service)
            elif action in {"create", "update", "adopt"}:
                apply_service(service_id, services[service_id])
            journal.complete_step("runtime")

            journal.start_step("projection")
            result = reconcile(apply_runtimes=False)
            journal.complete_step("projection")
            journal.complete({"service": service_id, "action": action})
            return result
        except Exception as exc:
            rollback_error: Exception | None = None
            try:
                store.atomic_write_store(before)
                if old_service is not None and action in {"update", "delete"}:
                    apply_service(service_id, old_service)
                elif old_service is None and action in {"create", "adopt"}:
                    try:
                        remove_service(service_id, definition or {})
                    except Exception:
                        pass
                reconcile(apply_runtimes=False)
            except Exception as rollback_exc:
                rollback_error = rollback_exc
            journal.fail(
                f"{exc}; rollback failed: {rollback_error}" if rollback_error else str(exc),
                manual_recovery=rollback_error is not None,
            )
            raise


def _runtime_lifecycle(action: str, service_id: str) -> dict[str, Any]:
    state = store.load_store()
    service = state.get("services", {}).get(service_id)
    if not isinstance(service, dict):
        raise OrchestratorError(f"Unknown service {service_id!r}")
    runtime_type = (service.get("runtime") or {}).get("type")
    import subprocess

    if runtime_type == "quadlet":
        unit = f"{service_id}.service"
        subprocess.run(["systemctl", action, unit], check=True)
    elif runtime_type == "compose":
        source = str(service["runtime"]["source"])
        provider_env = dict(os.environ)
        provider_env["COMPOSE_PROJECT_NAME"] = service_id
        subprocess.run(["podman", "compose", "-f", source, action], check=True, env=provider_env)
    elif runtime_type == "vm":
        command = {"start": "start", "stop": "shutdown", "restart": "reboot"}[action]
        subprocess.run(["virsh", command, service_id], check=True)
    elif runtime_type not in {"external", "native"}:
        raise OrchestratorError(f"Unsupported runtime type {runtime_type!r}")
    return reconcile(apply_runtimes=False)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nas-managed-service")
    sub = parser.add_subparsers(dest="command", required=True)
    reconcile_parser = sub.add_parser("reconcile")
    reconcile_parser.add_argument("--apply-runtimes", action="store_true")
    sub.add_parser("validate")
    show = sub.add_parser("show")
    show.add_argument("--json", action="store_true")
    plan = sub.add_parser("plan")
    plan.add_argument("service_id")
    plan.add_argument("--file", required=True)
    for name in ("create", "update", "adopt"):
        command = sub.add_parser(name)
        command.add_argument("service_id")
        command.add_argument("--file", required=True)
    delete = sub.add_parser("delete")
    delete.add_argument("service_id")
    for name in ("start", "stop", "restart"):
        command = sub.add_parser(name)
        command.add_argument("service_id")
    export = sub.add_parser("export")
    export.add_argument("--output")
    import_parser = sub.add_parser("import")
    import_parser.add_argument("--file", required=True)
    args = parser.parse_args(argv)

    try:
        if args.command == "reconcile":
            result = reconcile(apply_runtimes=args.apply_runtimes)
        elif args.command == "validate":
            store.load_store()
            result = effective_registry()
        elif args.command == "show":
            result = effective_registry()
        elif args.command == "plan":
            result = plan_service(args.service_id, _load_definition(args.file))
        elif args.command in {"create", "update", "adopt"}:
            result = mutate(args.command, args.service_id, _load_definition(args.file))
        elif args.command == "delete":
            result = mutate("delete", args.service_id)
        elif args.command in {"start", "stop", "restart"}:
            with acquire_operation(f"managed-service-{args.command}", ("runtime",), blocking=False):
                result = _runtime_lifecycle(args.command, args.service_id)
        elif args.command == "export":
            result = store.load_store()
            if args.output:
                _atomic_json(pathlib.Path(args.output), result, mode=0o600)
        elif args.command == "import":
            imported = _load_definition(args.file)
            if imported.get("schemaVersion") != store.SCHEMA_VERSION or not isinstance(imported.get("services"), dict):
                raise OrchestratorError("Import must be a managed-services schemaVersion 2 document")
            with acquire_operation("managed-service-import", ("runtime", "network", "identity"), blocking=False):
                store.atomic_write_store(imported)
                result = reconcile(apply_runtimes=True)
        else:
            parser.error("unknown command")
            return 2
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (store.ManagedServiceError, OrchestratorError, OperationBusyError, JournalError, OSError) as exc:
        print(f"nas-managed-service: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
