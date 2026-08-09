#!/usr/bin/env python3
"""Dependency-aware lifecycle layer for Managed Services V2.

This module deliberately delegates native runtime execution to
``nas_managed_service_v2``. It only owns graph validation and lifecycle ordering:
required services start before dependents, on-demand dependency chains are
touched together, and idle dependencies are not reaped while an active
dependent still needs them.
"""

from __future__ import annotations

import json
import time
from typing import Any

import nas_managed_service_v2 as _v2
from nas_managed_resources import ManagedResourceError

_BASE_EFFECTIVE_REGISTRY = _v2.effective_registry


def _dependencies(service_id: str, service: dict[str, Any]) -> list[str]:
    raw = service.get("dependsOn", [])
    if not isinstance(raw, list) or any(not isinstance(item, str) for item in raw):
        raise ManagedResourceError(f"Service {service_id}: dependsOn must be an array of service IDs")
    if len(raw) != len(set(raw)):
        raise ManagedResourceError(f"Service {service_id}: dependsOn contains duplicates")
    if service_id in raw:
        raise ManagedResourceError(f"Service {service_id}: cannot depend on itself")
    return raw


def _validate_dependency_graph(services: dict[str, Any]) -> None:
    for service_id, service in services.items():
        if not isinstance(service, dict):
            raise ManagedResourceError(f"Service {service_id!r} must be an object")
        for dependency in _dependencies(service_id, service):
            if dependency not in services:
                raise ManagedResourceError(f"Service {service_id}: unknown dependency {dependency!r}")

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(service_id: str, trail: list[str]) -> None:
        if service_id in visited:
            return
        if service_id in visiting:
            start = trail.index(service_id) if service_id in trail else 0
            cycle = trail[start:] + [service_id]
            raise ManagedResourceError(f"Managed service dependency cycle: {' -> '.join(cycle)}")
        visiting.add(service_id)
        trail.append(service_id)
        service = services[service_id]
        for dependency in _dependencies(service_id, service):
            visit(dependency, trail)
        trail.pop()
        visiting.remove(service_id)
        visited.add(service_id)

    for service_id in sorted(services):
        visit(service_id, [])


def effective_registry(*args: Any, **kwargs: Any) -> dict[str, Any]:
    effective = _BASE_EFFECTIVE_REGISTRY(*args, **kwargs)
    services = effective.get("services") or {}
    if not isinstance(services, dict):
        raise ManagedResourceError("Effective managed service registry services must be an object")
    _validate_dependency_graph(services)
    return effective


def dependency_order(service_id: str, services: dict[str, Any]) -> list[str]:
    if service_id not in services:
        raise ManagedResourceError(f"Unknown managed service {service_id!r}")
    _validate_dependency_graph(services)
    ordered: list[str] = []
    seen: set[str] = set()

    def visit(current: str) -> None:
        if current in seen:
            return
        service = services[current]
        for dependency in _dependencies(current, service):
            visit(dependency)
        seen.add(current)
        ordered.append(current)

    visit(service_id)
    return ordered


def _require_startable(service_id: str, service: dict[str, Any], *, dependency: bool) -> None:
    if not service.get("enabled"):
        role = "Dependency" if dependency else "Service"
        raise ManagedResourceError(f"{role} {service_id!r} is disabled")
    mode = (service.get("lifecycle") or {}).get("mode")
    if mode == "session":
        role = "Dependency" if dependency else "Service"
        raise ManagedResourceError(f"{role} {service_id!r} is session-scoped and cannot be auto-started")


def _touch_chain(ordered: list[str], services: dict[str, Any], *, now: int | None = None) -> dict[str, Any]:
    current = int(time.time()) if now is None else int(now)
    state = _v2._read_lifecycle_state()
    touched: dict[str, Any] = {}
    for service_id in ordered:
        service = services[service_id]
        if not _v2._lifecycle_owned_by_v2(service):
            continue
        if (service.get("lifecycle") or {}).get("mode") != "on-demand":
            continue
        record = state["services"].setdefault(service_id, {})
        record["lastAccess"] = current
        touched[service_id] = dict(record)
    if touched:
        _v2._write_lifecycle_state(state)
    return touched


def touch_service(service_id: str, *, now: int | None = None) -> dict[str, Any]:
    effective = effective_registry()
    services = effective["services"]
    service = services.get(service_id)
    if not isinstance(service, dict):
        raise ManagedResourceError(f"Unknown managed service {service_id!r}")
    if not _v2._lifecycle_owned_by_v2(service):
        raise ManagedResourceError(f"Service {service_id!r} is not lifecycle-owned by V2")
    if not service.get("enabled"):
        raise ManagedResourceError(f"Service {service_id!r} is disabled")
    if (service.get("lifecycle") or {}).get("mode") != "on-demand":
        raise ManagedResourceError(f"Service {service_id!r} is not on-demand")
    ordered = dependency_order(service_id, services)
    touched = _touch_chain(ordered, services, now=now)
    return touched.get(service_id, {})


def start_service(service_id: str) -> dict[str, Any]:
    effective = effective_registry()
    services = effective["services"]
    service = services.get(service_id)
    if not isinstance(service, dict):
        raise ManagedResourceError(f"Unknown managed service {service_id!r}")
    if not _v2._lifecycle_owned_by_v2(service):
        raise ManagedResourceError(f"Service {service_id!r} is not lifecycle-owned by V2")

    ordered = dependency_order(service_id, services)
    actions: list[dict[str, Any]] = []
    for current in ordered:
        current_service = services[current]
        _require_startable(current, current_service, dependency=current != service_id)
        result = _v2._apply_runtime(current, current_service, enabled=True)
        actions.append(
            {
                "service": current,
                "ownership": current_service.get("ownership", "runtime"),
                "result": result,
            }
        )
    touched = _touch_chain(ordered, services)
    return {"service": service_id, "order": ordered, "actions": actions, "touched": sorted(touched)}


def stop_service(service_id: str) -> dict[str, Any]:
    effective = effective_registry()
    service = effective.get("services", {}).get(service_id)
    if not isinstance(service, dict):
        raise ManagedResourceError(f"Unknown managed service {service_id!r}")
    if not _v2._lifecycle_owned_by_v2(service):
        raise ManagedResourceError(f"Service {service_id!r} is not lifecycle-owned by V2")
    result = _v2._apply_runtime(service_id, service, enabled=False)
    state = _v2._read_lifecycle_state()
    state.get("services", {}).pop(service_id, None)
    _v2._write_lifecycle_state(state)
    return result


def _transitively_depends_on(candidate: str, dependency: str, services: dict[str, Any]) -> bool:
    seen: set[str] = set()
    pending = list(_dependencies(candidate, services[candidate]))
    while pending:
        current = pending.pop()
        if current == dependency:
            return True
        if current in seen:
            continue
        seen.add(current)
        pending.extend(_dependencies(current, services[current]))
    return False


def _dependent_active(
    dependent_id: str,
    dependent: dict[str, Any],
    state: dict[str, Any],
    current: int,
) -> bool:
    if not dependent.get("enabled"):
        return False
    mode = (dependent.get("lifecycle") or {}).get("mode")
    if mode == "persistent":
        return True
    if mode == "session":
        # Session launchers are responsible for explicit dependency lifetime.
        # Without a session lease in the generic lifecycle state, fail safe and
        # do not reap a dependency merely because the generic timer fired.
        return True
    if mode != "on-demand":
        return False
    last_access = (state.get("services", {}).get(dependent_id) or {}).get("lastAccess")
    idle_seconds = (dependent.get("lifecycle") or {}).get("idleSeconds")
    return isinstance(last_access, int) and isinstance(idle_seconds, int) and current - last_access < idle_seconds


def _needed_by_active_dependent(
    service_id: str,
    services: dict[str, Any],
    state: dict[str, Any],
    current: int,
) -> bool:
    for dependent_id, dependent in services.items():
        if dependent_id == service_id or not isinstance(dependent, dict):
            continue
        if not _transitively_depends_on(dependent_id, service_id, services):
            continue
        if _dependent_active(dependent_id, dependent, state, current):
            return True
    return False


def reconcile_lifecycle(effective: dict[str, Any] | None = None) -> dict[str, Any]:
    if effective is None:
        effective = effective_registry()
    services = effective.get("services") or {}
    _validate_dependency_graph(services)
    actions: list[dict[str, Any]] = []
    started: set[str] = set()

    for service_id, service in sorted(services.items()):
        if not isinstance(service, dict) or not _v2._lifecycle_owned_by_v2(service):
            continue
        mode = (service.get("lifecycle") or {}).get("mode")
        if not service.get("enabled"):
            actions.append(
                {
                    "service": service_id,
                    "mode": mode,
                    "enabled": False,
                    "result": _v2._apply_runtime(service_id, service, enabled=False),
                }
            )
            continue
        if mode == "session":
            actions.append(
                {
                    "service": service_id,
                    "mode": mode,
                    "enabled": True,
                    "result": _v2._apply_runtime(service_id, service, enabled=False),
                }
            )
            continue
        if mode != "persistent":
            continue
        for current in dependency_order(service_id, services):
            if current in started:
                continue
            current_service = services[current]
            _require_startable(current, current_service, dependency=current != service_id)
            result = _v2._apply_runtime(current, current_service, enabled=True)
            actions.append(
                {
                    "service": current,
                    "requestedBy": service_id,
                    "mode": (current_service.get("lifecycle") or {}).get("mode"),
                    "enabled": True,
                    "result": result,
                }
            )
            started.add(current)
    return {"actions": actions}


def reap_lifecycle(*, now: int | None = None) -> dict[str, Any]:
    current = int(time.time()) if now is None else int(now)
    effective = effective_registry()
    services = effective.get("services") or {}
    state = _v2._read_lifecycle_state()
    stopped: list[str] = []
    retained: list[str] = []
    for service_id, service in sorted(services.items()):
        if not isinstance(service, dict) or not service.get("enabled") or not _v2._lifecycle_owned_by_v2(service):
            continue
        lifecycle = service.get("lifecycle") or {}
        if lifecycle.get("mode") != "on-demand":
            continue
        record = state.get("services", {}).get(service_id, {})
        last_access = record.get("lastAccess")
        if not isinstance(last_access, int) or current - last_access < int(lifecycle["idleSeconds"]):
            continue
        if _needed_by_active_dependent(service_id, services, state, current):
            retained.append(service_id)
            continue
        _v2._apply_runtime(service_id, service, enabled=False)
        stopped.append(service_id)
        state["services"].pop(service_id, None)
    if stopped:
        _v2._write_lifecycle_state(state)
    return {"stopped": stopped, "retainedForDependents": retained}


def _install() -> None:
    _v2.effective_registry = effective_registry
    _v2.start_service = start_service
    _v2.stop_service = stop_service
    _v2.touch_service = touch_service
    _v2.reconcile_lifecycle = reconcile_lifecycle
    _v2.reap_lifecycle = reap_lifecycle


def main(argv: list[str] | None = None) -> int:
    _install()
    return _v2.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
