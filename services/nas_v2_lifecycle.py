#!/usr/bin/env python3
"""Generic dependency, readiness, job, daemon and session lifecycle for V2."""

from __future__ import annotations

import json
import os
import pathlib
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from typing import Any

import nas_v2_runtime_ops as runtime_ops

STATE_PATH = pathlib.Path(os.environ.get("NAS_V2_LIFECYCLE_STATE", "/run/nas-control/v2-lifecycle.json"))


class V2LifecycleError(RuntimeError):
    pass


def _read_state(path: pathlib.Path = STATE_PATH) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"schemaVersion": 1, "services": {}, "sessions": {}}
    except (OSError, json.JSONDecodeError) as exc:
        raise V2LifecycleError(f"Unable to read lifecycle state {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise V2LifecycleError("Lifecycle state must be an object")
    value.setdefault("schemaVersion", 1)
    value.setdefault("services", {})
    value.setdefault("sessions", {})
    return value


def _write_state(value: dict[str, Any], path: pathlib.Path = STATE_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = pathlib.Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _probe_ready(probe: dict[str, Any]) -> bool:
    probe_type = probe["type"]
    if probe_type == "systemd":
        return subprocess.run(
            ["systemctl", "is-active", "--quiet", probe["unit"]],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode == 0
    if probe_type == "tcp":
        try:
            with socket.create_connection((probe.get("host", "127.0.0.1"), int(probe["port"])), timeout=1):
                return True
        except OSError:
            return False
    if probe_type == "http":
        try:
            request = urllib.request.Request(probe["url"], method="GET", headers={"User-Agent": "nixos-nas-v2/1"})
            with urllib.request.urlopen(request, timeout=2) as response:
                status = int(response.status)
                return int(probe.get("acceptStatusMin", 200)) <= status <= int(probe.get("acceptStatusMax", 399))
        except (OSError, urllib.error.URLError, TimeoutError):
            return False
    if probe_type == "path":
        return pathlib.Path(probe["path"]).exists()
    return False


def wait_ready(service_id: str, service: dict[str, Any]) -> None:
    readiness = service.get("readiness")
    if readiness is None:
        return
    probes = readiness.get("probes", [])
    deadline = time.monotonic() + int(readiness.get("timeoutSeconds", 60))
    interval = int(readiness.get("intervalMilliseconds", 500)) / 1000.0
    while True:
        if probes and all(_probe_ready(probe) for probe in probes):
            return
        if time.monotonic() >= deadline:
            raise V2LifecycleError(f"Service {service_id!r} did not become ready before its readiness timeout")
        time.sleep(interval)


def dependency_order(service_id: str, document: dict[str, Any]) -> list[str]:
    services = document["services"]
    if service_id not in services:
        raise V2LifecycleError(f"Unknown V2 service {service_id!r}")
    visiting: set[str] = set()
    visited: set[str] = set()
    ordered: list[str] = []

    def visit(current: str) -> None:
        if current in visited:
            return
        if current in visiting:
            raise V2LifecycleError(f"Dependency cycle encountered while activating {service_id!r}")
        visiting.add(current)
        for dependency in services[current].get("dependencies", []):
            visit(dependency["service"])
        visiting.remove(current)
        visited.add(current)
        ordered.append(current)

    visit(service_id)
    return ordered


def _mark_used(service_id: str, service: dict[str, Any], state: dict[str, Any], now: float | None = None) -> None:
    workload = service["workload"]
    if workload["kind"] == "daemon" and workload.get("activation") == "on-demand":
        state["services"][service_id] = {"lastUse": float(time.time() if now is None else now)}


def _active_session_services(state: dict[str, Any]) -> set[str]:
    return {
        str(session.get("service"))
        for session in state.get("sessions", {}).values()
        if isinstance(session, dict) and isinstance(session.get("service"), str)
    }


def _service_active(service_id: str, service: dict[str, Any], state: dict[str, Any]) -> bool:
    workload = service["workload"]
    if workload["kind"] == "session":
        return service_id in _active_session_services(state)
    if workload["kind"] != "daemon" or not service.get("enabled"):
        return False
    if workload.get("activation") == "persistent":
        return True
    return service_id in state.get("services", {})


def _active_dependents(service_id: str, document: dict[str, Any], state: dict[str, Any]) -> list[str]:
    return sorted(
        candidate_id
        for candidate_id, candidate in document["services"].items()
        if candidate_id != service_id
        and _service_active(candidate_id, candidate, state)
        and any(item["service"] == service_id for item in candidate.get("dependencies", []))
    )


def _activate_dependency(
    parent_id: str,
    dependency: dict[str, Any],
    document: dict[str, Any],
    state: dict[str, Any],
    results: dict[str, Any],
    active: set[str],
) -> None:
    target_id = dependency["service"]
    target = document["services"][target_id]
    condition = dependency.get("condition", "ready")
    if condition == "completed":
        if target["workload"]["kind"] != "job":
            raise V2LifecycleError(f"Service {parent_id}: completed dependency {target_id!r} is not a job")
        results[target_id] = run_job(target_id, document)
        return
    if target["workload"]["kind"] == "session":
        raise V2LifecycleError(f"Service {parent_id}: cannot automatically instantiate session dependency {target_id!r}")
    _activate_service(target_id, document, state, results, active)
    if condition == "ready":
        wait_ready(target_id, target)


def _activate_service(
    service_id: str,
    document: dict[str, Any],
    state: dict[str, Any],
    results: dict[str, Any],
    active: set[str],
) -> None:
    if service_id in active:
        return
    service = document["services"][service_id]
    if not service.get("enabled"):
        raise V2LifecycleError(f"Service {service_id!r} is disabled")
    for dependency in service.get("dependencies", []):
        _activate_dependency(service_id, dependency, document, state, results, active)
    kind = service["workload"]["kind"]
    if kind == "job":
        results[service_id] = runtime_ops.run_job(service_id, service)
    elif kind == "session":
        raise V2LifecycleError(f"Service {service_id!r} is a session workload; use session-begin")
    else:
        results[service_id] = runtime_ops.start(service_id, service)
        _mark_used(service_id, service, state)
    active.add(service_id)


def run_job(service_id: str, document: dict[str, Any]) -> dict[str, Any]:
    service = document["services"].get(service_id)
    if not isinstance(service, dict):
        raise V2LifecycleError(f"Unknown V2 service {service_id!r}")
    if not service.get("enabled"):
        raise V2LifecycleError(f"Service {service_id!r} is disabled")
    if service["workload"]["kind"] != "job":
        raise V2LifecycleError(f"Service {service_id!r} is not a job")
    state = _read_state()
    dependencies: dict[str, Any] = {}
    active: set[str] = set()
    for dependency in service.get("dependencies", []):
        _activate_dependency(service_id, dependency, document, state, dependencies, active)
    result = runtime_ops.run_job(service_id, service)
    _write_state(state)
    return {"service": service_id, "dependencies": dependencies, "runtime": result}


def start_service(service_id: str, document: dict[str, Any]) -> dict[str, Any]:
    service = document["services"].get(service_id)
    if not isinstance(service, dict):
        raise V2LifecycleError(f"Unknown V2 service {service_id!r}")
    if service["workload"]["kind"] == "job":
        return run_job(service_id, document)
    if service["workload"]["kind"] == "session":
        raise V2LifecycleError(f"Service {service_id!r} is a session workload; use session-begin")
    state = _read_state()
    results: dict[str, Any] = {}
    _activate_service(service_id, document, state, results, set())
    _write_state(state)
    return {"service": service_id, "started": results}


def touch_service(service_id: str, document: dict[str, Any]) -> dict[str, Any]:
    if service_id not in document["services"]:
        raise V2LifecycleError(f"Unknown V2 service {service_id!r}")
    state = _read_state()
    touched: list[str] = []
    for current in dependency_order(service_id, document):
        service = document["services"][current]
        before = dict(state["services"].get(current, {}))
        _mark_used(current, service, state)
        if state["services"].get(current) != before:
            touched.append(current)
    _write_state(state)
    return {"service": service_id, "touched": touched}


def session_begin(service_id: str, session_id: str, document: dict[str, Any]) -> dict[str, Any]:
    service = document["services"].get(service_id)
    if not isinstance(service, dict) or service["workload"]["kind"] != "session":
        raise V2LifecycleError(f"Service {service_id!r} is not a session workload")
    if not service.get("enabled"):
        raise V2LifecycleError(f"Service {service_id!r} is disabled")
    state = _read_state()
    if session_id in state["sessions"]:
        raise V2LifecycleError(f"Session {session_id!r} already exists")
    dependencies: dict[str, Any] = {}
    active: set[str] = set()
    for dependency in service.get("dependencies", []):
        _activate_dependency(service_id, dependency, document, state, dependencies, active)
    runtime_result = runtime_ops.begin_session(service_id, session_id, service)
    now = time.time()
    state["sessions"][session_id] = {"service": service_id, "lastUse": now}
    for dependency in service.get("dependencies", []):
        target_id = dependency["service"]
        _mark_used(target_id, document["services"][target_id], state, now)
    _write_state(state)
    return {
        "service": service_id,
        "session": session_id,
        "dependencies": dependencies,
        "runtime": runtime_result,
    }


def session_touch(session_id: str, document: dict[str, Any]) -> dict[str, Any]:
    state = _read_state()
    session = state["sessions"].get(session_id)
    if not isinstance(session, dict):
        raise V2LifecycleError(f"Unknown session {session_id!r}")
    service_id = session["service"]
    service = document["services"].get(service_id)
    if not isinstance(service, dict):
        raise V2LifecycleError(f"Session {session_id!r} references unknown service {service_id!r}")
    now = time.time()
    session["lastUse"] = now
    for current in dependency_order(service_id, document):
        if current == service_id:
            continue
        _mark_used(current, document["services"][current], state, now)
    _write_state(state)
    return {"session": session_id, "service": service_id, "lastUse": now}


def session_end(session_id: str, document: dict[str, Any]) -> dict[str, Any]:
    state = _read_state()
    session = state["sessions"].pop(session_id, None)
    if not isinstance(session, dict):
        raise V2LifecycleError(f"Unknown session {session_id!r}")
    service_id = session["service"]
    service = document["services"].get(service_id)
    if not isinstance(service, dict):
        raise V2LifecycleError(f"Session {session_id!r} references unknown service {service_id!r}")
    remaining = service_id in _active_session_services(state)
    runtime = None if remaining else runtime_ops.end_session(service_id, session_id, service)
    _write_state(state)
    return {"session": session_id, "service": service_id, "ended": True, "runtime": runtime}


def stop_service(service_id: str, document: dict[str, Any]) -> dict[str, Any]:
    service = document["services"].get(service_id)
    if not isinstance(service, dict):
        raise V2LifecycleError(f"Unknown V2 service {service_id!r}")
    if not service.get("managed", True):
        return {"service": service_id, "stopped": False, "reason": "externally-managed"}
    state = _read_state()
    if service_id in _active_session_services(state):
        raise V2LifecycleError(f"Service {service_id!r} still has active sessions")
    dependents = _active_dependents(service_id, document, state)
    if dependents:
        raise V2LifecycleError(f"Service {service_id!r} is still required by active services {dependents}")
    result = runtime_ops.stop(service_id, service)
    state["services"].pop(service_id, None)
    _write_state(state)
    return {"service": service_id, "stopped": True, "runtime": result}


def _protected_dependencies(document: dict[str, Any], state: dict[str, Any]) -> set[str]:
    protected: set[str] = set()
    for service_id, service in document["services"].items():
        if not _service_active(service_id, service, state):
            continue
        for dependency in service.get("dependencies", []):
            protected.add(dependency["service"])
    return protected


def reap(document: dict[str, Any], *, now: float | None = None) -> dict[str, Any]:
    current = float(time.time() if now is None else now)
    state = _read_state()
    expired_sessions: list[str] = []
    stopped: list[str] = []

    for session_id, session in list(state["sessions"].items()):
        service_id = session.get("service")
        service = document["services"].get(service_id)
        if not isinstance(service, dict):
            state["sessions"].pop(session_id, None)
            continue
        idle = int(service["workload"].get("leaseIdleSeconds", 900))
        if current - float(session.get("lastUse", 0)) < idle:
            continue
        state["sessions"].pop(session_id, None)
        expired_sessions.append(session_id)
        if service_id not in _active_session_services(state):
            runtime_ops.end_session(service_id, session_id, service)

    protected = _protected_dependencies(document, state)
    for service_id, lease in list(state["services"].items()):
        service = document["services"].get(service_id)
        if not isinstance(service, dict):
            state["services"].pop(service_id, None)
            continue
        workload = service["workload"]
        if workload["kind"] != "daemon" or workload.get("activation") != "on-demand":
            state["services"].pop(service_id, None)
            continue
        if service_id in protected:
            continue
        idle = int(workload["idleSeconds"])
        if current - float(lease.get("lastUse", 0)) < idle:
            continue
        runtime_ops.stop(service_id, service)
        state["services"].pop(service_id, None)
        stopped.append(service_id)

    _write_state(state)
    return {"stopped": sorted(stopped), "expiredSessions": sorted(expired_sessions)}
