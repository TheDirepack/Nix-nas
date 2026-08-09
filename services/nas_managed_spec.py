#!/usr/bin/env python3
"""Canonical loader, normalizer, and semantic validator for Managed Services V2.

Application names are deliberately absent. This module turns YAML/JSON desired
state into one deterministic document consumed by every V2 engine/projection.
"""

from __future__ import annotations

import copy
import json
import os
import pathlib
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError


DEFAULT_SPEC_PATH = pathlib.Path(os.environ.get("NAS_MANAGED_SPEC", "/var/lib/nas-control/services.yaml"))
DEFAULT_SCHEMA_PATH = pathlib.Path(
    os.environ.get("NAS_MANAGED_SPEC_SCHEMA", "/etc/nas-control/managed-services-v3.schema.json")
)
ID_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")


class ManagedSpecError(RuntimeError):
    """Invalid V2 desired state."""


def _json_path(parts: Any) -> str:
    rendered = "$"
    for part in parts:
        if isinstance(part, int):
            rendered += f"[{part}]"
        else:
            rendered += f".{part}"
    return rendered


def _load_schema(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManagedSpecError(f"Unable to read V2 JSON Schema {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ManagedSpecError("V2 JSON Schema must be an object")
    try:
        Draft202012Validator.check_schema(value)
    except SchemaError as exc:
        raise ManagedSpecError(f"Invalid V2 JSON Schema: {exc.message}") from exc
    return value


def parse_yaml(path: pathlib.Path) -> dict[str, Any]:
    yaml = YAML(typ="safe", pure=True)
    yaml.version = (1, 2)
    yaml.allow_duplicate_keys = False
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = yaml.load(handle)
    except (OSError, YAMLError) as exc:
        mark = getattr(exc, "problem_mark", None)
        location = f" at line {mark.line + 1}, column {mark.column + 1}" if mark is not None else ""
        raise ManagedSpecError(f"Unable to parse V2 YAML {path}{location}: {exc}") from exc
    if value is None:
        value = {"schemaVersion": 3, "services": {}}
    if not isinstance(value, dict):
        raise ManagedSpecError("V2 desired state must be a mapping/object")
    return value


def validate_schema(document: dict[str, Any], schema: dict[str, Any]) -> None:
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(document), key=lambda error: list(error.absolute_path))
    if not errors:
        return
    details = []
    for error in errors[:12]:
        details.append(f"{_json_path(error.absolute_path)}: {error.message}")
    if len(errors) > len(details):
        details.append(f"... and {len(errors) - len(details)} more validation error(s)")
    raise ManagedSpecError("V2 schema validation failed:\n" + "\n".join(details))


def _network_defaults(policy: dict[str, Any]) -> None:
    policy.setdefault("mode", "host")
    policy.setdefault("outboundDefault", "allow")
    policy.setdefault("lanAccess", False)
    policy.setdefault("allowedHostPorts", [])
    policy.setdefault("allowedEgress", [])


def _readiness_defaults(readiness: dict[str, Any]) -> None:
    readiness.setdefault("timeoutSeconds", 60)
    readiness.setdefault("intervalMilliseconds", 500)
    for probe in readiness.get("probes", []):
        if probe.get("type") == "tcp":
            probe.setdefault("host", "127.0.0.1")
        elif probe.get("type") == "http":
            probe.setdefault("acceptStatusMin", 200)
            probe.setdefault("acceptStatusMax", 399)


def _normalize_service(service_id: str, service: dict[str, Any]) -> None:
    service.setdefault("managed", True)
    service.setdefault("principal", f"application:{service_id}")
    service.setdefault("dependencies", [])
    service.setdefault("requiresCapabilities", [])
    service.setdefault("resources", {})
    service.setdefault("sandbox", {})
    service.setdefault("storage", [])
    service.setdefault("credentials", [])
    service.setdefault("sessionInputs", {})
    service.setdefault("endpoints", {})

    workload = service["workload"]
    if workload["kind"] == "job":
        workload.setdefault("schedules", [])
    elif workload["kind"] == "session":
        workload.setdefault("leaseIdleSeconds", 900)

    resources = service["resources"]
    resources.setdefault("accelerators", [])
    for accelerator in resources["accelerators"]:
        accelerator.setdefault("required", False)
        accelerator.setdefault("mode", "shared")
        if "device" not in accelerator:
            accelerator.setdefault("vendor", "any")
            accelerator.setdefault("quantity", 1)

    sandbox = service["sandbox"]
    sandbox.setdefault("profile", "strict")
    sandbox.setdefault("readOnlyRoot", True)
    sandbox.setdefault("writablePaths", [])
    sandbox.setdefault("tmpfs", [])
    sandbox.setdefault("addLinuxCapabilities", [])
    sandbox.setdefault("dropAllLinuxCapabilities", True)
    for tmpfs in sandbox["tmpfs"]:
        tmpfs.setdefault("noexec", True)
        tmpfs.setdefault("nodev", True)
        tmpfs.setdefault("nosuid", True)

    for dependency in service["dependencies"]:
        dependency.setdefault("condition", "ready")
    for attachment in service["storage"]:
        attachment.setdefault("access", "read")
    for input_spec in service["sessionInputs"].values():
        input_spec.setdefault("allowSubpath", True)
        input_spec.setdefault("access", "read")

    runtime = service["runtime"]
    if runtime["type"] == "exec":
        exec_spec = runtime["exec"]
        exec_spec.setdefault("restart", "on-failure")
        exec_spec.setdefault("restartSeconds", 3)
        exec_spec.setdefault("timeoutStopSeconds", 30)
        exec_spec.setdefault("environment", {})
        exec_spec.setdefault("identity", {"mode": "dynamic"})
    elif runtime["type"] == "oci":
        runtime.setdefault("command", [])
        runtime.setdefault("pull", "missing")

    if "readiness" in service:
        _readiness_defaults(service["readiness"])
    if "network" in service:
        _network_defaults(service["network"])

    for endpoint in service["endpoints"].values():
        endpoint.setdefault("priority", 0)
        endpoint.setdefault("portal", {})
        endpoint["portal"].setdefault("visible", False)
        target = endpoint["target"]
        if target["type"] in {"http", "https", "tcp", "udp"}:
            target.setdefault("host", "127.0.0.1")
        exposure = endpoint["exposure"]
        if exposure["type"] == "port":
            exposure.setdefault("protocol", "tcp")


def normalize(document: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(document)
    result.setdefault("generation", 1)
    result.setdefault("storageResources", {})
    result.setdefault("networkProfiles", {})
    result.setdefault("credentials", {})
    for resource in result["storageResources"].values():
        resource.setdefault("scope", "system")
        resource["backup"].setdefault("consistency", "filesystem")
        resource.setdefault("fileBrowser", {})
        resource["fileBrowser"].setdefault("visible", True)
    for profile in result["networkProfiles"].values():
        _network_defaults(profile)
    for credential in result["credentials"].values():
        credential.setdefault("required", True)
    for service_id, service in result["services"].items():
        _normalize_service(service_id, service)
    return result


def _safe_path(value: str, *, context: str) -> None:
    path = pathlib.PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts or any(character in value for character in ("\x00", "\n", "\r")):
        raise ManagedSpecError(f"{context} contains an unsafe path: {value!r}")


def _validate_graph(services: dict[str, dict[str, Any]]) -> None:
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(service_id: str, trail: list[str]) -> None:
        if service_id in visited:
            return
        if service_id in visiting:
            start = trail.index(service_id) if service_id in trail else 0
            cycle = trail[start:] + [service_id]
            raise ManagedSpecError(f"V2 dependency cycle: {' -> '.join(cycle)}")
        visiting.add(service_id)
        trail.append(service_id)
        for dependency in services[service_id]["dependencies"]:
            visit(dependency["service"], trail)
        trail.pop()
        visiting.remove(service_id)
        visited.add(service_id)

    for service_id in sorted(services):
        visit(service_id, [])


def semantic_validate(document: dict[str, Any], *, platform_capabilities: set[str] | None = None) -> None:
    resources = document["storageResources"]
    credentials = document["credentials"]
    profiles = document["networkProfiles"]
    services = document["services"]

    for resource_id, resource in resources.items():
        _safe_path(resource["path"], context=f"storage resource {resource_id}")
        scope = resource["scope"]
        template = resource.get("pathTemplate")
        if scope == "user" and (not isinstance(template, str) or "{user}" not in template):
            raise ManagedSpecError(f"Storage resource {resource_id}: user scope requires pathTemplate containing {{user}}")
        if scope == "instance" and (not isinstance(template, str) or "{instance}" not in template):
            raise ManagedSpecError(
                f"Storage resource {resource_id}: instance scope requires pathTemplate containing {{instance}}"
            )
        if isinstance(template, str):
            _safe_path(template, context=f"storage resource {resource_id} pathTemplate")

    for credential_id, credential in credentials.items():
        _safe_path(credential["path"], context=f"credential {credential_id}")

    for service_id, service in services.items():
        if service["principal"] != f"application:{service_id}":
            raise ManagedSpecError(f"Service {service_id}: principal must be application:{service_id}")
        if not service["managed"] and service["workload"]["kind"] == "session":
            raise ManagedSpecError(f"Service {service_id}: externally managed services cannot be session workloads")
        if service.get("networkProfile") is not None and service["networkProfile"] not in profiles:
            raise ManagedSpecError(f"Service {service_id}: unknown network profile {service['networkProfile']!r}")
        if platform_capabilities is not None:
            missing = sorted(set(service["requiresCapabilities"]) - platform_capabilities)
            if missing:
                raise ManagedSpecError(f"Service {service_id}: unavailable host capabilities: {missing}")

        for attachment in service["storage"]:
            resource = attachment["resource"]
            if resource not in resources:
                raise ManagedSpecError(f"Service {service_id}: unknown storage resource {resource!r}")
            _safe_path(attachment["mountPath"], context=f"service {service_id} storage mount")
        for attachment in service["credentials"]:
            credential = attachment["credential"]
            if credential not in credentials:
                raise ManagedSpecError(f"Service {service_id}: unknown credential {credential!r}")
            if attachment["use"] == "file":
                _safe_path(attachment["mountPath"], context=f"service {service_id} credential mount")

        kind = service["workload"]["kind"]
        if kind != "session" and service["sessionInputs"]:
            raise ManagedSpecError(f"Service {service_id}: sessionInputs are only valid for session workloads")
        for input_id, input_spec in service["sessionInputs"].items():
            resource = input_spec["resource"]
            if resource not in resources:
                raise ManagedSpecError(f"Service {service_id} input {input_id}: unknown storage resource {resource!r}")
            _safe_path(input_spec["mountPath"], context=f"service {service_id} session input {input_id}")

        runtime_type = service["runtime"]["type"]
        for accelerator in service["resources"]["accelerators"]:
            device = accelerator.get("device")
            if runtime_type == "vm":
                if accelerator["mode"] != "passthrough" or not isinstance(device, str) or not device.startswith("pci:"):
                    raise ManagedSpecError(
                        f"Service {service_id}: VM accelerators require passthrough mode and explicit pci: device"
                    )
            elif runtime_type == "compose" and not accelerator.get("target"):
                raise ManagedSpecError(f"Service {service_id}: Compose accelerator requests require target")
            elif runtime_type in {"systemd", "exec"} and isinstance(device, str) and device.startswith("cdi:"):
                raise ManagedSpecError(f"Service {service_id}: CDI selectors are container-only")

        for endpoint_id, endpoint in service["endpoints"].items():
            auth = endpoint["auth"]
            if auth["mode"] == "identity":
                expected = f"application.{service_id}."
                if not auth["capability"].startswith(expected):
                    raise ManagedSpecError(
                        f"Service {service_id} endpoint {endpoint_id}: capability must start with {expected!r}"
                    )
            elif auth["mode"] == "secret" and auth["credential"] not in credentials:
                raise ManagedSpecError(
                    f"Service {service_id} endpoint {endpoint_id}: unknown credential {auth['credential']!r}"
                )
            exposure = endpoint["exposure"]
            if exposure["type"] == "port-range" and exposure["end"] < exposure["start"]:
                raise ManagedSpecError(f"Service {service_id} endpoint {endpoint_id}: port range end precedes start")

        seen_dependencies: set[str] = set()
        for dependency in service["dependencies"]:
            target_id = dependency["service"]
            if target_id == service_id:
                raise ManagedSpecError(f"Service {service_id}: cannot depend on itself")
            if target_id in seen_dependencies:
                raise ManagedSpecError(f"Service {service_id}: duplicate dependency {target_id!r}")
            seen_dependencies.add(target_id)
            target = services.get(target_id)
            if target is None:
                raise ManagedSpecError(f"Service {service_id}: unknown dependency {target_id!r}")
            condition = dependency["condition"]
            target_kind = target["workload"]["kind"]
            if condition == "completed" and target_kind != "job":
                raise ManagedSpecError(
                    f"Service {service_id}: dependency {target_id!r} uses completed but target is not a job"
                )
            if condition == "ready" and target_kind == "job":
                raise ManagedSpecError(
                    f"Service {service_id}: job dependency {target_id!r} must use completed or started"
                )
            if condition == "ready" and "readiness" not in target:
                raise ManagedSpecError(
                    f"Service {service_id}: dependency {target_id!r} requests ready but target has no readiness probes"
                )

    _validate_graph(services)


def load_and_normalize(
    spec_path: pathlib.Path = DEFAULT_SPEC_PATH,
    schema_path: pathlib.Path = DEFAULT_SCHEMA_PATH,
    *,
    platform_capabilities: set[str] | None = None,
) -> dict[str, Any]:
    schema = _load_schema(schema_path)
    document = parse_yaml(spec_path)
    validate_schema(document, schema)
    normalized = normalize(document)
    # Defaults are annotations in JSON Schema, so validate once more after the
    # deterministic normalizer has materialized them.
    validate_schema(normalized, schema)
    semantic_validate(normalized, platform_capabilities=platform_capabilities)
    return normalized
