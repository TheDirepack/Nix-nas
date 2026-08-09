#!/usr/bin/env python3
"""Canonical Managed Services V2 schema runtime.

This is the single execution boundary for GUI/YAML desired state:

    services.yaml -> schema validation -> deterministic normalization ->
    semantic validation -> host resource resolution -> effective state ->
    generic runtime and subsystem projections.

No application names appear here.  Adding an application is a data change when
its runtime/capabilities are already supported.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import pathlib
import subprocess
import tempfile
from typing import Any

from jsonschema import Draft202012Validator

from nas_managed_devices import discover_gpus
from nas_managed_network import apply_firewalld, merge_network_policy, service_network
from nas_managed_spec import ManagedSpecError, parse_yaml, semantic_validate

DEFAULT_SPEC = pathlib.Path(os.environ.get("NAS_MANAGED_SPEC", "/var/lib/nas-control/services.yaml"))
DEFAULT_SCHEMA = pathlib.Path(
    os.environ.get("NAS_MANAGED_SPEC_SCHEMA", "/etc/nas-control/managed-services-v3.schema.json")
)
DEFAULT_EFFECTIVE = pathlib.Path(
    os.environ.get("NAS_EFFECTIVE_REGISTRY", "/run/nas-control/effective-endpoints.json")
)


class V2RuntimeError(RuntimeError):
    pass


def _atomic_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = pathlib.Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o640)
        os.replace(temporary, path)
        dir_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        temporary.unlink(missing_ok=True)


def _load_schema(path: pathlib.Path) -> dict[str, Any]:
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise V2RuntimeError(f"Unable to read V2 schema {path}: {exc}") from exc
    if not isinstance(schema, dict):
        raise V2RuntimeError("V2 schema must be an object")
    Draft202012Validator.check_schema(schema)
    return schema


def _schema_validate(document: dict[str, Any], schema: dict[str, Any]) -> None:
    errors = sorted(
        Draft202012Validator(schema).iter_errors(document),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if not errors:
        return
    rendered = []
    for error in errors[:16]:
        path = "$" + "".join(f"[{part}]" if isinstance(part, int) else f".{part}" for part in error.absolute_path)
        rendered.append(f"{path}: {error.message}")
    raise V2RuntimeError("V2 schema validation failed:\n" + "\n".join(rendered))


def _network_defaults(value: dict[str, Any]) -> None:
    value.setdefault("mode", "host")
    value.setdefault("outboundDefault", "allow")
    value.setdefault("lanAccess", False)
    value.setdefault("allowedHostPorts", [])
    value.setdefault("allowedEgress", [])


def normalize_gui_document(raw: dict[str, Any]) -> dict[str, Any]:
    """Apply behavioral defaults once after JSON Schema validation."""

    doc = copy.deepcopy(raw)
    doc.setdefault("generation", 1)
    doc.setdefault("storageResources", {})
    doc.setdefault("networkProfiles", {})
    doc.setdefault("credentials", {})
    for resource in doc["storageResources"].values():
        resource.setdefault("scope", "system")
        resource["backup"].setdefault("consistency", "filesystem")
        resource.setdefault("fileBrowser", {})
        resource["fileBrowser"].setdefault("visible", True)
    for profile in doc["networkProfiles"].values():
        _network_defaults(profile)
    for credential in doc["credentials"].values():
        credential.setdefault("required", True)

    for service_id, service in doc["services"].items():
        service.setdefault("managed", True)
        service.setdefault("principal", f"application:{service_id}")
        service.setdefault("dependencies", [])
        service.setdefault("requiresCapabilities", [])
        service.setdefault("resources", {})
        service["resources"].setdefault("accelerators", [])
        service.setdefault("sandbox", {})
        service["sandbox"].setdefault("profile", "inherit")
        service.setdefault("storage", [])
        service.setdefault("credentials", [])
        service.setdefault("sessionInputs", {})
        service.setdefault("routes", {})
        service.setdefault("listeners", {})
        workload = service["workload"]
        if workload["kind"] == "job":
            workload.setdefault("schedules", [])
            for schedule in workload["schedules"]:
                schedule.setdefault("randomizedDelaySeconds", 0)
                schedule.setdefault("persistent", True)
        elif workload["kind"] == "session":
            workload.setdefault("leaseIdleSeconds", 900)
        for dependency in service["dependencies"]:
            dependency.setdefault("condition", "ready")
        for attachment in service["storage"]:
            attachment.setdefault("access", "read")
        for item in service["sessionInputs"].values():
            item.setdefault("allowSubpath", True)
            item.setdefault("access", "read")
        for route in service["routes"].values():
            route.setdefault("priority", 0)
            route.setdefault("portal", {})
            route["portal"].setdefault("visible", False)
            target = route["target"]
            if target["type"] in {"http", "https"}:
                target.setdefault("host", "127.0.0.1")
            exposure = route["exposure"]
            if exposure["type"] == "hostname":
                exposure.setdefault("path", "/")
        for listener in service["listeners"].values():
            listener.setdefault("firewall", True)
        runtime = service["runtime"]
        if runtime["type"] == "python":
            runtime.setdefault("interpreter", "/run/current-system/sw/bin/python3")
            runtime.setdefault("dependencies", {})
            runtime["dependencies"].setdefault("requireHashes", True)
            runtime["dependencies"].setdefault("installProjectDependencies", False)
            runtime.setdefault("args", [])
            runtime.setdefault("environment", {})
            runtime.setdefault("restart", "on-failure")
            runtime.setdefault("restartSeconds", 3)
        elif runtime["type"] in {"exec", "oci"}:
            runtime.setdefault("environment", {})
            if runtime["type"] == "exec":
                runtime.setdefault("restart", "on-failure")
                runtime.setdefault("restartSeconds", 3)
            else:
                runtime.setdefault("command", [])
                runtime.setdefault("pull", "missing")
        if "network" in service:
            _network_defaults(service["network"])
        if "readiness" in service:
            readiness = service["readiness"]
            readiness.setdefault("timeoutSeconds", 60)
            readiness.setdefault("intervalMilliseconds", 500)
            for probe in readiness["probes"]:
                if probe["type"] == "tcp":
                    probe.setdefault("host", "127.0.0.1")
                elif probe["type"] == "http":
                    probe.setdefault("acceptStatusMin", 200)
                    probe.setdefault("acceptStatusMax", 399)
    return doc


def load_document(
    spec_path: pathlib.Path = DEFAULT_SPEC,
    schema_path: pathlib.Path = DEFAULT_SCHEMA,
    *,
    platform_capabilities: set[str] | None = None,
) -> dict[str, Any]:
    raw = parse_yaml(spec_path)
    schema = _load_schema(schema_path)
    _schema_validate(raw, schema)
    normalized = normalize_gui_document(raw)
    try:
        semantic_validate(normalized, platform_capabilities=platform_capabilities)
    except ManagedSpecError as exc:
        raise V2RuntimeError(str(exc)) from exc
    return normalized


def _resolve_storage(service: dict[str, Any], document: dict[str, Any]) -> list[dict[str, Any]]:
    resolved: list[dict[str, Any]] = []
    for attachment in service["storage"]:
        resource = document["storageResources"][attachment["resource"]]
        item = {
            "resource": attachment["resource"],
            "hostPath": resource["path"],
            "guestPath": attachment["mountPath"],
            "mode": "rw" if attachment["access"] == "write" else "ro",
            "requiredCapabilities": ["read", "write"] if attachment["access"] == "write" else ["read"],
            "stateClass": resource["stateClass"],
            "scope": resource["scope"],
        }
        if attachment.get("target") is not None:
            item["target"] = attachment["target"]
        if resource.get("dataset") is not None:
            item["dataset"] = resource["dataset"]
        if resource.get("pathTemplate") is not None:
            item["pathTemplate"] = resource["pathTemplate"]
        resolved.append(item)
    return resolved


def _record_from_gpus(records: list[dict[str, Any]], accelerator: dict[str, Any]) -> dict[str, Any]:
    return {
        "request": copy.deepcopy(accelerator),
        "required": accelerator.get("required", False),
        "vendors": sorted({str(record["vendor"]) for record in records}),
        "devicePaths": sorted({path for record in records for path in record.get("devicePaths", [])}),
        "cdiDevices": sorted({name for record in records for name in record.get("cdiDevices", [])}),
        "pciAddresses": sorted({str(record["pciAddress"]) for record in records}),
        **({"target": accelerator["target"]} if accelerator.get("target") else {}),
    }


def _resolve_devices(service_id: str, service: dict[str, Any], inventory: list[dict[str, Any]]) -> list[dict[str, Any]]:
    resolved: list[dict[str, Any]] = []
    for accelerator in service["resources"]["accelerators"]:
        if accelerator["kind"] != "gpu":
            continue
        selected: list[dict[str, Any]] = []
        device = accelerator.get("device")
        if isinstance(device, str) and device.startswith("pci:"):
            address = device.removeprefix("pci:").lower()
            selected = [item for item in inventory if str(item.get("pciAddress", "")).lower() == address]
        elif isinstance(device, str) and device.startswith("cdi:"):
            resolved.append({
                "request": copy.deepcopy(accelerator),
                "required": accelerator.get("required", False),
                "vendors": [],
                "devicePaths": [],
                "cdiDevices": [device.removeprefix("cdi:")],
                "pciAddresses": [],
                **({"target": accelerator["target"]} if accelerator.get("target") else {}),
            })
            continue
        else:
            vendor = accelerator.get("vendor", "any")
            candidates = inventory if vendor == "any" else [item for item in inventory if item.get("vendor") == vendor]
            quantity = accelerator.get("quantity", 1)
            selected = list(candidates) if quantity == "all" else list(candidates[: int(quantity)])
        quantity = accelerator.get("quantity", 1)
        minimum = 1 if quantity == "all" else int(quantity)
        if accelerator.get("required", False) and len(selected) < minimum:
            raise V2RuntimeError(f"Service {service_id}: required GPU request cannot be satisfied")
        resolved.append(_record_from_gpus(selected, accelerator))
    return resolved


def _resolve_network(service_id: str, service: dict[str, Any], document: dict[str, Any]) -> dict[str, Any] | None:
    profile = document["networkProfiles"].get(service.get("networkProfile"))
    inline = service.get("network")
    mode = (inline or profile or {}).get("mode", "host")
    if mode != "isolated":
        return None
    def policy_only(value: dict[str, Any] | None) -> dict[str, Any] | None:
        if value is None:
            return None
        return {key: copy.deepcopy(item) for key, item in value.items() if key != "mode"}
    policy = merge_network_policy(policy_only(profile), policy_only(inline))
    policy["mode"] = "isolated"
    policy["identity"] = service_network(service_id)
    return policy


def _legacy_auth(auth: dict[str, Any]) -> dict[str, Any]:
    mode = auth["mode"]
    if mode == "identity":
        return {"mode": "forward-auth", "capability": auth["capability"]}
    if mode == "secret":
        return {"mode": "api-key", "credential": auth["credential"], "sources": auth["sources"]}
    return {"mode": "public"}


def _flatten_routes(service_id: str, service: dict[str, Any]) -> dict[str, dict[str, Any]]:
    flattened: dict[str, dict[str, Any]] = {}
    for route_id, route in service["routes"].items():
        target = route["target"]
        if target["type"] not in {"http", "https"}:
            # Keep the canonical route in effective state; the current Caddy
            # adapter cannot safely lower unix-http yet and must fail closed.
            continue
        exposure = route["exposure"]
        exposures: list[dict[str, Any]] = []
        if exposure["type"] == "path":
            exposures = [{"type": "path", "value": path, "prefix": True} for path in exposure["paths"]]
        elif exposure["type"] == "hostname":
            exposures = [{"type": "hostname", "value": exposure["hostname"], "prefix": True}]
        for index, lowered in enumerate(exposures):
            endpoint_id = route_id if index == 0 else f"{route_id}-{index + 1}"
            flattened[f"{service_id}:{endpoint_id}"] = {
                "label": f"{service['name']}:{route_id}",
                "serviceId": service_id,
                "endpointId": endpoint_id,
                "transport": target["type"],
                "targetPort": target["port"],
                "targetHost": target.get("host", "127.0.0.1"),
                "exposure": lowered,
                "auth": _legacy_auth(route["auth"]),
                "portal": route.get("portal", {}),
                "proxy": route.get("proxy", {}),
                "available": bool(service["enabled"]),
            }
    return flattened


def compile_effective(document: dict[str, Any]) -> dict[str, Any]:
    inventory = discover_gpus()
    effective = copy.deepcopy(document)
    effective["endpoints"] = {}
    effective["backupResources"] = sorted(
        resource_id
        for resource_id, resource in document["storageResources"].items()
        if resource["backup"]["enabled"]
    )
    for service_id, service in effective["services"].items():
        workload = service["workload"]
        if workload["kind"] == "daemon":
            service["lifecycle"] = {
                "mode": workload["activation"],
                **({"idleSeconds": workload["idleSeconds"]} if workload["activation"] == "on-demand" else {}),
            }
        elif workload["kind"] == "session":
            service["lifecycle"] = {"mode": "session"}
        else:
            service["lifecycle"] = {"mode": "persistent"}
        service["ownership"] = "v2" if service["managed"] else "system"
        service["resolvedStorage"] = _resolve_storage(service, document)
        service["resolvedDevices"] = _resolve_devices(service_id, service, inventory)
        network = _resolve_network(service_id, service, document)
        if network is not None:
            service["resolvedNetwork"] = network
        for attachment in service["credentials"]:
            attachment["resolvedPath"] = document["credentials"][attachment["credential"]]["path"]
        effective["endpoints"].update(_flatten_routes(service_id, service))
    return effective


def _apply_runtime(service_id: str, service: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    runtime_type = service["runtime"]["type"]
    workload = service["workload"]
    if runtime_type == "python":
        from nas_service_runtime_python import apply_python

        return apply_python(service_id, service, dry_run=dry_run)
    if runtime_type == "systemd":
        unit = service["runtime"]["unit"]
        operation = None
        if service["managed"] and not service["enabled"]:
            operation = "stop"
        elif workload["kind"] == "daemon" and workload.get("activation") == "persistent" and service["enabled"]:
            operation = "start"
        if operation is not None and not dry_run:
            subprocess.run(["systemctl", operation, unit], check=True)
        return {"service": service_id, "runtime": "systemd", "unit": unit, "operation": operation}
    if workload["kind"] in {"job", "session"}:
        return {"service": service_id, "runtime": runtime_type, "operation": None}
    projected = dict(service)
    projected["enabled"] = bool(service["enabled"] and workload.get("activation") == "persistent")
    if runtime_type == "quadlet":
        from nas_service_runtime_podman import apply_podman

        return apply_podman(service_id, projected, dry_run=dry_run)
    if runtime_type == "compose":
        from nas_service_runtime_compose import apply_compose

        return apply_compose(service_id, projected, dry_run=dry_run)
    if runtime_type == "vm":
        from nas_service_runtime_libvirt import apply_libvirt

        return apply_libvirt(service_id, projected, dry_run=dry_run)
    if runtime_type in {"exec", "oci"}:
        return {"service": service_id, "runtime": runtime_type, "operation": None, "deferred": True}
    raise V2RuntimeError(f"Service {service_id}: unsupported runtime {runtime_type!r}")


def apply_document(
    document: dict[str, Any],
    *,
    effective_path: pathlib.Path = DEFAULT_EFFECTIVE,
    dry_run: bool = False,
    authentik: bool = True,
) -> dict[str, Any]:
    effective = compile_effective(document)
    if not dry_run:
        _atomic_json(effective_path, effective)

    result: dict[str, Any] = {"effective": str(effective_path), "runtimes": {}, "projections": {}}
    for service_id in sorted(effective["services"]):
        service = effective["services"][service_id]
        network = service.get("resolvedNetwork")
        if network is not None:
            policy = {key: value for key, value in network.items() if key not in {"identity", "mode"}}
            result.setdefault("networks", {})[service_id] = apply_firewalld(service_id, policy, dry_run=dry_run)
        result["runtimes"][service_id] = _apply_runtime(service_id, service, dry_run=dry_run)

    if dry_run:
        return result

    # Projection modules all consume the exact same effective document.
    from nas_copyparty_projection import atomic_write_config, render_config
    from nas_service_caddy import write_caddy_fragment

    atomic_write_config(render_config(effective))
    result["projections"]["copyparty"] = "applied"
    write_caddy_fragment(effective=effective)
    result["projections"]["caddy"] = "applied"

    # Restic reads storageResources/backupResources from the effective file; no
    # separate backup database or scheduler is created by V2.
    result["projections"]["backup"] = "effective-state-published"

    if authentik:
        from nas_authentik_v2_groups import reconcile_groups
        from nas_identity_sync import authentik_token

        result["projections"]["authentik"] = reconcile_groups(authentik_token(), effective)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nas-v2-runtime")
    parser.add_argument("command", choices=("validate", "compile", "plan", "apply"))
    parser.add_argument("--spec", type=pathlib.Path, default=DEFAULT_SPEC)
    parser.add_argument("--schema", type=pathlib.Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--effective", type=pathlib.Path, default=DEFAULT_EFFECTIVE)
    parser.add_argument("--skip-authentik", action="store_true")
    args = parser.parse_args(argv)
    try:
        document = load_document(args.spec, args.schema)
        if args.command == "validate":
            print(json.dumps(document, indent=2, sort_keys=True))
            return 0
        effective = compile_effective(document)
        if args.command == "compile":
            print(json.dumps(effective, indent=2, sort_keys=True))
            return 0
        result = apply_document(
            document,
            effective_path=args.effective,
            dry_run=args.command == "plan",
            authentik=not args.skip_authentik,
        )
    except Exception as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
