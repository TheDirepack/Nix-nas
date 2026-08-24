#!/usr/bin/env python3
"""Managed Services V2 schema loader, normalizer, semantic validator, and compiler.

This module is intentionally application-agnostic. It validates configuration
correctness and derives native-projection metadata; it does not authenticate
users, assign Authentik capabilities, supervise workloads, or make request-time
authorization decisions.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import pathlib
import re
from collections.abc import Iterable, Mapping
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

DEFAULT_SPEC_PATH = pathlib.Path(os.environ.get("NAS_V2_SPEC", "/var/lib/nas-control/services"))
DEFAULT_SCHEMA_PATH = pathlib.Path(os.environ.get("NAS_V2_SCHEMA", "/etc/nas-control/managed-services-v3.schema.json"))
DEFAULT_PLATFORM_PATH = pathlib.Path(
    os.environ.get("NAS_V2_PLATFORM_CAPABILITIES", "/etc/nas-control/platform-capabilities.json")
)
DEFAULT_EFFECTIVE_PATH = pathlib.Path(os.environ.get("NAS_V2_EFFECTIVE", "/run/nas-control/effective.json"))

SERVICE_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
CAPABILITY_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
SYSTEMD_UNIT_RE = re.compile(r"^[A-Za-z0-9_.@:-]{1,255}\.(?:service|timer|target|path|socket|mount)$")
APP_ROOT = pathlib.PurePosixPath("/var/lib/nas-control/apps")
SECRET_ROOT = pathlib.PurePosixPath("/run/nas-secrets")


class ManagedServicesV2Error(RuntimeError):
    """Raised when desired state cannot be safely compiled."""

    def __init__(self, message: str, *, path: str = "$", code: str = "invalid-spec") -> None:
        super().__init__(message)
        self.path = path
        self.code = code

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": str(self)}


def _json_path(parts: Iterable[Any]) -> str:
    rendered = "$"
    for part in parts:
        rendered += f"[{part}]" if isinstance(part, int) else f".{part}"
    return rendered


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_plain(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise ManagedServicesV2Error(
        f"YAML value of type {type(value).__name__} is not JSON-compatible",
        code="yaml-type",
    )


def parse_yaml_text(text: str, *, source: str = "<memory>") -> dict[str, Any]:
    if text == "" or text.strip() == "":
        raise ManagedServicesV2Error(
            "Managed Services V2 desired state must not be empty",
            code="yaml-empty",
        )
    parser = YAML(typ="safe", pure=True)
    parser.version = (1, 2)
    parser.allow_duplicate_keys = False
    try:
        value = parser.load(text)
    except YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        location = ""
        path = "$"
        if mark is not None:
            location = f" at line {mark.line + 1}, column {mark.column + 1}"
            path = f"$@{mark.line + 1}:{mark.column + 1}"
        raise ManagedServicesV2Error(
            f"Unable to parse YAML {source}{location}: {exc}",
            path=path,
            code="yaml-parse",
        ) from exc
    if value is None:
        raise ManagedServicesV2Error(
            "Managed Services V2 desired state must not be empty (YAML null)",
            code="yaml-empty",
        )
    plain = _plain(value)
    if not isinstance(plain, dict):
        raise ManagedServicesV2Error(
            "Managed Services V2 desired state must be a mapping/object",
            code="yaml-root",
        )
    return plain


def _yaml_files_in_dir(directory: pathlib.Path) -> list[pathlib.Path]:
    try:
        entries = list(directory.iterdir())
    except OSError as exc:
        raise ManagedServicesV2Error(
            f"Unable to read Managed Services V2 desired state {directory}: {exc}",
            code="io-read",
        ) from exc
    files = [p for p in entries if p.is_file() and p.suffix.lower() in {".yaml", ".yml"}]
    return sorted(files, key=lambda p: p.name)


def _merge_documents(documents: list[dict[str, Any]]) -> dict[str, Any]:
    if not documents:
        raise ManagedServicesV2Error(
            "Managed Services V2 desired state must not be empty",
            code="yaml-empty",
        )
    merged = copy.deepcopy(documents[0])
    for doc in documents[1:]:
        for key, value in doc.items():
            if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
                merged[key] = {**merged[key], **{k: copy.deepcopy(v) for k, v in value.items()}}
            else:
                merged[key] = copy.deepcopy(value)
    return merged


def is_directory_authority(path: pathlib.Path) -> bool:
    try:
        return path.is_dir()
    except OSError:
        return False


def hash_authority(path: pathlib.Path) -> str:
    p = pathlib.Path(path)
    if p.is_dir():
        files = _yaml_files_in_dir(p)
        if not files:
            raise ManagedServicesV2Error(
                f"Managed Services V2 desired state directory {p} contains no YAML files",
                code="yaml-empty",
            )
        h = hashlib.sha256()
        for f in files:
            try:
                data = f.read_bytes()
            except OSError as exc:
                raise ManagedServicesV2Error(
                    f"Unable to read Managed Services V2 desired state {f}: {exc}",
                    code="io-read",
                ) from exc
            # Include filename and length delimiters to avoid concatenation ambiguity.
            h.update(f.name.encode("utf-8"))
            h.update(b"\x00")
            h.update(str(len(data)).encode("utf-8"))
            h.update(b"\x00")
            h.update(data)
            h.update(b"\x00")
        return h.hexdigest()
    try:
        data = p.read_bytes()
    except OSError as exc:
        raise ManagedServicesV2Error(
            f"Unable to read Managed Services V2 desired state {p}: {exc}",
            code="io-read",
        ) from exc
    return hashlib.sha256(data).hexdigest()


def parse_yaml(path: pathlib.Path = DEFAULT_SPEC_PATH) -> dict[str, Any]:
    p = pathlib.Path(path)
    if p.is_dir():
        files = _yaml_files_in_dir(p)
        if not files:
            raise ManagedServicesV2Error(
                f"Managed Services V2 desired state directory {p} contains no YAML files",
                code="yaml-empty",
            )
        docs: list[dict[str, Any]] = []
        for f in files:
            try:
                text = f.read_text(encoding="utf-8")
            except OSError as exc:
                raise ManagedServicesV2Error(
                    f"Unable to read Managed Services V2 desired state {f}: {exc}",
                    code="io-read",
                ) from exc
            docs.append(parse_yaml_text(text, source=str(f)))
        return _merge_documents(docs)
    try:
        return parse_yaml_text(p.read_text(encoding="utf-8"), source=str(p))
    except OSError as exc:
        raise ManagedServicesV2Error(
            f"Unable to read Managed Services V2 desired state {p}: {exc}",
            code="io-read",
        ) from exc


def load_schema(path: pathlib.Path = DEFAULT_SCHEMA_PATH) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManagedServicesV2Error(
            f"Unable to read Managed Services V2 JSON Schema {path}: {exc}",
            code="schema-read",
        ) from exc
    if not isinstance(value, dict):
        raise ManagedServicesV2Error("Managed Services V2 JSON Schema must be an object", code="schema-invalid")
    try:
        Draft202012Validator.check_schema(value)
    except SchemaError as exc:
        raise ManagedServicesV2Error(
            f"Invalid Managed Services V2 JSON Schema: {exc.message}",
            code="schema-invalid",
        ) from exc
    return value


def validate_schema(document: dict[str, Any], schema: dict[str, Any]) -> None:
    errors = sorted(
        Draft202012Validator(schema).iter_errors(document),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if not errors:
        return
    first = errors[0]
    path = _json_path(first.absolute_path)
    extra = f" ({len(errors)} schema errors total)" if len(errors) > 1 else ""
    raise ManagedServicesV2Error(
        f"{first.message}{extra}",
        path=path,
        code="schema-validation",
    )


def _safe_absolute_path(value: str, *, path: str) -> pathlib.PurePosixPath:
    if any(ord(character) < 0x20 or character == "\x7f" for character in value):
        raise ManagedServicesV2Error("Path contains a forbidden control character", path=path, code="unsafe-path")
    candidate = pathlib.PurePosixPath(value)
    if not candidate.is_absolute() or ".." in candidate.parts:
        raise ManagedServicesV2Error("Path must be absolute and must not contain '..'", path=path, code="unsafe-path")
    return candidate


def _under(root: pathlib.PurePosixPath, candidate: pathlib.PurePosixPath) -> bool:
    try:
        candidate.relative_to(root)
    except ValueError:
        return False
    return True


def _safe_host_path_under(root: pathlib.PurePosixPath, value: str, *, path: str) -> pathlib.PurePosixPath:
    candidate = _safe_absolute_path(value, path=path)
    if not _under(root, candidate):
        raise ManagedServicesV2Error(
            f"Path must be beneath {root}",
            path=path,
            code="path-containment",
        )
    resolved_root = pathlib.Path(str(root)).resolve(strict=False)
    resolved_candidate = pathlib.Path(str(candidate)).resolve(strict=False)
    try:
        resolved_candidate.relative_to(resolved_root)
    except ValueError as exc:
        raise ManagedServicesV2Error(
            f"Path resolves outside {root} through a symlink",
            path=path,
            code="symlink-escape",
        ) from exc
    return candidate


def _normalize_network(policy: dict[str, Any]) -> None:
    policy.setdefault("mode", "host")
    policy.setdefault("outboundDefault", "allow")
    policy.setdefault("lanAccess", False)
    policy.setdefault("allowedHostPorts", [])
    policy.setdefault("allowedEgress", [])
    for rule in policy["allowedEgress"]:
        rule.setdefault("ports", [])


def _normalize_runtime(runtime: dict[str, Any]) -> None:
    runtime_type = runtime["type"]
    if runtime_type == "exec":
        runtime.setdefault("environment", {})
        runtime.setdefault("identity", {"mode": "dynamic"})
        runtime["identity"].setdefault("mode", "dynamic")
        runtime.setdefault("restart", "on-failure")
    elif runtime_type == "python":
        runtime.setdefault("interpreter", "/run/current-system/sw/bin/python3")
        runtime.setdefault("dependencies", {})
        runtime["dependencies"].setdefault("requireHashes", True)
        runtime.setdefault("environment", {})
        runtime.setdefault("identity", {"mode": "dynamic"})
        runtime["identity"].setdefault("mode", "dynamic")
        runtime.setdefault("restart", "on-failure")
        runtime["entrypoint"].setdefault("args", [])
    elif runtime_type == "oci":
        runtime.setdefault("command", [])
        runtime.setdefault("pull", "missing")


def _normalize_service(service: dict[str, Any]) -> None:
    service.setdefault("enabled", True)
    service.setdefault("managed", True)
    service.setdefault("dependencies", [])
    service.setdefault("requiresCapabilities", [])
    service.setdefault("authorization", {"capabilities": []})
    service["authorization"].setdefault("capabilities", [])
    service.setdefault("resources", {})
    service["resources"].setdefault("accelerators", [])
    service.setdefault("sandbox", {})
    sandbox = service["sandbox"]
    generated_runtime = service["runtime"]["type"] in {"exec", "python", "oci"}
    sandbox.setdefault("mode", "strict" if generated_runtime else "inherit")
    if sandbox["mode"] == "strict":
        sandbox.setdefault("readOnlyRoot", True)
        sandbox.setdefault("writablePaths", [])
        sandbox.setdefault("tmpfs", [])
        sandbox.setdefault("addCapabilities", [])
        sandbox.setdefault("dropCapabilities", [])
        sandbox.setdefault("noNewPrivileges", True)
    service.setdefault("storage", [])
    service.setdefault("credentials", [])
    service.setdefault("routes", {})
    service.setdefault("listeners", {})

    workload = service["workload"]
    kind = workload["kind"]
    if kind == "daemon":
        workload.setdefault("activation", "persistent")
    elif kind == "job":
        workload.setdefault("schedules", [])
        for schedule in workload["schedules"]:
            schedule.setdefault("randomizedDelaySeconds", 0)
            schedule.setdefault("persistent", True)

    _normalize_runtime(service["runtime"])

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

    if "network" in service:
        _normalize_network(service["network"])
    elif workload.get("kind") == "session":
        policy = service.setdefault("network", {})
        policy.setdefault("mode", "isolated")
        policy.setdefault("outboundDefault", "deny")
        _normalize_network(policy)

    for dependency in service["dependencies"]:
        dependency.setdefault("condition", "ready")
    for attachment in service["storage"]:
        attachment.setdefault("access", "read")
    for accelerator in service["resources"]["accelerators"]:
        accelerator.setdefault("vendor", "any")
        accelerator.setdefault("quantity", 1)
        accelerator.setdefault("required", False)
        accelerator.setdefault("mode", "shared")
    for route in service["routes"].values():
        route.setdefault("proxy", {})
        route["proxy"].setdefault("requestHeaders", {})
        route["proxy"].setdefault("removeRequestHeaders", [])
        route["proxy"].setdefault("responseHeaders", {})
        route["proxy"].setdefault("trustedIdentityHeaders", [])
        route["proxy"].setdefault("requireHeaders", {})
        route.setdefault("portal", {})
        route["portal"].setdefault("visible", False)
        route["portal"].setdefault("order", 0)
        auth = route["auth"]
        if auth["mode"] == "identity":
            auth.setdefault("capability", "access")
        target = route["target"]
        if target["type"] in {"http", "https"}:
            target.setdefault("host", "127.0.0.1")
        exposure = route["exposure"]
        if exposure["type"] == "hostname":
            exposure.setdefault("path", "/")
    for listener in service["listeners"].values():
        listener.setdefault("firewall", True)


def normalize(document: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(document)
    result.setdefault("generation", 1)
    result.setdefault("storageResources", {})
    result.setdefault("credentials", {})
    result.setdefault("networkProfiles", {})
    # Backup remote descriptor — optional, defaults to local config-only.
    # This drives the rclone provider/scope UI and Nix restic wiring; the
    # compiler itself treats it as passthrough (no storage projection).
    if "backup" not in result or not isinstance(result["backup"], dict):
        result["backup"] = {}
    backup = result["backup"]
    backup.setdefault("remote", {})
    remote = backup["remote"] if isinstance(backup["remote"], dict) else {}
    backup["remote"] = remote
    remote.setdefault("provider", "local")
    remote.setdefault("scope", "config-only")
    remote.setdefault("rcloneRemote", "")
    remote.setdefault("rcloneConfigFile", "")

    for resource in result["storageResources"].values():
        resource.setdefault("scope", "system")
        resource.setdefault("capabilities", ["read"])
        resource.setdefault("backup", {"enabled": False, "consistency": "filesystem"})
        resource["backup"].setdefault("enabled", False)
        resource["backup"].setdefault("consistency", "filesystem")
        resource.setdefault("fileBrowser", {"visible": False})
        resource["fileBrowser"].setdefault("visible", False)
    for credential in result["credentials"].values():
        credential.setdefault("required", True)
    for profile in result["networkProfiles"].values():
        _normalize_network(profile)
    for service in result["services"].values():
        _normalize_service(service)
    return result


def _validate_runtime_paths(service_id: str, service: dict[str, Any]) -> None:
    runtime = service["runtime"]
    runtime_type = runtime["type"]
    root = APP_ROOT / service_id

    if runtime_type in {"quadlet", "compose", "vm"}:
        _safe_host_path_under(
            root,
            runtime["source"],
            path=f"$.services.{service_id}.runtime.source",
        )
    elif runtime_type == "python":
        dependencies = runtime["dependencies"]
        if "requirementsFile" in dependencies:
            _safe_host_path_under(
                root,
                dependencies["requirementsFile"],
                path=f"$.services.{service_id}.runtime.dependencies.requirementsFile",
            )
        if "script" in runtime["entrypoint"]:
            _safe_host_path_under(
                root,
                runtime["entrypoint"]["script"],
                path=f"$.services.{service_id}.runtime.entrypoint.script",
            )
    elif runtime_type == "exec":
        command = runtime["command"]
        executable = _safe_absolute_path(command[0], path=f"$.services.{service_id}.runtime.command[0]")
        if executable == pathlib.PurePosixPath("/"):
            raise ManagedServicesV2Error(
                "Executable path must name a file",
                path=f"$.services.{service_id}.runtime.command[0]",
                code="runtime-command",
            )
    elif runtime_type == "systemd":
        unit = runtime["unit"]
        if not SYSTEMD_UNIT_RE.fullmatch(unit):
            raise ManagedServicesV2Error(
                "systemd runtime unit must name a .service, .timer, .target, or .path unit without control characters",
                path=f"$.services.{service_id}.runtime.unit",
                code="runtime-unit",
            )


def _validate_dependency_graph(services: dict[str, dict[str, Any]]) -> None:
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(service_id: str, trail: list[str]) -> None:
        if service_id in visited:
            return
        if service_id in visiting:
            start = trail.index(service_id)
            cycle = trail[start:] + [service_id]
            raise ManagedServicesV2Error(
                "Dependency cycle: " + " -> ".join(cycle),
                path=f"$.services.{service_id}.dependencies",
                code="dependency-cycle",
            )
        visiting.add(service_id)
        trail.append(service_id)
        for dependency in services[service_id]["dependencies"]:
            visit(dependency["service"], trail)
        trail.pop()
        visiting.remove(service_id)
        visited.add(service_id)

    for service_id in sorted(services):
        visit(service_id, [])


def _listener_ports(exposure: dict[str, Any]) -> range:
    if "port" in exposure:
        return range(exposure["port"], exposure["port"] + 1)
    return range(exposure["start"], exposure["end"] + 1)


def _routes_conflict(first: str, second: str) -> bool:
    """True when two path exposures can shadow one another in Caddy.

    Caddy matches a path route with ``path /x /x/*``; ``/api`` therefore
    matches every request that ``/api/users`` does. Treat '/' as the root
    that shadows every other path, compare by leading path segments, and
    ignore redundant `/` characters within each candidate. Parent/child
    conflicts are allowed only when the renderer guarantees
    longest-path-first ordering; exact duplicates and ambiguous overlaps
    must still fail closed.
    """
    first = first.rstrip("/") or "/"
    second = second.rstrip("/") or "/"
    if first == "/" or second == "/":
        return True
    first_parts = first.strip("/").split("/")
    second_parts = second.strip("/").split("/")
    return first_parts[: len(second_parts)] == second_parts or second_parts[: len(first_parts)] == first_parts


def semantic_validate(
    document: dict[str, Any],
    *,
    platform_capabilities: set[str] | None = None,
) -> None:
    resources = document["storageResources"]
    credentials = document["credentials"]
    profiles = document["networkProfiles"]
    services = document["services"]

    for resource_id, resource in resources.items():
        resource_path = _safe_absolute_path(resource["path"], path=f"$.storageResources.{resource_id}.path")
        template = resource.get("pathTemplate")
        if template is not None:
            _safe_absolute_path(template, path=f"$.storageResources.{resource_id}.pathTemplate")
        scope = resource["scope"]
        if scope == "user" and (not isinstance(template, str) or "{user}" not in template):
            raise ManagedServicesV2Error(
                "User-scoped storage requires pathTemplate containing {user}",
                path=f"$.storageResources.{resource_id}.pathTemplate",
                code="storage-template",
            )
        if scope == "instance" and (not isinstance(template, str) or "{instance}" not in template):
            raise ManagedServicesV2Error(
                "Instance-scoped storage requires pathTemplate containing {instance}",
                path=f"$.storageResources.{resource_id}.pathTemplate",
                code="storage-template",
            )
        backup = resource["backup"]
        if resource["stateClass"] in {"cache", "ephemeral"} and backup["enabled"]:
            raise ManagedServicesV2Error(
                "Cache/ephemeral storage cannot be selected as authoritative backup state",
                path=f"$.storageResources.{resource_id}.backup.enabled",
                code="backup-state-class",
            )
        if backup["consistency"] == "zfs-snapshot" and not resource.get("dataset"):
            raise ManagedServicesV2Error(
                "zfs-snapshot consistency requires a dataset",
                path=f"$.storageResources.{resource_id}.dataset",
                code="backup-consistency",
            )
        del resource_path  # lexical safety is the only host-independent check here

    for credential_id, credential in credentials.items():
        try:
            _safe_host_path_under(
                SECRET_ROOT,
                credential["path"],
                path=f"$.credentials.{credential_id}.path",
            )
        except ManagedServicesV2Error as exc:
            if exc.code == "path-containment":
                raise ManagedServicesV2Error(
                    f"Credential references must be beneath {SECRET_ROOT}",
                    path=f"$.credentials.{credential_id}.path",
                    code="credential-path",
                ) from exc
            raise

    for profile_id, profile in profiles.items():
        if "vlanId" in profile and profile["mode"] != "isolated":
            raise ManagedServicesV2Error(
                "VLAN selection requires network mode 'isolated'",
                path=f"$.networkProfiles.{profile_id}.vlanId",
                code="network-vlan",
            )

    route_paths: dict[str, str] = {}
    route_hostnames: dict[str, str] = {}
    listener_owners: dict[tuple[str, int], str] = {}

    for service_id, service in services.items():
        _validate_runtime_paths(service_id, service)
        kind = service["workload"]["kind"]
        workload = service["workload"]

        if kind == "daemon":
            if workload["activation"] == "on-demand" and "idleSeconds" not in workload:
                raise ManagedServicesV2Error(
                    "On-demand daemons require idleSeconds",
                    path=f"$.services.{service_id}.workload.idleSeconds",
                    code="workload-lifecycle",
                )
            if workload.get("schedules"):
                raise ManagedServicesV2Error(
                    "Daemon workloads cannot declare schedules",
                    path=f"$.services.{service_id}.workload.schedules",
                    code="workload-lifecycle",
                )
        elif kind == "job":
            if "activation" in workload or "idleSeconds" in workload:
                raise ManagedServicesV2Error(
                    "Job workloads cannot declare daemon activation/idle fields",
                    path=f"$.services.{service_id}.workload",
                    code="workload-lifecycle",
                )
        elif kind == "session" and ("activation" in workload or "schedules" in workload or "idleSeconds" in workload):
            raise ManagedServicesV2Error(
                "Session workloads cannot declare daemon/job lifecycle fields",
                path=f"$.services.{service_id}.workload",
                code="workload-lifecycle",
            )

        if platform_capabilities is not None:
            missing = sorted(set(service["requiresCapabilities"]) - platform_capabilities)
            if missing:
                raise ManagedServicesV2Error(
                    f"Unavailable platform capabilities: {', '.join(missing)}",
                    path=f"$.services.{service_id}.requiresCapabilities",
                    code="platform-capability",
                )

        if "networkProfile" in service and "network" in service:
            raise ManagedServicesV2Error(
                "Use either network or networkProfile, not both",
                path=f"$.services.{service_id}",
                code="network-policy",
            )
        if "networkProfile" in service and service["networkProfile"] not in profiles:
            raise ManagedServicesV2Error(
                f"Unknown network profile {service['networkProfile']!r}",
                path=f"$.services.{service_id}.networkProfile",
                code="missing-reference",
            )

        policy = profiles[service["networkProfile"]] if "networkProfile" in service else service.get("network")
        if isinstance(policy, dict) and "vlanId" in policy:
            if policy["mode"] != "isolated":
                raise ManagedServicesV2Error(
                    "VLAN selection requires network mode 'isolated'",
                    path=f"$.services.{service_id}.network.vlanId",
                    code="network-vlan",
                )
            runtime_type = service["runtime"]["type"]
            if not service["managed"] or runtime_type not in {"oci", "quadlet", "compose"}:
                raise ManagedServicesV2Error(
                    "VLAN selection requires a V2-managed OCI, Quadlet, or Compose runtime",
                    path=f"$.services.{service_id}.network.vlanId",
                    code="network-vlan-runtime",
                )

        if isinstance(policy, dict) and policy.get("mode") == "isolated":
            runtime_type = service["runtime"]["type"]
            if not service["managed"] or runtime_type not in {"oci", "quadlet", "compose"}:
                raise ManagedServicesV2Error(
                    f"Isolated service {service_id!r} requires a V2-managed runtime with a stable V2 bridge; runtime {runtime_type!r} is not implemented",
                    path=f"$.services.{service_id}.network.mode",
                    code="network-isolated-runtime",
                )
            if kind == "session" and runtime_type != "oci":
                raise ManagedServicesV2Error(
                    f"Session service {service_id!r} with isolated networking currently requires direct OCI runtime",
                    path=f"$.services.{service_id}.runtime.type",
                    code="network-session-runtime",
                )
            if kind == "session" and (service["routes"] or service["listeners"]):
                raise ManagedServicesV2Error(
                    f"Session service {service_id!r} cannot expose fixed routes/listeners because concurrent instances require per-instance endpoints",
                    path=f"$.services.{service_id}",
                    code="network-session-endpoints",
                )

        mount_targets: set[str] = set()
        for index, attachment in enumerate(service["storage"]):
            resource_id = attachment["resource"]
            if resource_id not in resources:
                raise ManagedServicesV2Error(
                    f"Unknown storage resource {resource_id!r}",
                    path=f"$.services.{service_id}.storage[{index}].resource",
                    code="missing-reference",
                )
            mount = _safe_absolute_path(
                attachment["mountPath"],
                path=f"$.services.{service_id}.storage[{index}].mountPath",
            )
            mount_key = str(mount)
            if mount_key in mount_targets:
                raise ManagedServicesV2Error(
                    f"Conflicting storage mount target {mount_key}",
                    path=f"$.services.{service_id}.storage[{index}].mountPath",
                    code="storage-conflict",
                )
            mount_targets.add(mount_key)
            if service["runtime"]["type"] == "compose" and not attachment.get("target"):
                raise ManagedServicesV2Error(
                    "Compose storage attachments require an explicit target service",
                    path=f"$.services.{service_id}.storage[{index}].target",
                    code="compose-target",
                )
            if service["runtime"]["type"] == "vm" and not attachment.get("mountTag"):
                raise ManagedServicesV2Error(
                    "VM storage attachments require an explicit virtiofs mountTag",
                    path=f"$.services.{service_id}.storage[{index}].mountTag",
                    code="vm-storage",
                )

        for index, attachment in enumerate(service["credentials"]):
            credential_id = attachment["credential"]
            if credential_id not in credentials:
                raise ManagedServicesV2Error(
                    f"Unknown credential {credential_id!r}",
                    path=f"$.services.{service_id}.credentials[{index}].credential",
                    code="missing-reference",
                )
            if attachment["use"] == "file":
                if "mountPath" not in attachment:
                    raise ManagedServicesV2Error(
                        "File credential attachment requires mountPath",
                        path=f"$.services.{service_id}.credentials[{index}].mountPath",
                        code="credential-attachment",
                    )
                _safe_absolute_path(
                    attachment["mountPath"],
                    path=f"$.services.{service_id}.credentials[{index}].mountPath",
                )
            if service["runtime"]["type"] == "compose" and not attachment.get("target"):
                raise ManagedServicesV2Error(
                    "Compose credential attachments require an explicit target service",
                    path=f"$.services.{service_id}.credentials[{index}].target",
                    code="compose-target",
                )

        accelerator_entries = service["resources"]["accelerators"]
        for index, accelerator in enumerate(accelerator_entries):
            runtime_type = service["runtime"]["type"]
            if runtime_type == "vm":
                selector = accelerator.get("device", "")
                if accelerator["mode"] != "passthrough" or not selector.startswith("pci:"):
                    raise ManagedServicesV2Error(
                        "VM GPU access requires passthrough mode and an explicit pci: selector",
                        path=f"$.services.{service_id}.resources.accelerators[{index}]",
                        code="gpu-passthrough",
                    )
            elif runtime_type == "compose" and not accelerator.get("target"):
                raise ManagedServicesV2Error(
                    "Compose accelerator requests require an explicit target service",
                    path=f"$.services.{service_id}.resources.accelerators[{index}].target",
                    code="compose-target",
                )
            elif accelerator["mode"] == "passthrough":
                raise ManagedServicesV2Error(
                    "GPU passthrough is currently valid only for VM runtimes",
                    path=f"$.services.{service_id}.resources.accelerators[{index}].mode",
                    code="gpu-mode",
                )

        declared_capabilities = {capability["id"] for capability in service["authorization"]["capabilities"]}
        if len(declared_capabilities) != len(service["authorization"]["capabilities"]):
            raise ManagedServicesV2Error(
                "Duplicate service authorization capability id",
                path=f"$.services.{service_id}.authorization.capabilities",
                code="capability-duplicate",
            )
        for route_id, route in service["routes"].items():
            auth = route["auth"]
            if auth["mode"] == "identity":
                capability = auth["capability"]
                if capability != "access" and capability not in declared_capabilities:
                    raise ManagedServicesV2Error(
                        f"Route references undeclared service capability {capability!r}",
                        path=f"$.services.{service_id}.routes.{route_id}.auth.capability",
                        code="capability-reference",
                    )
            elif "capability" in auth:
                raise ManagedServicesV2Error(
                    "Only identity-protected routes may name a capability",
                    path=f"$.services.{service_id}.routes.{route_id}.auth.capability",
                    code="route-auth",
                )

            exposure = route["exposure"]
            if exposure["type"] == "path":
                for route_path in exposure["paths"]:
                    # Exact duplicates (including normalized trailing-slash variants) must fail closed
                    normalized = route_path.rstrip("/") or "/"
                    for existing_path, existing_owner in route_paths.items():
                        existing_norm = existing_path.rstrip("/") or "/"
                        if normalized == existing_norm:
                            raise ManagedServicesV2Error(
                                f"Duplicate route path {route_path!r}; already used by {existing_owner}",
                                path=f"$.services.{service_id}.routes.{route_id}.exposure.paths",
                                code="route-conflict",
                            )
                    # Parent/child overlaps are allowed only when longest-path-first ordering is guaranteed.
                    # The Caddy renderer sorts by longest path first, so /shares/admin is matched before /shares.
                    # Root "/" shadowing everything and ambiguous non-parent overlaps must still fail closed.
                    for registered_path, registered_owner in route_paths.items():
                        if _routes_conflict(route_path, registered_path):
                            registered_norm = registered_path.rstrip("/") or "/"
                            if normalized == registered_norm:
                                continue  # already handled as duplicate
                            if normalized == "/" or registered_norm == "/":
                                raise ManagedServicesV2Error(
                                    f"Route path {route_path!r} overlaps {registered_path!r} already used by {registered_owner}",
                                    path=f"$.services.{service_id}.routes.{route_id}.exposure.paths",
                                    code="route-overlap",
                                )
                            first_parts = normalized.strip("/").split("/") if normalized != "/" else []
                            second_parts = registered_norm.strip("/").split("/") if registered_norm != "/" else []
                            is_parent = (
                                first_parts[: len(second_parts)] == second_parts
                                or second_parts[: len(first_parts)] == first_parts
                            )
                            if is_parent:
                                continue
                            raise ManagedServicesV2Error(
                                f"Route path {route_path!r} overlaps {registered_path!r} already used by {registered_owner}",
                                path=f"$.services.{service_id}.routes.{route_id}.exposure.paths",
                                code="route-overlap",
                            )
                    route_paths[route_path] = f"{service_id}:{route_id}"
            else:
                for hostname in exposure["hostnames"]:
                    owner = route_hostnames.get(hostname)
                    if owner is not None:
                        raise ManagedServicesV2Error(
                            f"Duplicate route hostname {hostname!r}; already used by {owner}",
                            path=f"$.services.{service_id}.routes.{route_id}.exposure.hostnames",
                            code="route-conflict",
                        )
                    route_hostnames[hostname] = f"{service_id}:{route_id}"

        for listener_id, listener in service["listeners"].items():
            exposure = listener["exposure"]
            if "start" in exposure and exposure["end"] < exposure["start"]:
                raise ManagedServicesV2Error(
                    "Listener range end must not precede start",
                    path=f"$.services.{service_id}.listeners.{listener_id}.exposure",
                    code="listener-range",
                )
            if "targetPort" in listener and "port" not in exposure:
                raise ManagedServicesV2Error(
                    "Listener targetPort remapping requires a single exposed port, not a port range",
                    path=f"$.services.{service_id}.listeners.{listener_id}.targetPort",
                    code="listener-target-port",
                )
            for port in _listener_ports(exposure):
                key = (listener["protocol"], port)
                owner = listener_owners.get(key)
                if owner is not None:
                    raise ManagedServicesV2Error(
                        f"Listener {listener['protocol']}/{port} conflicts with {owner}",
                        path=f"$.services.{service_id}.listeners.{listener_id}.exposure",
                        code="listener-conflict",
                    )
                listener_owners[key] = f"{service_id}:{listener_id}"

        seen_dependencies: set[str] = set()
        for index, dependency in enumerate(service["dependencies"]):
            target_id = dependency["service"]
            if target_id == service_id:
                raise ManagedServicesV2Error(
                    "A service cannot depend on itself",
                    path=f"$.services.{service_id}.dependencies[{index}]",
                    code="dependency-self",
                )
            if target_id in seen_dependencies:
                raise ManagedServicesV2Error(
                    f"Duplicate dependency {target_id!r}",
                    path=f"$.services.{service_id}.dependencies[{index}]",
                    code="dependency-duplicate",
                )
            seen_dependencies.add(target_id)
            target = services.get(target_id)
            if target is None:
                raise ManagedServicesV2Error(
                    f"Unknown dependency {target_id!r}",
                    path=f"$.services.{service_id}.dependencies[{index}].service",
                    code="missing-reference",
                )
            if service["enabled"] and not target["enabled"]:
                raise ManagedServicesV2Error(
                    f"Enabled service {service_id!r} depends on disabled service {target_id!r}",
                    path=f"$.services.{service_id}.dependencies[{index}].service",
                    code="dependency-disabled",
                )
            condition = dependency["condition"]
            target_kind = target["workload"]["kind"]
            if condition == "completed" and target_kind != "job":
                raise ManagedServicesV2Error(
                    "completed dependency condition requires a job target",
                    path=f"$.services.{service_id}.dependencies[{index}].condition",
                    code="dependency-condition",
                )
            if condition == "ready":
                if target_kind == "job":
                    raise ManagedServicesV2Error(
                        "Jobs cannot satisfy a ready dependency; use completed or started",
                        path=f"$.services.{service_id}.dependencies[{index}].condition",
                        code="dependency-condition",
                    )
                if "readiness" not in target:
                    raise ManagedServicesV2Error(
                        "ready dependency target must define readiness probes",
                        path=f"$.services.{service_id}.dependencies[{index}].condition",
                        code="dependency-condition",
                    )

    _validate_dependency_graph(services)


def load_platform_capabilities(path: pathlib.Path = DEFAULT_PLATFORM_PATH) -> set[str]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManagedServicesV2Error(
            f"Unable to read platform capability inventory {path}: {exc}",
            code="platform-read",
        ) from exc
    capabilities = value.get("capabilities") if isinstance(value, dict) else None
    if isinstance(capabilities, dict):
        return {key for key, enabled in capabilities.items() if enabled is True}
    if isinstance(capabilities, list) and all(isinstance(item, str) for item in capabilities):
        return set(capabilities)
    raise ManagedServicesV2Error(
        "Platform capability inventory must contain a capabilities object or string array",
        code="platform-invalid",
    )


def build_effective(document: dict[str, Any]) -> dict[str, Any]:
    effective = copy.deepcopy(document)
    derived_authorization: dict[str, Any] = {}
    derived_runtime: dict[str, Any] = {}
    derived_routes: list[dict[str, Any]] = []

    for service_id, service in effective["services"].items():
        capabilities = {"access": f"application.{service_id}.access"}
        for capability in service["authorization"]["capabilities"]:
            capabilities[capability["id"]] = f"application.{service_id}.{capability['id']}"
        derived_authorization[service_id] = {"capabilities": capabilities}

        runtime = service["runtime"]
        if runtime["type"] == "systemd":
            owner_unit = runtime["unit"]
        else:
            owner_unit = f"nas-v2-{service_id}.service"
        derived_runtime[service_id] = {
            "type": runtime["type"],
            "ownerUnit": owner_unit,
            "managed": service["managed"],
        }

        on_demand = service["workload"]["kind"] == "daemon" and service["workload"].get("activation") == "on-demand"
        for route_id, route in service["routes"].items():
            required_capability = None
            if route["auth"]["mode"] == "identity":
                required_capability = capabilities[route["auth"]["capability"]]
            derived_routes.append(
                {
                    "service": service_id,
                    "route": route_id,
                    "authMode": route["auth"]["mode"],
                    "requiredCapability": required_capability,
                    "onDemandWake": on_demand,
                    "target": copy.deepcopy(route["target"]),
                    "exposure": copy.deepcopy(route["exposure"]),
                    "proxy": copy.deepcopy(route["proxy"]),
                    "portal": copy.deepcopy(route["portal"]),
                }
            )

    effective["derived"] = {
        "authorization": derived_authorization,
        "runtime": derived_runtime,
        "routes": derived_routes,
        "backupResources": sorted(
            resource_id
            for resource_id, resource in effective["storageResources"].items()
            if resource["backup"]["enabled"] and resource["stateClass"] == "authoritative"
        ),
    }
    return effective


def compile_document(
    document: dict[str, Any],
    schema: dict[str, Any],
    *,
    platform_capabilities: set[str] | None = None,
) -> dict[str, Any]:
    validate_schema(document, schema)
    normalized = normalize(document)
    validate_schema(normalized, schema)
    semantic_validate(normalized, platform_capabilities=platform_capabilities)
    return build_effective(normalized)


def load_and_compile(
    spec_path: pathlib.Path = DEFAULT_SPEC_PATH,
    schema_path: pathlib.Path = DEFAULT_SCHEMA_PATH,
    platform_path: pathlib.Path | None = DEFAULT_PLATFORM_PATH,
) -> dict[str, Any]:
    capabilities = None if platform_path is None else load_platform_capabilities(platform_path)
    return compile_document(parse_yaml(spec_path), load_schema(schema_path), platform_capabilities=capabilities)
