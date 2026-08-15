#!/usr/bin/env python3
"""Generate native systemd projections for Managed Services V2 workloads."""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import subprocess
import tempfile
from typing import Any

from nas_v2_compose import ComposeProjectionError, render_compose_override
from nas_v2_libvirt import LibvirtProjectionError, render_domain_xml, validate_domain_xml
from nas_v2_quadlet import QuadletProjectionError, render_quadlet, validate_quadlets


class SystemdAttachmentError(RuntimeError):
    """Raised when an attachment cannot be represented safely by systemd."""


_SAFE_CREDENTIAL_ID = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_PROTECTED_HOME_ROOTS = (
    pathlib.PurePosixPath("/home"),
    pathlib.PurePosixPath("/root"),
    pathlib.PurePosixPath("/run/user"),
)
_DEV_ROOT = pathlib.PurePosixPath("/dev")


def _quote_attachment(value: str) -> str:
    if any(character in value for character in ("\x00", "\r", "\n")):
        raise SystemdAttachmentError("systemd attachment path contains a forbidden control character")
    return '"' + value.replace("%", "%%").replace("\\", "\\\\").replace('"', '\\"') + '"'


def _bind_path(value: str, *, field: str) -> pathlib.PurePosixPath:
    path = pathlib.PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts:
        raise SystemdAttachmentError(f"{field} must be an absolute safe path")
    if ":" in value:
        raise SystemdAttachmentError(f"{field} may not contain ':'")
    return path


def _bind_value(source: pathlib.PurePosixPath, destination: pathlib.PurePosixPath) -> str:
    if source == destination:
        return str(source)
    return f"{source}:{destination}"


def _under(path: pathlib.PurePosixPath, root: pathlib.PurePosixPath) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _protect_home_conflict(service: dict[str, Any], destination: pathlib.PurePosixPath, *, label: str) -> None:
    if service.get("sandbox", {}).get("mode") == "strict" and any(
        _under(destination, root) for root in _PROTECTED_HOME_ROOTS
    ):
        raise SystemdAttachmentError(f"{label} {destination} conflicts with generated ProtectHome=yes sandboxing")


def _storage_lines(effective: dict[str, Any], service: dict[str, Any]) -> list[str]:
    resources = effective.get("storageResources", {})
    if not isinstance(resources, dict):
        raise SystemdAttachmentError("compiled storageResources must be an object")
    runtime = service.get("runtime", {})
    identity = runtime.get("identity", {}) if isinstance(runtime, dict) else {}
    generated_runtime = isinstance(runtime, dict) and runtime.get("type") in {"exec", "python"}
    dynamic_identity = generated_runtime and isinstance(identity, dict) and identity.get("mode") == "dynamic"

    lines: list[str] = []
    for attachment in service.get("storage", []):
        if not isinstance(attachment, dict):
            raise SystemdAttachmentError("compiled storage attachment is invalid")
        resource_id = attachment.get("resource")
        resource = resources.get(resource_id) if isinstance(resource_id, str) else None
        if not isinstance(resource, dict) or not isinstance(resource.get("path"), str):
            raise SystemdAttachmentError(f"storage resource {resource_id!r} is missing from effective state")
        source = _bind_path(resource["path"], field=f"storage resource {resource_id!r} path")
        mount_path = attachment.get("mountPath")
        if not isinstance(mount_path, str):
            raise SystemdAttachmentError("storage attachment mountPath is missing")
        destination = _bind_path(mount_path, field="storage attachment mountPath")
        _protect_home_conflict(service, destination, label="storage mount")
        access = attachment.get("access")
        value = _bind_value(source, destination)
        if access == "read":
            lines.append(f"BindReadOnlyPaths={_quote_attachment(value)}")
        elif access == "write":
            if dynamic_identity:
                raise SystemdAttachmentError(
                    "writable host storage requires runtime.identity.mode=existing; refusing DynamicUser writable bind"
                )
            lines.append(f"BindPaths={_quote_attachment(value)}")
        else:
            raise SystemdAttachmentError(f"unsupported storage access mode {access!r}")
    return lines


def _credential_lines(effective: dict[str, Any], service: dict[str, Any]) -> list[str]:
    credentials = effective.get("credentials", {})
    if not isinstance(credentials, dict):
        raise SystemdAttachmentError("compiled credentials must be an object")

    lines: list[str] = []
    seen_native_ids: set[str] = set()
    seen_mounts: set[str] = set()
    for attachment in service.get("credentials", []):
        if not isinstance(attachment, dict):
            raise SystemdAttachmentError("compiled credential attachment is invalid")
        credential_id = attachment.get("credential")
        credential = credentials.get(credential_id) if isinstance(credential_id, str) else None
        if not isinstance(credential, dict) or not isinstance(credential.get("path"), str):
            raise SystemdAttachmentError(f"credential {credential_id!r} is missing from effective state")
        source_path = _bind_path(credential["path"], field=f"credential {credential_id!r} path")
        required = credential.get("required") is not False
        use = attachment.get("use")

        if use == "environment-file":
            prefix = "" if required else "-"
            lines.append(f"EnvironmentFile={prefix}{_quote_attachment(str(source_path))}")
            continue

        if use == "native-reference":
            if not required:
                raise SystemdAttachmentError(
                    f"optional native-reference credential {credential_id!r} is not safely representable yet"
                )
            if not isinstance(credential_id, str) or not _SAFE_CREDENTIAL_ID.fullmatch(credential_id):
                raise SystemdAttachmentError(f"credential identifier {credential_id!r} is unsafe for LoadCredential=")
            if credential_id in seen_native_ids:
                raise SystemdAttachmentError(f"duplicate native credential identifier {credential_id!r}")
            seen_native_ids.add(credential_id)
            lines.append(f"LoadCredential={_quote_attachment(credential_id + ':' + str(source_path))}")
            continue

        if use == "file":
            mount_path = attachment.get("mountPath")
            if not isinstance(mount_path, str):
                raise SystemdAttachmentError(f"file credential {credential_id!r} requires mountPath")
            destination = _bind_path(mount_path, field=f"file credential {credential_id!r} mountPath")
            _protect_home_conflict(service, destination, label="credential mount")
            destination_text = str(destination)
            if destination_text in seen_mounts:
                raise SystemdAttachmentError(f"duplicate file credential mount target {destination_text!r}")
            seen_mounts.add(destination_text)
            source_text = str(source_path)
            if not required:
                source_text = "-" + source_text
            lines.append(f"BindReadOnlyPaths={_quote_attachment(source_text + ':' + destination_text)}")
            continue
        raise SystemdAttachmentError(f"unsupported credential use {use!r}")
    return lines


def _accelerator_lines(service: dict[str, Any]) -> list[str]:
    resources = service.get("resources", {})
    accelerators = resources.get("accelerators", []) if isinstance(resources, dict) else []
    if not accelerators:
        return []
    runtime = service.get("runtime", {})
    identity = runtime.get("identity", {}) if isinstance(runtime, dict) else {}
    if isinstance(runtime, dict) and runtime.get("type") in {"exec", "python"}:
        if isinstance(identity, dict) and identity.get("mode") == "dynamic":
            raise SystemdAttachmentError(
                "generated host workloads with GPU access require runtime.identity.mode=existing so device DAC/group access is explicit"
            )
    lines = ["DevicePolicy=closed"]
    seen: set[str] = set()
    for accelerator in accelerators:
        if not isinstance(accelerator, dict) or accelerator.get("mode") != "shared":
            raise SystemdAttachmentError("systemd accelerator request was not resolved to shared device access")
        device = accelerator.get("device")
        if not isinstance(device, str):
            raise SystemdAttachmentError("systemd accelerator request is missing a concrete device selector")
        path = _bind_path(device, field="accelerator device")
        try:
            path.relative_to(_DEV_ROOT)
        except ValueError as exc:
            raise SystemdAttachmentError("systemd accelerators must resolve to device nodes beneath /dev") from exc
        value = str(path)
        if value not in seen:
            lines.append(f"DeviceAllow={_quote_attachment(value + ' rw')}")
            seen.add(value)
    return lines


def attachment_lines(effective: dict[str, Any], service: dict[str, Any]) -> list[str]:
    """Return deterministic systemd [Service] directives for host attachments."""
    return [
        *_storage_lines(effective, service),
        *_credential_lines(effective, service),
        *_accelerator_lines(service),
    ]


__all__ = ["SystemdAttachmentError", "attachment_lines"]


class SystemdProjectionError(RuntimeError):
    """Raised when a V2 service cannot be lowered to systemd."""


_SAFE_IDENTITY = re.compile(r"^(?:[A-Za-z_][A-Za-z0-9_.-]{0,63}|[0-9]{1,10})$")
APP_ROOT = pathlib.Path("/var/lib/nas-control/apps")
VENV_ROOT = pathlib.Path("/var/lib/nas-control/venvs")
_CTRL = ("\x00", "\r", "\n")


def _has_ctrl(value: str) -> bool:
    return any(c in value for c in _CTRL)


def _reject_ctrl(value: str, field: str) -> None:
    if _has_ctrl(value):
        raise SystemdProjectionError(f"{field} contains a forbidden control character")


def _single_line(value: str, *, field: str) -> str:
    _reject_ctrl(value, field)
    return value.replace("%", "%%")


def _quote(value: str) -> str:
    safe = _single_line(value, field="systemd argument")
    return '"' + safe.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _fingerprint(value: Any) -> str:
    return hashlib.sha256(_json_bytes(value)).hexdigest()


def _sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise SystemdProjectionError(f"unable to read managed source file {path}: {exc}") from exc
    return digest.hexdigest()


def _absolute_binary(value: str, *, field: str) -> str:
    candidate = pathlib.PurePosixPath(value)
    if not candidate.is_absolute() or ".." in candidate.parts:
        raise SystemdProjectionError(f"{field} must be an absolute safe path")
    return value


def _owner_unit(effective: dict[str, Any], service_id: str) -> str:
    value = effective["derived"]["runtime"][service_id]["ownerUnit"]
    if not isinstance(value, str) or not value.endswith((".service", ".target")):
        raise SystemdProjectionError(f"invalid owner unit for {service_id!r}: {value!r}")
    return value


def _is_managed_on_demand(service: dict[str, Any]) -> bool:
    w = service["workload"]
    return service["managed"] and w["kind"] == "daemon" and w.get("activation") == "on-demand"


def _lifecycle_unit_lines(service: dict[str, Any]) -> list[str]:
    return ["StopWhenUnneeded=yes"] if _is_managed_on_demand(service) else []


def _dependency_lines(effective: dict[str, Any], service: dict[str, Any]) -> list[str]:
    requires: list[str] = []
    after: list[str] = []
    for dep in service["dependencies"]:
        target = dep["service"]
        owner = _owner_unit(effective, target)
        requires.append(owner)
        if dep["condition"] == "ready":
            gate = f"nas-v2-ready-{target}.service"
            requires.append(gate)
            after.append(gate)
        else:
            after.append(owner)
    lines: list[str] = []
    if requires:
        lines.append("Requires=" + " ".join(sorted(set(requires))))
    if after:
        lines.append("After=" + " ".join(sorted(set(after))))
    return lines


def _resource_lines(service: dict[str, Any]) -> list[str]:
    r = service["resources"]
    lines: list[str] = []
    if "cpuQuotaPercent" in r:
        lines.append(f"CPUQuota={r['cpuQuotaPercent']}%")
    if "memoryHighBytes" in r:
        lines.append(f"MemoryHigh={r['memoryHighBytes']}")
    if "memoryMaxBytes" in r:
        lines.append(f"MemoryMax={r['memoryMaxBytes']}")
    if "pidsMax" in r:
        lines.append(f"TasksMax={r['pidsMax']}")
    return lines


def _sandbox_lines(service: dict[str, Any]) -> list[str]:
    sandbox = service["sandbox"]
    if sandbox["mode"] == "inherit":
        return []
    lines = [
        "PrivateTmp=yes",
        "ProtectHome=yes",
        f"NoNewPrivileges={'yes' if sandbox['noNewPrivileges'] else 'no'}",
    ]
    if sandbox["readOnlyRoot"]:
        lines.append("ProtectSystem=strict")
    for path in sandbox["writablePaths"]:
        lines.append("ReadWritePaths=" + _quote(path))
    for mount in sandbox["tmpfs"]:
        value = mount["path"]
        if "sizeBytes" in mount:
            value += f":size={mount['sizeBytes']}"
        lines.append("TemporaryFileSystem=" + _quote(value))
    add = sandbox["addCapabilities"]
    drop = sandbox["dropCapabilities"]
    if set(add) & set(drop):
        raise SystemdProjectionError("sandbox capability may not be both added and dropped")
    if add:
        caps = " ".join(add)
        lines.extend([f"CapabilityBoundingSet={caps}", f"AmbientCapabilities={caps}"])
    elif drop:
        lines.append("CapabilityBoundingSet=~" + " ".join(drop))
    return lines


def _identity_lines(runtime: dict[str, Any]) -> list[str]:
    identity = runtime["identity"]
    mode = identity["mode"]
    if mode == "dynamic":
        if identity.get("user") or identity.get("group"):
            raise SystemdProjectionError("dynamic identity may not declare user/group")
        return ["DynamicUser=yes"]
    if mode != "existing":
        raise SystemdProjectionError(f"unsupported runtime identity mode {mode!r}")
    user = identity.get("user")
    group = identity.get("group")
    if not isinstance(user, str) or not _SAFE_IDENTITY.fullmatch(user):
        raise SystemdProjectionError("existing runtime identity requires a safe user")
    lines = [f"User={user}"]
    if group is not None:
        if not isinstance(group, str) or not _SAFE_IDENTITY.fullmatch(group):
            raise SystemdProjectionError("existing runtime identity group is unsafe")
        lines.append(f"Group={group}")
    return lines


def _environment_lines(runtime: dict[str, Any]) -> list[str]:
    env = runtime.get("environment", {})
    if not isinstance(env, dict):
        raise SystemdProjectionError("environment must be an object")
    lines: list[str] = []
    for name, value in sorted(env.items()):
        if not isinstance(name, str) or not name or "=" in name or _has_ctrl(name):
            raise SystemdProjectionError(f"invalid environment variable name {name!r}")
        if not isinstance(value, str) or _has_ctrl(value):
            raise SystemdProjectionError(f"invalid environment value for {name!r}")
        lines.append(f"Environment={_quote(f'{name}={value}')}")
    return lines


def _attachment_lines(effective: dict[str, Any], service: dict[str, Any]) -> list[str]:
    try:
        return attachment_lines(effective, service)
    except SystemdAttachmentError as exc:
        raise SystemdProjectionError(str(exc)) from exc


def _restart_line(service: dict[str, Any], runtime: dict[str, Any], kind: str) -> list[str]:
    restart = runtime["restart"]
    if _is_managed_on_demand(service):
        restart = "no"
    if kind == "job" and restart == "always":
        label = "Python" if runtime["type"] == "python" else runtime["type"]
        raise SystemdProjectionError(f"job {label} runtime may not use restart=always")
    return [] if restart == "no" else [f"Restart={restart}"]


def _unit_header(service: dict[str, Any], effective: dict[str, Any]) -> list[str]:
    return [
        "Description=" + _single_line(service["name"], field="service name"),
        *_lifecycle_unit_lines(service),
        *_dependency_lines(effective, service),
    ]


def _exec_unit(
    effective: dict[str, Any],
    service_id: str,
    service: dict[str, Any],
    *,
    python_bin: str,
    source_dir: pathlib.Path,
    descriptor_path: pathlib.Path,
) -> str:
    if service["workload"]["kind"] == "session":
        raise SystemdProjectionError(f"exec service {service_id!r} session templates are not implemented yet")
    runtime = service["runtime"]
    kind = service["workload"]["kind"]
    lines = [
        "[Unit]",
        *_unit_header(service, effective),
        "",
        "[Service]",
        "Type=oneshot" if kind == "job" else "Type=simple",
        f"ExecStart={_quote(python_bin)} {_quote(str(source_dir / 'nas_v2_exec_runner.py'))} --config {_quote(str(descriptor_path))}",
        *_identity_lines(runtime),
        *_environment_lines(runtime),
        *_resource_lines(service),
        *_sandbox_lines(service),
        *_attachment_lines(effective, service),
        *_restart_line(service, runtime, kind),
    ]
    return "\n".join(lines) + "\n"


def _python_environment(service_id: str, runtime: dict[str, Any], *, uv_bin: str) -> tuple[dict[str, Any], str]:
    _absolute_binary(uv_bin, field=f"Python service {service_id!r} uv binary")
    interpreter = runtime["interpreter"]
    _absolute_binary(interpreter, field=f"Python service {service_id!r} interpreter")
    requirements = runtime["dependencies"].get("requirementsFile")
    requirements_hash: str | None = None
    if requirements is not None:
        candidate = pathlib.Path(requirements)
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to((APP_ROOT / service_id).resolve(strict=False))
        except (OSError, ValueError) as exc:
            raise SystemdProjectionError(
                f"Python service {service_id!r} requirementsFile must exist beneath its managed app root"
            ) from exc
        if not resolved.is_file():
            raise SystemdProjectionError(f"Python service {service_id!r} requirementsFile must name a file")
        requirements_hash = _sha256_file(resolved)
    env_input = {
        "uv": uv_bin,
        "interpreter": interpreter,
        "requirementsFile": requirements,
        "requirementsSha256": requirements_hash,
        "requireHashes": runtime["dependencies"]["requireHashes"],
    }
    fingerprint = _fingerprint(env_input)
    descriptor: dict[str, Any] = {
        "serviceId": service_id,
        "uv": uv_bin,
        "interpreter": interpreter,
        "venv": str(VENV_ROOT / service_id / "venv"),
        "requireHashes": runtime["dependencies"]["requireHashes"],
        "environmentFingerprint": fingerprint,
    }
    if requirements is not None:
        descriptor["requirementsFile"] = requirements
        descriptor["requirementsSha256"] = requirements_hash
    return descriptor, fingerprint


def _python_exec_descriptor(service_id: str, runtime: dict[str, Any]) -> dict[str, Any]:
    venv_python = VENV_ROOT / service_id / "venv" / "bin" / "python"
    entrypoint = runtime["entrypoint"]
    cmd = (
        [str(venv_python), "-m", entrypoint["module"], *entrypoint["args"]]
        if "module" in entrypoint
        else [str(venv_python), entrypoint["script"], *entrypoint["args"]]
    )
    return {"command": cmd, "workingDirectory": runtime.get("workingDirectory", str(APP_ROOT / service_id))}


def _python_unit(
    effective: dict[str, Any],
    service_id: str,
    service: dict[str, Any],
    *,
    python_bin: str,
    source_dir: pathlib.Path,
    exec_descriptor_path: pathlib.Path,
    environment_descriptor_path: pathlib.Path,
) -> str:
    if service["workload"]["kind"] == "session":
        raise SystemdProjectionError(f"python service {service_id!r} session templates are not implemented yet")
    runtime = service["runtime"]
    kind = service["workload"]["kind"]
    state_directory = f"nas-control/venvs/{service_id}"
    cache_directory = f"nas-v2-uv/{service_id}"
    lines = [
        "[Unit]",
        *_unit_header(service, effective),
        "",
        "[Service]",
        "Type=oneshot" if kind == "job" else "Type=simple",
        f"ExecStartPre={_quote(python_bin)} {_quote(str(source_dir / 'nas_v2_python_prepare.py'))} --config {_quote(str(environment_descriptor_path))}",
        f"ExecStart={_quote(python_bin)} {_quote(str(source_dir / 'nas_v2_exec_runner.py'))} --config {_quote(str(exec_descriptor_path))}",
        *_identity_lines(runtime),
        *_environment_lines(runtime),
        f"StateDirectory={state_directory}",
        "StateDirectoryMode=0750",
        f"CacheDirectory={cache_directory}",
        "CacheDirectoryMode=0750",
        f"Environment=UV_CACHE_DIR=/var/cache/{cache_directory}",
        *_resource_lines(service),
        *_sandbox_lines(service),
        *_attachment_lines(effective, service),
        *_restart_line(service, runtime, kind),
    ]
    return "\n".join(lines) + "\n"


def _existing_dropin(effective: dict[str, Any], service: dict[str, Any]) -> str | None:
    unit_lines = [*_lifecycle_unit_lines(service), *_dependency_lines(effective, service)]
    service_lines = [*_resource_lines(service), *_attachment_lines(effective, service)]
    if service["sandbox"]["mode"] == "strict":
        service_lines.extend(_sandbox_lines(service))
    if not unit_lines and not service_lines:
        return None
    lines: list[str] = []
    if unit_lines:
        lines.extend(["[Unit]", *unit_lines, ""])
    if service_lines:
        lines.extend(["[Service]", *service_lines, ""])
    return "\n".join(lines).rstrip() + "\n"


def _quadlet_source(effective: dict[str, Any], service_id: str, service: dict[str, Any]) -> bytes:
    if service["workload"]["kind"] == "session":
        raise SystemdProjectionError(
            f"{service['runtime']['type']} service {service_id!r} session templates are not implemented yet"
        )
    unit_lines = [
        "Description=" + _single_line(service["name"], field="service name"),
        *_lifecycle_unit_lines(service),
        *_dependency_lines(effective, service),
    ]
    service_lines = _resource_lines(service)
    if service["workload"]["kind"] == "job":
        service_lines.insert(0, "Type=oneshot")
    try:
        return render_quadlet(effective, service_id, service, unit_lines=unit_lines, service_lines=service_lines)
    except QuadletProjectionError as exc:
        raise SystemdProjectionError(str(exc)) from exc


def _compose_unit(
    effective: dict[str, Any],
    service_id: str,
    service: dict[str, Any],
    *,
    source_path: pathlib.Path,
    override_path: pathlib.Path,
    podman_bin: str,
    compose_provider_bin: str,
) -> str:
    _absolute_binary(podman_bin, field=f"Compose service {service_id!r} Podman binary")
    _absolute_binary(compose_provider_bin, field=f"Compose service {service_id!r} provider binary")
    project = f"nas-v2-{service_id}"
    common = [
        _quote(podman_bin),
        "compose",
        "--project-name",
        _quote(project),
        "--file",
        _quote(str(source_path)),
        "--file",
        _quote(str(override_path)),
    ]
    start = " ".join([*common, "up", "--detach", "--remove-orphans"])
    stop = " ".join([*common, "down", "--remove-orphans"])
    return "\n".join(
        [
            "[Unit]",
            "Description=" + _single_line(service["name"], field="service name"),
            *_lifecycle_unit_lines(service),
            *_dependency_lines(effective, service),
            "",
            "[Service]",
            "Type=oneshot",
            "RemainAfterExit=yes",
            "Environment=" + _quote(f"PODMAN_COMPOSE_PROVIDER={compose_provider_bin}"),
            f"ExecStart={start}",
            f"ExecStop={stop}",
            "TimeoutStartSec=0",
            "",
        ]
    )


def _vm_unit(
    effective: dict[str, Any],
    service_id: str,
    service: dict[str, Any],
    *,
    python_bin: str,
    source_dir: pathlib.Path,
    descriptor_path: pathlib.Path,
) -> str:
    # libvirtd is platform substrate when virtualization is enabled; derive the
    # unit name from the V2 virtualization service when present, otherwise use
    # the well-known platform unit as fallback for pre-V2 callers.
    libvirt_unit = "libvirtd.service"  # pragma: no cover - V2 integration
    try:  # pragma: no cover
        virt = effective.get("services", {}).get("virtualization", {})
        candidate = virt.get("runtime", {}).get("unit") if isinstance(virt.get("runtime"), dict) else None
        if isinstance(candidate, str) and candidate.endswith(".service"):
            libvirt_unit = candidate
    except (AttributeError, TypeError):  # pragma: no cover
        pass
    return "\n".join(
        [
            "[Unit]",
            "Description=" + _single_line(service["name"], field="service name"),
            f"Requires={libvirt_unit}",
            f"After={libvirt_unit}",
            *_lifecycle_unit_lines(service),
            *_dependency_lines(effective, service),
            "",
            "[Service]",
            "Type=oneshot",
            "RemainAfterExit=yes",
            f"ExecStart={_quote(python_bin)} {_quote(str(source_dir / 'nas_v2_libvirt.py'))} start --config {_quote(str(descriptor_path))}",
            f"ExecStop={_quote(python_bin)} {_quote(str(source_dir / 'nas_v2_libvirt.py'))} stop --config {_quote(str(descriptor_path))}",
            "TimeoutStartSec=0",
            "TimeoutStopSec=240",
            "NoNewPrivileges=yes",
            "PrivateTmp=yes",
            "ProtectHome=yes",
            "ProtectSystem=strict",
            "",
        ]
    )


def _readiness_unit(
    service_id: str,
    owner_unit: str,
    *,
    python_bin: str,
    source_dir: pathlib.Path,
    descriptor_path: pathlib.Path,
    systemctl_bin: str,
) -> str:
    return "\n".join(
        [
            "[Unit]",
            f"Description=Managed Services V2 readiness gate for {service_id}",
            f"Requires={owner_unit}",
            f"After={owner_unit}",
            f"PartOf={owner_unit}",
            "",
            "[Service]",
            "Type=oneshot",
            f"ExecStart={_quote(python_bin)} {_quote(str(source_dir / 'nas_v2_readiness.py'))} --config {_quote(str(descriptor_path))} --systemctl {_quote(systemctl_bin)}",
            "NoNewPrivileges=yes",
            "PrivateTmp=yes",
            "ProtectHome=yes",
            "ProtectSystem=strict",
            "",
        ]
    )


def _lease_unit(service_id: str, owner_unit: str, *, has_readiness: bool) -> str:
    requires = [owner_unit]
    after = [owner_unit]
    if has_readiness:
        ready = f"nas-v2-ready-{service_id}.service"
        requires.append(ready)
        after.append(ready)
    return "\n".join(
        [
            "[Unit]",
            f"Description=Managed Services V2 on-demand lease for {service_id}",
            "Requires=" + " ".join(requires),
            "After=" + " ".join(after),
            "",
        ]
    )


def _idle_stop_unit(service_id: str, *, systemctl_bin: str) -> str:
    lease = f"nas-v2-lease-{service_id}.target"
    return "\n".join(
        [
            "[Unit]",
            f"Description=Release Managed Services V2 on-demand lease for {service_id}",
            "",
            "[Service]",
            "Type=oneshot",
            f"ExecStart={_quote(systemctl_bin)} stop {_quote(lease)}",
            "NoNewPrivileges=yes",
            "PrivateTmp=yes",
            "ProtectHome=yes",
            "ProtectSystem=strict",
            "",
        ]
    )


def _idle_timer_unit(service_id: str, *, idle_seconds: int) -> str:
    return "\n".join(
        [
            "[Unit]",
            f"Description=Managed Services V2 idle timer for {service_id}",
            "",
            "[Timer]",
            f"OnActiveSec={idle_seconds}s",
            f"Unit=nas-v2-idle-stop-{service_id}.service",
            "AccuracySec=1s",
            "",
        ]
    )


def _timer_unit(service_id: str, owner_unit: str, index: int, schedule: dict[str, Any]) -> tuple[str, str]:
    unit = f"nas-v2-timer-{service_id}-{index}.timer"
    lines = [
        "[Unit]",
        f"Description=Managed Services V2 schedule {index} for {service_id}",
        "",
        "[Timer]",
        f"Unit={owner_unit}",
    ]
    if "calendar" in schedule:
        lines.append("OnCalendar=" + _single_line(schedule["calendar"], field="calendar schedule"))
        lines.append(f"Persistent={'true' if schedule['persistent'] else 'false'}")
    else:
        interval = schedule["intervalSeconds"]
        lines.extend([f"OnBootSec={interval}s", f"OnUnitActiveSec={interval}s"])
    if schedule["randomizedDelaySeconds"]:
        lines.append(f"RandomizedDelaySec={schedule['randomizedDelaySeconds']}s")
    lines.extend(["", "[Install]", "WantedBy=timers.target", ""])
    return unit, "\n".join(lines)


def generate_projection(
    effective: dict[str, Any],
    *,
    output_dir: pathlib.Path,
    python_bin: str,
    source_dir: pathlib.Path,
    systemctl_bin: str,
    uv_bin: str,
    podman_bin: str = "podman",
    compose_provider_bin: str = "podman-compose",
    virsh_bin: str = "virsh",
) -> tuple[dict[pathlib.Path, bytes], dict[str, Any]]:
    files: dict[pathlib.Path, bytes] = {}
    links: dict[str, str] = {}
    quadlet_links: dict[str, str] = {}
    start_units: set[str] = set()
    owned_units: set[str] = set()
    stop_units: set[str] = set()
    fingerprints: dict[str, str] = {}
    unit_dir = output_dir / "units"
    descriptor_dir = output_dir / "descriptors"
    quadlet_dir = output_dir / "quadlet"
    compose_dir = output_dir / "compose"
    vm_dir = output_dir / "vm"
    services = effective["services"]
    for service_id in sorted(services):
        service = services[service_id]
        runtime = service["runtime"]
        owner = _owner_unit(effective, service_id)
        managed = service["managed"]
        env_fp: str | None = None
        src_fp: str | None = None
        if runtime["type"] == "exec":
            descriptor = {"command": runtime["command"], "workingDirectory": runtime.get("workingDirectory")}
            dpath = descriptor_dir / f"{service_id}.exec.json"
            files[dpath] = _json_bytes(descriptor)
            upath = unit_dir / owner
            files[upath] = _exec_unit(
                effective, service_id, service, python_bin=python_bin, source_dir=source_dir, descriptor_path=dpath
            ).encode()
            links[owner] = str(upath)
        elif runtime["type"] == "python":
            env_desc, env_fp = _python_environment(service_id, runtime, uv_bin=uv_bin)
            env_path = descriptor_dir / f"{service_id}.python-env.json"
            files[env_path] = _json_bytes(env_desc)
            exec_path = descriptor_dir / f"{service_id}.python-exec.json"
            files[exec_path] = _json_bytes(_python_exec_descriptor(service_id, runtime))
            upath = unit_dir / owner
            files[upath] = _python_unit(
                effective,
                service_id,
                service,
                python_bin=python_bin,
                source_dir=source_dir,
                exec_descriptor_path=exec_path,
                environment_descriptor_path=env_path,
            ).encode()
            links[owner] = str(upath)
        elif runtime["type"] == "compose":
            try:
                source_path, override = render_compose_override(effective, service_id, service)
            except ComposeProjectionError as exc:
                raise SystemdProjectionError(str(exc)) from exc
            opath = compose_dir / f"{service_id}.override.yaml"
            files[opath] = override
            upath = unit_dir / owner
            files[upath] = _compose_unit(
                effective,
                service_id,
                service,
                source_path=source_path,
                override_path=opath,
                podman_bin=podman_bin,
                compose_provider_bin=compose_provider_bin,
            ).encode()
            links[owner] = str(upath)
            src_fp = _sha256_file(source_path)
        elif runtime["type"] == "vm":
            _absolute_binary(virsh_bin, field=f"VM service {service_id!r} virsh binary")
            try:
                source_path, domain_name, domain_xml = render_domain_xml(effective, service_id, service)
            except LibvirtProjectionError as exc:
                raise SystemdProjectionError(str(exc)) from exc
            xpath = vm_dir / f"{service_id}.xml"
            files[xpath] = domain_xml
            dpath = descriptor_dir / f"{service_id}.vm.json"
            files[dpath] = _json_bytes(
                {"virsh": virsh_bin, "domain": domain_name, "xml": str(xpath), "shutdownTimeoutSeconds": 180}
            )
            upath = unit_dir / owner
            files[upath] = _vm_unit(
                effective, service_id, service, python_bin=python_bin, source_dir=source_dir, descriptor_path=dpath
            ).encode()
            links[owner] = str(upath)
            src_fp = _sha256_file(source_path)
        elif runtime["type"] == "systemd":
            dropin = _existing_dropin(effective, service)
            if dropin is not None:
                dpath = unit_dir / f"{owner}.d" / "50-nas-v2.conf"
                files[dpath] = dropin.encode()
                links[f"{owner}.d/50-nas-v2.conf"] = str(dpath)
        elif runtime["type"] in {"oci", "quadlet"}:
            spath = quadlet_dir / f"nas-v2-{service_id}.container"
            files[spath] = _quadlet_source(effective, service_id, service)
            quadlet_links[spath.name] = str(spath)
        else:
            raise SystemdProjectionError(
                f"runtime {runtime['type']!r} for service {service_id!r} needs its native adapter before systemd projection"
            )
        if "readiness" in service:
            readiness = json.loads(json.dumps(service["readiness"]))
            for probe in readiness["probes"]:
                if probe["type"] == "systemd" and not probe.get("unit"):
                    probe["unit"] = owner
            dpath = descriptor_dir / f"{service_id}.readiness.json"
            files[dpath] = _json_bytes(readiness)
            ready_unit = f"nas-v2-ready-{service_id}.service"
            rpath = unit_dir / ready_unit
            files[rpath] = _readiness_unit(
                service_id,
                owner,
                python_bin=python_bin,
                source_dir=source_dir,
                descriptor_path=dpath,
                systemctl_bin=systemctl_bin,
            ).encode()
            links[ready_unit] = str(rpath)
            fingerprints[ready_unit] = _fingerprint(readiness)
            if managed:
                owned_units.add(ready_unit)
        if _is_managed_on_demand(service):
            lease = f"nas-v2-lease-{service_id}.target"
            lpath = unit_dir / lease
            files[lpath] = _lease_unit(service_id, owner, has_readiness="readiness" in service).encode()
            links[lease] = str(lpath)
            idle_stop = f"nas-v2-idle-stop-{service_id}.service"
            spath = unit_dir / idle_stop
            files[spath] = _idle_stop_unit(service_id, systemctl_bin=systemctl_bin).encode()
            links[idle_stop] = str(spath)
            idle_timer = f"nas-v2-idle-{service_id}.timer"
            tpath = unit_dir / idle_timer
            files[tpath] = _idle_timer_unit(service_id, idle_seconds=service["workload"]["idleSeconds"]).encode()
            links[idle_timer] = str(tpath)
            owned_units.update({lease, idle_stop, idle_timer})
            if not service["enabled"]:
                stop_units.update({lease, idle_stop, idle_timer})
        if service["workload"]["kind"] == "job":
            for idx, schedule in enumerate(service["workload"]["schedules"]):
                tun, tcontent = _timer_unit(service_id, owner, idx, schedule)
                tpath = unit_dir / tun
                files[tpath] = tcontent.encode()
                links[tun] = str(tpath)
                if managed:
                    owned_units.add(tun)
                    if service["enabled"]:
                        start_units.add(tun)
                    else:
                        stop_units.add(tun)
        if managed:
            owned_units.add(owner)
            if not service["enabled"]:
                stop_units.add(owner)
                if "readiness" in service:
                    stop_units.add(f"nas-v2-ready-{service_id}.service")
            elif service["workload"]["kind"] == "daemon" and service["workload"]["activation"] == "persistent":
                start_units.add(owner)
        fp_val: dict[str, Any] = {
            "runtime": runtime,
            "dependencies": service["dependencies"],
            "resources": service["resources"],
            "sandbox": service["sandbox"],
            "workload": service["workload"],
            "storage": service["storage"],
            "credentials": service["credentials"],
            "network": service.get("network"),
            "networkProfile": service.get("networkProfile"),
        }
        if env_fp is not None:
            fp_val["pythonEnvironment"] = env_fp
        if src_fp is not None:
            fp_val["runtimeSourceSha256"] = src_fp
        fingerprints[owner] = _fingerprint(fp_val)
    manifest = {
        "schemaVersion": 1,
        "links": [{"target": t, "source": s} for t, s in sorted(links.items())],
        "quadletLinks": [{"target": t, "source": s} for t, s in sorted(quadlet_links.items())],
        "ownedUnits": sorted(owned_units),
        "startUnits": sorted(start_units),
        "stopUnits": sorted(stop_units),
        "fingerprints": fingerprints,
    }
    files[output_dir / "manifest.json"] = _json_bytes(manifest)
    return files, manifest


def validate_projection(
    files: dict[pathlib.Path, bytes],
    *,
    systemd_analyze_bin: str,
    quadlet_generator_bin: str | None = None,
    virt_xml_validate_bin: str | None = None,
) -> None:
    unit_files = {p: d for p, d in files.items() if p.suffix in {".service", ".timer", ".target"}}
    if unit_files:
        with tempfile.TemporaryDirectory(prefix="nas-v2-systemd-verify-") as raw_tmp:
            tmp = pathlib.Path(raw_tmp)
            verify_paths: list[str] = []
            for src, data in unit_files.items():
                dst = tmp / src.name
                dst.write_bytes(data)
                verify_paths.append(str(dst))
            result = subprocess.run(
                [systemd_analyze_bin, "verify", *verify_paths], capture_output=True, text=True, timeout=30, check=False
            )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()[:4000]
            raise SystemdProjectionError(f"systemd-analyze rejected generated units: {detail}")
    if any(p.suffix == ".container" for p in files):
        if quadlet_generator_bin is None:
            raise SystemdProjectionError("Quadlet projection requires a Podman system generator binary")
        try:
            validate_quadlets(files, generator_bin=quadlet_generator_bin)
        except QuadletProjectionError as exc:
            raise SystemdProjectionError(str(exc)) from exc
    vm_xml = [d for p, d in files.items() if p.parent.name == "vm" and p.suffix == ".xml"]
    if vm_xml:
        if virt_xml_validate_bin is None:
            raise SystemdProjectionError("VM projection requires a virt-xml-validate binary")
        try:
            for content in vm_xml:
                validate_domain_xml(content, validator_bin=virt_xml_validate_bin)
        except LibvirtProjectionError as exc:
            raise SystemdProjectionError(str(exc)) from exc


__all__ = ["SystemdProjectionError", "generate_projection", "validate_projection"]
