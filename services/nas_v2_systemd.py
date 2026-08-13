#!/usr/bin/env python3
"""Generate native systemd projections for Managed Services V2 workloads.

systemd remains the lifecycle owner across host processes, Python services,
Compose projects, VMs, and Podman/Quadlet generated services. This module only
compiles finite unit/source files and a reconciliation manifest; it never runs
as a resident controller.
"""

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
from nas_v2_systemd_attachments import SystemdAttachmentError, attachment_lines


class SystemdProjectionError(RuntimeError):
    """Raised when a V2 service cannot be faithfully lowered to systemd."""


_SAFE_IDENTITY = re.compile(r"^(?:[A-Za-z_][A-Za-z0-9_.-]{0,63}|[0-9]{1,10})$")
APP_ROOT = pathlib.Path("/var/lib/nas-control/apps")
VENV_ROOT = pathlib.Path("/var/lib/nas-control/venvs")


def _single_line(value: str, *, field: str) -> str:
    if any(character in value for character in ("\x00", "\r", "\n")):
        raise SystemdProjectionError(f"{field} contains a forbidden control character")
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


def _venv_path(service_id: str) -> pathlib.Path:
    return VENV_ROOT / service_id / "venv"


def _owner_unit(effective: dict[str, Any], service_id: str) -> str:
    value = effective["derived"]["runtime"][service_id]["ownerUnit"]
    if not isinstance(value, str) or not value.endswith((".service", ".target")):
        raise SystemdProjectionError(f"invalid owner unit for {service_id!r}: {value!r}")
    return value


def _ready_unit(service_id: str) -> str:
    return f"nas-v2-ready-{service_id}.service"


def _lease_unit_name(service_id: str) -> str:
    return f"nas-v2-lease-{service_id}.target"


def _idle_timer_name(service_id: str) -> str:
    return f"nas-v2-idle-{service_id}.timer"


def _idle_stop_name(service_id: str) -> str:
    return f"nas-v2-idle-stop-{service_id}.service"


def _is_managed_on_demand(service: dict[str, Any]) -> bool:
    workload = service["workload"]
    return service["managed"] and workload["kind"] == "daemon" and workload.get("activation") == "on-demand"


def _owner_lifecycle_lines(service: dict[str, Any]) -> list[str]:
    return ["StopWhenUnneeded=yes"] if _is_managed_on_demand(service) else []


def _dependency_lines(effective: dict[str, Any], service: dict[str, Any]) -> list[str]:
    requires: list[str] = []
    after: list[str] = []
    for dependency in service["dependencies"]:
        target = dependency["service"]
        owner = _owner_unit(effective, target)
        requires.append(owner)
        if dependency["condition"] == "ready":
            gate = _ready_unit(target)
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
    resources = service["resources"]
    lines: list[str] = []
    if "cpuQuotaPercent" in resources:
        lines.append(f"CPUQuota={resources['cpuQuotaPercent']}%")
    if "memoryHighBytes" in resources:
        lines.append(f"MemoryHigh={resources['memoryHighBytes']}")
    if "memoryMaxBytes" in resources:
        lines.append(f"MemoryMax={resources['memoryMaxBytes']}")
    if "pidsMax" in resources:
        lines.append(f"TasksMax={resources['pidsMax']}")
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
        capability_list = " ".join(add)
        lines.extend([f"CapabilityBoundingSet={capability_list}", f"AmbientCapabilities={capability_list}"])
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
    environment = runtime.get("environment", {})
    if not isinstance(environment, dict):
        raise SystemdProjectionError("environment must be an object")
    lines: list[str] = []
    for name, value in sorted(environment.items()):
        if not isinstance(name, str) or not name or "=" in name or "\x00" in name or "\n" in name or "\r" in name:
            raise SystemdProjectionError(f"invalid environment variable name {name!r}")
        if not isinstance(value, str) or "\x00" in value or "\n" in value or "\r" in value:
            raise SystemdProjectionError(f"invalid environment value for {name!r}")
        lines.append(f"Environment={_quote(f'{name}={value}')}")
    return lines


def _attachment_lines(effective: dict[str, Any], service: dict[str, Any]) -> list[str]:
    try:
        return attachment_lines(effective, service)
    except SystemdAttachmentError as exc:
        raise SystemdProjectionError(str(exc)) from exc


def _ensure_supported_generated(service_id: str, service: dict[str, Any], runtime_type: str) -> None:
    if service["workload"]["kind"] == "session":
        raise SystemdProjectionError(f"{runtime_type} service {service_id!r} session templates are not implemented yet")


def _exec_unit(
    effective: dict[str, Any],
    service_id: str,
    service: dict[str, Any],
    *,
    python_bin: str,
    source_dir: pathlib.Path,
    descriptor_path: pathlib.Path,
) -> str:
    _ensure_supported_generated(service_id, service, "exec")
    runtime = service["runtime"]
    kind = service["workload"]["kind"]
    lines = [
        "[Unit]",
        "Description=" + _single_line(service["name"], field="service name"),
        *_owner_lifecycle_lines(service),
        *_dependency_lines(effective, service),
        "",
        "[Service]",
        "Type=oneshot" if kind == "job" else "Type=simple",
        f"ExecStart={_quote(python_bin)} {_quote(str(source_dir / 'nas_v2_exec_runner.py'))} --config {_quote(str(descriptor_path))}",
        *_identity_lines(runtime),
        *_environment_lines(runtime),
        *_resource_lines(service),
        *_sandbox_lines(service),
        *_attachment_lines(effective, service),
    ]
    restart = runtime["restart"]
    if _is_managed_on_demand(service):
        restart = "no"
    if kind == "job" and restart == "always":
        raise SystemdProjectionError("job exec runtime may not use restart=always")
    if restart != "no":
        lines.append(f"Restart={restart}")
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

    environment_input = {
        "uv": uv_bin,
        "interpreter": interpreter,
        "requirementsFile": requirements,
        "requirementsSha256": requirements_hash,
        "requireHashes": runtime["dependencies"]["requireHashes"],
    }
    environment_fingerprint = _fingerprint(environment_input)
    descriptor = {
        "serviceId": service_id,
        "uv": uv_bin,
        "interpreter": interpreter,
        "venv": str(_venv_path(service_id)),
        "requireHashes": runtime["dependencies"]["requireHashes"],
        "environmentFingerprint": environment_fingerprint,
    }
    if requirements is not None:
        descriptor["requirementsFile"] = requirements
        descriptor["requirementsSha256"] = requirements_hash
    return descriptor, environment_fingerprint


def _python_exec_descriptor(service_id: str, runtime: dict[str, Any]) -> dict[str, Any]:
    venv_python = _venv_path(service_id) / "bin" / "python"
    entrypoint = runtime["entrypoint"]
    if "module" in entrypoint:
        command = [str(venv_python), "-m", entrypoint["module"], *entrypoint["args"]]
    else:
        command = [str(venv_python), entrypoint["script"], *entrypoint["args"]]
    return {
        "command": command,
        "workingDirectory": runtime.get("workingDirectory", str(APP_ROOT / service_id)),
    }


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
    _ensure_supported_generated(service_id, service, "python")
    runtime = service["runtime"]
    kind = service["workload"]["kind"]
    state_directory = f"nas-control/venvs/{service_id}"
    cache_directory = f"nas-v2-uv/{service_id}"
    lines = [
        "[Unit]",
        "Description=" + _single_line(service["name"], field="service name"),
        *_owner_lifecycle_lines(service),
        *_dependency_lines(effective, service),
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
    ]
    restart = runtime["restart"]
    if _is_managed_on_demand(service):
        restart = "no"
    if kind == "job" and restart == "always":
        raise SystemdProjectionError("job Python runtime may not use restart=always")
    if restart != "no":
        lines.append(f"Restart={restart}")
    return "\n".join(lines) + "\n"


def _existing_dropin(effective: dict[str, Any], service: dict[str, Any]) -> str | None:
    unit_lines = [*_owner_lifecycle_lines(service), *_dependency_lines(effective, service)]
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
        *_owner_lifecycle_lines(service),
        *_dependency_lines(effective, service),
    ]
    service_lines = _resource_lines(service)
    if service["workload"]["kind"] == "job":
        service_lines.insert(0, "Type=oneshot")
    try:
        return render_quadlet(
            effective,
            service_id,
            service,
            unit_lines=unit_lines,
            service_lines=service_lines,
        )
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
            *_owner_lifecycle_lines(service),
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
    return "\n".join(
        [
            "[Unit]",
            "Description=" + _single_line(service["name"], field="service name"),
            "Requires=libvirtd.service",
            "After=libvirtd.service",
            *_owner_lifecycle_lines(service),
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
        requires.append(_ready_unit(service_id))
        after.append(_ready_unit(service_id))
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
    lease = _lease_unit_name(service_id)
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
            f"Unit={_idle_stop_name(service_id)}",
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
    """Generate staged files and a reconcile manifest without mutating systemd."""
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
        environment_fingerprint: str | None = None
        runtime_source_fingerprint: str | None = None

        if runtime["type"] == "exec":
            descriptor = {
                "command": runtime["command"],
                "workingDirectory": runtime.get("workingDirectory"),
            }
            descriptor_path = descriptor_dir / f"{service_id}.exec.json"
            files[descriptor_path] = _json_bytes(descriptor)
            unit_path = unit_dir / owner
            files[unit_path] = _exec_unit(
                effective,
                service_id,
                service,
                python_bin=python_bin,
                source_dir=source_dir,
                descriptor_path=descriptor_path,
            ).encode()
            links[owner] = str(unit_path)
        elif runtime["type"] == "python":
            environment_descriptor, environment_fingerprint = _python_environment(
                service_id,
                runtime,
                uv_bin=uv_bin,
            )
            environment_descriptor_path = descriptor_dir / f"{service_id}.python-env.json"
            files[environment_descriptor_path] = _json_bytes(environment_descriptor)
            exec_descriptor_path = descriptor_dir / f"{service_id}.python-exec.json"
            files[exec_descriptor_path] = _json_bytes(_python_exec_descriptor(service_id, runtime))
            unit_path = unit_dir / owner
            files[unit_path] = _python_unit(
                effective,
                service_id,
                service,
                python_bin=python_bin,
                source_dir=source_dir,
                exec_descriptor_path=exec_descriptor_path,
                environment_descriptor_path=environment_descriptor_path,
            ).encode()
            links[owner] = str(unit_path)
        elif runtime["type"] == "compose":
            try:
                source_path, override = render_compose_override(effective, service_id, service)
            except ComposeProjectionError as exc:
                raise SystemdProjectionError(str(exc)) from exc
            override_path = compose_dir / f"{service_id}.override.yaml"
            files[override_path] = override
            unit_path = unit_dir / owner
            files[unit_path] = _compose_unit(
                effective,
                service_id,
                service,
                source_path=source_path,
                override_path=override_path,
                podman_bin=podman_bin,
                compose_provider_bin=compose_provider_bin,
            ).encode()
            links[owner] = str(unit_path)
            runtime_source_fingerprint = _sha256_file(source_path)
        elif runtime["type"] == "vm":
            _absolute_binary(virsh_bin, field=f"VM service {service_id!r} virsh binary")
            try:
                source_path, domain_name, domain_xml = render_domain_xml(effective, service_id, service)
            except LibvirtProjectionError as exc:
                raise SystemdProjectionError(str(exc)) from exc
            xml_path = vm_dir / f"{service_id}.xml"
            files[xml_path] = domain_xml
            descriptor_path = descriptor_dir / f"{service_id}.vm.json"
            files[descriptor_path] = _json_bytes(
                {
                    "virsh": virsh_bin,
                    "domain": domain_name,
                    "xml": str(xml_path),
                    "shutdownTimeoutSeconds": 180,
                }
            )
            unit_path = unit_dir / owner
            files[unit_path] = _vm_unit(
                effective,
                service_id,
                service,
                python_bin=python_bin,
                source_dir=source_dir,
                descriptor_path=descriptor_path,
            ).encode()
            links[owner] = str(unit_path)
            runtime_source_fingerprint = _sha256_file(source_path)
        elif runtime["type"] == "systemd":
            dropin = _existing_dropin(effective, service)
            if dropin is not None:
                dropin_path = unit_dir / f"{owner}.d" / "50-nas-v2.conf"
                files[dropin_path] = dropin.encode()
                links[f"{owner}.d/50-nas-v2.conf"] = str(dropin_path)
        elif runtime["type"] in {"oci", "quadlet"}:
            source_path = quadlet_dir / f"nas-v2-{service_id}.container"
            files[source_path] = _quadlet_source(effective, service_id, service)
            quadlet_links[source_path.name] = str(source_path)
        else:
            raise SystemdProjectionError(
                f"runtime {runtime['type']!r} for service {service_id!r} needs its native adapter before systemd projection"
            )

        if "readiness" in service:
            readiness = json.loads(json.dumps(service["readiness"]))
            for probe in readiness["probes"]:
                if probe["type"] == "systemd" and not probe.get("unit"):
                    probe["unit"] = owner
            descriptor_path = descriptor_dir / f"{service_id}.readiness.json"
            files[descriptor_path] = _json_bytes(readiness)
            ready_unit = _ready_unit(service_id)
            ready_path = unit_dir / ready_unit
            files[ready_path] = _readiness_unit(
                service_id,
                owner,
                python_bin=python_bin,
                source_dir=source_dir,
                descriptor_path=descriptor_path,
                systemctl_bin=systemctl_bin,
            ).encode()
            links[ready_unit] = str(ready_path)
            fingerprints[ready_unit] = _fingerprint(readiness)
            if managed:
                owned_units.add(ready_unit)

        if _is_managed_on_demand(service):
            lease = _lease_unit_name(service_id)
            lease_path = unit_dir / lease
            files[lease_path] = _lease_unit(
                service_id,
                owner,
                has_readiness="readiness" in service,
            ).encode()
            links[lease] = str(lease_path)

            idle_stop = _idle_stop_name(service_id)
            idle_stop_path = unit_dir / idle_stop
            files[idle_stop_path] = _idle_stop_unit(service_id, systemctl_bin=systemctl_bin).encode()
            links[idle_stop] = str(idle_stop_path)

            idle_timer = _idle_timer_name(service_id)
            idle_timer_path = unit_dir / idle_timer
            files[idle_timer_path] = _idle_timer_unit(
                service_id,
                idle_seconds=service["workload"]["idleSeconds"],
            ).encode()
            links[idle_timer] = str(idle_timer_path)

            owned_units.update({lease, idle_stop, idle_timer})
            if not service["enabled"]:
                stop_units.update({lease, idle_stop, idle_timer})

        if service["workload"]["kind"] == "job":
            for index, schedule in enumerate(service["workload"]["schedules"]):
                timer_unit, timer_content = _timer_unit(service_id, owner, index, schedule)
                timer_path = unit_dir / timer_unit
                files[timer_path] = timer_content.encode()
                links[timer_unit] = str(timer_path)
                if managed:
                    owned_units.add(timer_unit)
                    if service["enabled"]:
                        start_units.add(timer_unit)
                    else:
                        stop_units.add(timer_unit)

        if managed:
            owned_units.add(owner)
            if not service["enabled"]:
                stop_units.add(owner)
                if "readiness" in service:
                    stop_units.add(_ready_unit(service_id))
            elif service["workload"]["kind"] == "daemon" and service["workload"]["activation"] == "persistent":
                start_units.add(owner)

        fingerprint_value = {
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
        if environment_fingerprint is not None:
            fingerprint_value["pythonEnvironment"] = environment_fingerprint
        if runtime_source_fingerprint is not None:
            fingerprint_value["runtimeSourceSha256"] = runtime_source_fingerprint
        fingerprints[owner] = _fingerprint(fingerprint_value)

    manifest = {
        "schemaVersion": 1,
        "links": [{"target": target, "source": source} for target, source in sorted(links.items())],
        "quadletLinks": [{"target": target, "source": source} for target, source in sorted(quadlet_links.items())],
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
    """Validate generated systemd, Quadlet, and libvirt sources before activation."""
    unit_files = {path: data for path, data in files.items() if path.suffix in {".service", ".timer", ".target"}}
    if unit_files:
        with tempfile.TemporaryDirectory(prefix="nas-v2-systemd-verify-") as raw_tmp:
            tmp = pathlib.Path(raw_tmp)
            verify_paths: list[str] = []
            for source_path, data in unit_files.items():
                destination = tmp / source_path.name
                destination.write_bytes(data)
                verify_paths.append(str(destination))
            result = subprocess.run(
                [systemd_analyze_bin, "verify", *verify_paths],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()[:4000]
            raise SystemdProjectionError(f"systemd-analyze rejected generated units: {detail}")

    has_quadlets = any(path.suffix == ".container" for path in files)
    if has_quadlets:
        if quadlet_generator_bin is None:
            raise SystemdProjectionError("Quadlet projection requires a Podman system generator binary")
        try:
            validate_quadlets(files, generator_bin=quadlet_generator_bin)
        except QuadletProjectionError as exc:
            raise SystemdProjectionError(str(exc)) from exc

    vm_xml = [data for path, data in files.items() if path.parent.name == "vm" and path.suffix == ".xml"]
    if vm_xml:
        if virt_xml_validate_bin is None:
            raise SystemdProjectionError("VM projection requires a virt-xml-validate binary")
        try:
            for content in vm_xml:
                validate_domain_xml(content, validator_bin=virt_xml_validate_bin)
        except LibvirtProjectionError as exc:
            raise SystemdProjectionError(str(exc)) from exc


__all__ = ["SystemdProjectionError", "generate_projection", "validate_projection"]
