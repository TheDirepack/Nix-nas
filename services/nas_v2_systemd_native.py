#!/usr/bin/env python3
"""Native systemd projection for Managed Services V2.

systemd owns lifecycle and activation.  Python project environments are owned
by uv.  This module only lowers desired state into declarative unit files and
runtime descriptors for adapters that genuinely need structured argv.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import subprocess
import tempfile
from typing import Any

from nas_v2_activation import (
    ActivationProjectionError,
    backend_target,
    proxy_unit,
    socket_path,
    socket_unit,
)
from nas_v2_libvirt import LibvirtProjectionError, render_domain_xml, validate_domain_xml
from nas_v2_quadlet import QuadletProjectionError, render_quadlet, validate_quadlets
from nas_v2_systemd_attachments import SystemdAttachmentError, attachment_lines


class SystemdProjectionError(RuntimeError):
    """Raised when a V2 service cannot be lowered to systemd."""


_SAFE_IDENTITY = re.compile(r"^(?:[A-Za-z_][A-Za-z0-9_.-]{0,63}|[0-9]{1,10})$")
APP_ROOT = pathlib.Path("/var/lib/nas-control/apps")
_CTRL = ("\x00", "\r", "\n")


def _has_ctrl(value: str) -> bool:
    return any(c in value for c in _CTRL)


def _single_line(value: str, *, field: str) -> str:
    if _has_ctrl(value):
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


def _owner_unit(effective: dict[str, Any], service_id: str) -> str:
    value = effective["derived"]["runtime"][service_id]["ownerUnit"]
    if not isinstance(value, str) or not value.endswith((".service", ".target", ".socket")):
        raise SystemdProjectionError(f"invalid owner unit for {service_id!r}: {value!r}")
    return value


def _is_on_demand(service: dict[str, Any]) -> bool:
    workload = service["workload"]
    return service["managed"] and workload["kind"] == "daemon" and workload.get("activation") == "on-demand"


def _dependency_lines(effective: dict[str, Any], service: dict[str, Any]) -> list[str]:
    requires: set[str] = set()
    after: set[str] = set()
    for dep in service["dependencies"]:
        owner = _owner_unit(effective, dep["service"])
        requires.add(owner)
        if dep["condition"] == "ready":
            gate = f"nas-v2-ready-{dep['service']}.service"
            requires.add(gate)
            after.add(gate)
        else:
            after.add(owner)
    lines: list[str] = []
    if requires:
        lines.append("Requires=" + " ".join(sorted(requires)))
    if after:
        lines.append("After=" + " ".join(sorted(after)))
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
    lines = ["PrivateTmp=yes", "ProtectHome=yes", f"NoNewPrivileges={'yes' if sandbox['noNewPrivileges'] else 'no'}"]
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
    if identity["mode"] == "dynamic":
        if identity.get("user") or identity.get("group"):
            raise SystemdProjectionError("dynamic identity may not declare user/group")
        return ["DynamicUser=yes"]
    if identity["mode"] != "existing":
        raise SystemdProjectionError(f"unsupported runtime identity mode {identity['mode']!r}")
    user = identity.get("user")
    group = identity.get("group")
    if not isinstance(user, str) or _SAFE_IDENTITY.fullmatch(user) is None:
        raise SystemdProjectionError("existing runtime identity requires a safe user")
    lines = [f"User={user}"]
    if group is not None:
        if not isinstance(group, str) or _SAFE_IDENTITY.fullmatch(group) is None:
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


def _restart_lines(service: dict[str, Any], runtime: dict[str, Any]) -> list[str]:
    restart = "no" if _is_on_demand(service) else runtime["restart"]
    if service["workload"]["kind"] == "job" and restart == "always":
        raise SystemdProjectionError("job runtime may not use restart=always")
    return [] if restart == "no" else [f"Restart={restart}"]


def _unit_header(effective: dict[str, Any], service: dict[str, Any]) -> list[str]:
    return [
        "Description=" + _single_line(service["name"], field="service name"),
        *(["StopWhenUnneeded=yes"] if _is_on_demand(service) else []),
        *_dependency_lines(effective, service),
    ]


def _exec_unit(
    effective: dict[str, Any],
    service: dict[str, Any],
    *,
    python_bin: str,
    source_dir: pathlib.Path,
    descriptor_path: pathlib.Path,
) -> bytes:
    runtime = service["runtime"]
    kind = service["workload"]["kind"]
    lines = [
        "[Unit]",
        *_unit_header(effective, service),
        "",
        "[Service]",
        "Type=oneshot" if kind == "job" else "Type=simple",
        f"ExecStart={_quote(python_bin)} {_quote(str(source_dir / 'nas_v2_exec_runner.py'))} --config {_quote(str(descriptor_path))}",
        *_identity_lines(runtime),
        *_environment_lines(runtime),
        *_resource_lines(service),
        *_sandbox_lines(service),
        *_attachment_lines(effective, service),
        *_restart_lines(service, runtime),
        "",
    ]
    return "\n".join(lines).encode()


def _python_command(service_id: str, runtime: dict[str, Any], *, uv_bin: str) -> tuple[list[str], str | None]:
    _absolute_binary(uv_bin, field=f"Python service {service_id!r} uv binary")
    interpreter = _absolute_binary(runtime["interpreter"], field=f"Python service {service_id!r} interpreter")
    working = pathlib.Path(runtime.get("workingDirectory", str(APP_ROOT / service_id)))
    try:
        working.resolve(strict=False).relative_to((APP_ROOT / service_id).resolve(strict=False))
    except ValueError as exc:
        raise SystemdProjectionError(f"Python service {service_id!r} workingDirectory must remain beneath its app root") from exc
    entrypoint = runtime["entrypoint"]
    program = [interpreter, "-m", entrypoint["module"], *entrypoint["args"]] if "module" in entrypoint else [interpreter, entrypoint["script"], *entrypoint["args"]]
    requirements = runtime["dependencies"].get("requirementsFile")
    requirements_hash: str | None = None
    prefix = [uv_bin, "run", "--python", interpreter]
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
        prefix.extend(["--no-project", "--with-requirements", str(resolved)])
    else:
        pyproject = working / "pyproject.toml"
        lockfile = working / "uv.lock"
        if pyproject.is_file() or lockfile.is_file():
            if not pyproject.is_file() or not lockfile.is_file():
                raise SystemdProjectionError(
                    f"Python service {service_id!r} project mode requires both pyproject.toml and uv.lock"
                )
            prefix.extend(["--project", str(working), "--locked"])
        else:
            prefix.append("--no-project")
    return [*prefix, *program], requirements_hash


def _python_unit(
    effective: dict[str, Any],
    service_id: str,
    service: dict[str, Any],
    *,
    uv_bin: str,
) -> tuple[bytes, str | None]:
    runtime = service["runtime"]
    command, requirements_hash = _python_command(service_id, runtime, uv_bin=uv_bin)
    kind = service["workload"]["kind"]
    working = runtime.get("workingDirectory", str(APP_ROOT / service_id))
    lines = [
        "[Unit]",
        *_unit_header(effective, service),
        "",
        "[Service]",
        "Type=oneshot" if kind == "job" else "Type=simple",
        "ExecStart=" + " ".join(_quote(part) for part in command),
        "WorkingDirectory=" + _quote(working),
        *_identity_lines(runtime),
        *_environment_lines(runtime),
        "CacheDirectory=" + f"nas-v2-uv/{service_id}",
        "CacheDirectoryMode=0750",
        f"Environment={_quote('UV_CACHE_DIR=/var/cache/nas-v2-uv/' + service_id)}",
        *(["Environment=UV_REQUIRE_HASHES=1"] if runtime["dependencies"]["requireHashes"] else []),
        *_resource_lines(service),
        *_sandbox_lines(service),
        *_attachment_lines(effective, service),
        *_restart_lines(service, runtime),
        "",
    ]
    return "\n".join(lines).encode(), requirements_hash


def _existing_dropin(effective: dict[str, Any], service: dict[str, Any]) -> bytes | None:
    unit_lines = [*(["StopWhenUnneeded=yes"] if _is_on_demand(service) else []), *_dependency_lines(effective, service)]
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
    return ("\n".join(lines).rstrip() + "\n").encode()


def _quadlet_source(effective: dict[str, Any], service_id: str, service: dict[str, Any]) -> bytes:
    unit_lines = [
        "Description=" + _single_line(service["name"], field="service name"),
        *(["StopWhenUnneeded=yes"] if _is_on_demand(service) else []),
        *_dependency_lines(effective, service),
    ]
    service_lines = _resource_lines(service)
    if service["workload"]["kind"] == "job":
        service_lines.insert(0, "Type=oneshot")
    try:
        return render_quadlet(effective, service_id, service, unit_lines=unit_lines, service_lines=service_lines)
    except QuadletProjectionError as exc:
        raise SystemdProjectionError(str(exc)) from exc


def _vm_unit(
    effective: dict[str, Any],
    service: dict[str, Any],
    *,
    python_bin: str,
    source_dir: pathlib.Path,
    descriptor_path: pathlib.Path,
) -> bytes:
    libvirt_unit = "libvirtd.service"
    virt = effective.get("services", {}).get("virtualization", {})
    candidate = virt.get("runtime", {}).get("unit") if isinstance(virt, dict) and isinstance(virt.get("runtime"), dict) else None
    if isinstance(candidate, str) and candidate.endswith(".service"):
        libvirt_unit = candidate
    return ("\n".join([
        "[Unit]", "Description=" + _single_line(service["name"], field="service name"),
        f"Requires={libvirt_unit}", f"After={libvirt_unit}",
        *(["StopWhenUnneeded=yes"] if _is_on_demand(service) else []), *_dependency_lines(effective, service), "",
        "[Service]", "Type=oneshot", "RemainAfterExit=yes",
        f"ExecStart={_quote(python_bin)} {_quote(str(source_dir / 'nas_v2_libvirt.py'))} start --config {_quote(str(descriptor_path))}",
        f"ExecStop={_quote(python_bin)} {_quote(str(source_dir / 'nas_v2_libvirt.py'))} stop --config {_quote(str(descriptor_path))}",
        "TimeoutStartSec=0", "TimeoutStopSec=240", "NoNewPrivileges=yes", "PrivateTmp=yes", "ProtectHome=yes", "ProtectSystem=strict", "",
    ])).encode()


def _readiness_unit(
    service_id: str,
    owner: str,
    *,
    python_bin: str,
    source_dir: pathlib.Path,
    descriptor_path: pathlib.Path,
    systemctl_bin: str,
) -> bytes:
    return ("\n".join([
        "[Unit]", f"Description=Managed Services V2 readiness gate for {service_id}", f"Requires={owner}", f"After={owner}", f"PartOf={owner}", "",
        "[Service]", "Type=oneshot",
        f"ExecStart={_quote(python_bin)} {_quote(str(source_dir / 'nas_v2_readiness.py'))} --config {_quote(str(descriptor_path))} --systemctl {_quote(systemctl_bin)}",
        "NoNewPrivileges=yes", "PrivateTmp=yes", "ProtectHome=yes", "ProtectSystem=strict", "",
    ])).encode()


def _systemd_socket_proxyd(systemctl_bin: str) -> str:
    systemctl = pathlib.PurePosixPath(_absolute_binary(systemctl_bin, field="systemctl binary"))
    return str(systemctl.parent.parent / "lib/systemd/systemd-socket-proxyd")


def _derived_route(effective: dict[str, Any], service_id: str, route_id: str) -> dict[str, Any]:
    for route in effective.get("derived", {}).get("routes", []):
        if isinstance(route, dict) and route.get("service") == service_id and route.get("route") == route_id:
            return route
    raise SystemdProjectionError(f"compiled route {service_id}.{route_id} is missing")


def _activation_units(
    effective: dict[str, Any],
    service_id: str,
    service: dict[str, Any],
    owner: str,
    *,
    systemctl_bin: str,
) -> list[tuple[str, bytes, str, bytes]]:
    if not _is_on_demand(service):
        return []
    idle = service["workload"]["idleSeconds"]
    proxyd = _systemd_socket_proxyd(systemctl_bin)
    result: list[tuple[str, bytes, str, bytes]] = []
    for route_id in sorted(service["routes"]):
        route = _derived_route(effective, service_id, route_id)
        if route["authMode"] == "upstream":
            raise SystemdProjectionError(
                f"on-demand service {service_id!r} route {route_id!r} uses upstream-native authentication; activation must be authorized before the backend starts"
            )
        try:
            sun = socket_unit(service_id, route_id)
            pun = proxy_unit(service_id, route_id)
            spath = socket_path(service_id, route_id)
            backend = backend_target(route)
        except ActivationProjectionError as exc:
            raise SystemdProjectionError(str(exc)) from exc
        socket_content = ("\n".join([
            "[Unit]", f"Description=Managed Services V2 activation socket for {service_id}.{route_id}", "",
            "[Socket]", f"ListenStream={spath}", "SocketMode=0600", "SocketUser=caddy", "SocketGroup=caddy",
            "RemoveOnStop=yes", f"Service={pun}", "", "[Install]", "WantedBy=sockets.target", "",
        ])).encode()
        requires = [owner, sun]
        after = [owner, sun]
        if "readiness" in service:
            ready = f"nas-v2-ready-{service_id}.service"
            requires.append(ready)
            after.append(ready)
        proxy_content = ("\n".join([
            "[Unit]", f"Description=Managed Services V2 socket proxy for {service_id}.{route_id}",
            "Requires=" + " ".join(requires), "After=" + " ".join(after), f"PartOf={sun}", "",
            "[Service]", "Type=notify", f"ExecStart={_quote(proxyd)} --exit-idle-time={idle}s {_quote(backend)}",
            "NoNewPrivileges=yes", "PrivateTmp=yes", "ProtectHome=yes", "ProtectSystem=strict", "",
        ])).encode()
        result.append((sun, socket_content, pun, proxy_content))
    if not result:
        raise SystemdProjectionError(f"on-demand service {service_id!r} requires at least one Caddy route for native activation")
    return result


def _timer_unit(service_id: str, owner: str, index: int, schedule: dict[str, Any]) -> tuple[str, bytes]:
    unit = f"nas-v2-timer-{service_id}-{index}.timer"
    lines = ["[Unit]", f"Description=Managed Services V2 schedule {index} for {service_id}", "", "[Timer]", f"Unit={owner}"]
    if "calendar" in schedule:
        lines.extend(["OnCalendar=" + _single_line(schedule["calendar"], field="calendar schedule"), f"Persistent={'true' if schedule['persistent'] else 'false'}"])
    else:
        interval = schedule["intervalSeconds"]
        lines.extend([f"OnBootSec={interval}s", f"OnUnitActiveSec={interval}s"])
    if schedule["randomizedDelaySeconds"]:
        lines.append(f"RandomizedDelaySec={schedule['randomizedDelaySeconds']}s")
    lines.extend(["", "[Install]", "WantedBy=timers.target", ""])
    return unit, "\n".join(lines).encode()


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
    vm_dir = output_dir / "vm"

    for service_id in sorted(effective["services"]):
        service = effective["services"][service_id]
        runtime = service["runtime"]
        owner = _owner_unit(effective, service_id)
        managed = service["managed"]
        source_hash: str | None = None
        requirements_hash: str | None = None
        if runtime["type"] == "exec":
            dpath = descriptor_dir / f"{service_id}.exec.json"
            files[dpath] = _json_bytes({"command": runtime["command"], "workingDirectory": runtime.get("workingDirectory")})
            upath = unit_dir / owner
            files[upath] = _exec_unit(effective, service, python_bin=python_bin, source_dir=source_dir, descriptor_path=dpath)
            links[owner] = str(upath)
        elif runtime["type"] == "python":
            upath = unit_dir / owner
            files[upath], requirements_hash = _python_unit(effective, service_id, service, uv_bin=uv_bin)
            links[owner] = str(upath)
        elif runtime["type"] == "vm":
            _absolute_binary(virsh_bin, field=f"VM service {service_id!r} virsh binary")
            try:
                source_path, domain_name, domain_xml = render_domain_xml(effective, service_id, service)
            except LibvirtProjectionError as exc:
                raise SystemdProjectionError(str(exc)) from exc
            xpath = vm_dir / f"{service_id}.xml"
            files[xpath] = domain_xml
            dpath = descriptor_dir / f"{service_id}.vm.json"
            files[dpath] = _json_bytes({"virsh": virsh_bin, "domain": domain_name, "xml": str(xpath), "shutdownTimeoutSeconds": 180})
            upath = unit_dir / owner
            files[upath] = _vm_unit(effective, service, python_bin=python_bin, source_dir=source_dir, descriptor_path=dpath)
            links[owner] = str(upath)
            source_hash = _sha256_file(source_path)
        elif runtime["type"] == "systemd":
            dropin = _existing_dropin(effective, service)
            if dropin is not None:
                dpath = unit_dir / f"{owner}.d" / "50-nas-v2.conf"
                files[dpath] = dropin
                links[f"{owner}.d/50-nas-v2.conf"] = str(dpath)
        elif runtime["type"] in {"oci", "quadlet"}:
            spath = quadlet_dir / f"nas-v2-{service_id}.container"
            files[spath] = _quadlet_source(effective, service_id, service)
            quadlet_links[spath.name] = str(spath)
        else:
            raise SystemdProjectionError(f"runtime {runtime['type']!r} for service {service_id!r} has no native adapter")

        if "readiness" in service:
            readiness = json.loads(json.dumps(service["readiness"]))
            for probe in readiness["probes"]:
                if probe["type"] == "systemd" and not probe.get("unit"):
                    probe["unit"] = owner
            dpath = descriptor_dir / f"{service_id}.readiness.json"
            files[dpath] = _json_bytes(readiness)
            ready = f"nas-v2-ready-{service_id}.service"
            rpath = unit_dir / ready
            files[rpath] = _readiness_unit(service_id, owner, python_bin=python_bin, source_dir=source_dir, descriptor_path=dpath, systemctl_bin=systemctl_bin)
            links[ready] = str(rpath)
            fingerprints[ready] = _fingerprint(readiness)
            if managed:
                owned_units.add(ready)

        for sun, scontent, pun, pcontent in _activation_units(effective, service_id, service, owner, systemctl_bin=systemctl_bin):
            spath = unit_dir / sun
            ppath = unit_dir / pun
            files[spath] = scontent
            files[ppath] = pcontent
            links[sun] = str(spath)
            links[pun] = str(ppath)
            owned_units.update({sun, pun})
            if service["enabled"]:
                start_units.add(sun)
            else:
                stop_units.update({sun, pun})

        if service["workload"]["kind"] == "job":
            for index, schedule in enumerate(service["workload"]["schedules"]):
                timer, content = _timer_unit(service_id, owner, index, schedule)
                tpath = unit_dir / timer
                files[tpath] = content
                links[timer] = str(tpath)
                if managed:
                    owned_units.add(timer)
                    (start_units if service["enabled"] else stop_units).add(timer)

        if managed:
            owned_units.add(owner)
            if not service["enabled"]:
                stop_units.add(owner)
                if "readiness" in service:
                    stop_units.add(f"nas-v2-ready-{service_id}.service")
            elif service["workload"]["kind"] == "daemon" and service["workload"]["activation"] == "persistent":
                start_units.add(owner)

        fp: dict[str, Any] = {
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
        if requirements_hash is not None:
            fp["requirementsSha256"] = requirements_hash
        if source_hash is not None:
            fp["runtimeSourceSha256"] = source_hash
        fingerprints[owner] = _fingerprint(fp)

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
    unit_files = {p: d for p, d in files.items() if p.suffix in {".service", ".timer", ".target", ".socket", ".path"}}
    if unit_files:
        with tempfile.TemporaryDirectory(prefix="nas-v2-systemd-verify-") as raw_tmp:
            tmp = pathlib.Path(raw_tmp)
            verify_paths: list[str] = []
            for src, data in unit_files.items():
                dst = tmp / src.name
                dst.write_bytes(data)
                verify_paths.append(str(dst))
            result = subprocess.run([systemd_analyze_bin, "verify", *verify_paths], capture_output=True, text=True, timeout=30, check=False)
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


__all__ = ["APP_ROOT", "SystemdProjectionError", "generate_projection", "validate_projection"]
