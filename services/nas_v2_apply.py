#!/usr/bin/env python3
"""Transactional file-level apply primitives for Managed Services V2.

The core materializes derived effective/plan files transactionally. Native
projection adapters stage their files through the same boundary before any
reload/reconcile action is permitted.
"""

from __future__ import annotations

import json
import os
import pathlib
import tempfile
from dataclasses import dataclass
from typing import Any

from nas_v2_accelerator import enabled_capabilities, load_platform_inventory, resolve_effective
from nas_v2_backup import compile_backup_projection
from nas_v2_caddy import generate_caddyfile, validate_caddyfile
from nas_v2_firewalld import materialize_projection as materialize_firewalld_projection
from nas_v2_plan import build_plan
from nas_v2_podman_network import PodmanNetworkProjectionError, requires_firewalld
from nas_v2_podman_network import augment_projection as augment_podman_networks
from nas_v2_portal import portal_bytes
from nas_v2_session_projection import SessionProjectionError
from nas_v2_session_projection import generate_projection as generate_systemd_projection
from nas_v2_source_watch import (
    SourceWatchProjectionError,
    augment_projection,
    validate_source_watches,
)
from nas_v2_spec import (
    DEFAULT_PLATFORM_PATH,
    DEFAULT_SCHEMA_PATH,
    DEFAULT_SPEC_PATH,
    ManagedServicesV2Error,
    compile_document,
    load_schema,
    parse_yaml,
    parse_yaml_text,
)
from nas_v2_systemd import SystemdProjectionError
from nas_v2_systemd import validate_projection as validate_systemd_projection


@dataclass(frozen=True)
class ApplyPaths:
    desired: pathlib.Path = DEFAULT_SPEC_PATH
    schema: pathlib.Path = DEFAULT_SCHEMA_PATH
    platform: pathlib.Path | None = DEFAULT_PLATFORM_PATH
    effective: pathlib.Path = pathlib.Path("/run/nas-control/effective.json")
    plan: pathlib.Path = pathlib.Path("/run/nas-control/plan.json")


@dataclass(frozen=True)
class CaddyProjection:
    output: pathlib.Path
    caddy_bin: str
    authentik_upstream: str = "127.0.0.1:9000"
    authentik_path: str = "/identity/"
    lan_host: str = "nas.local"
    wake_socket: str | None = None


@dataclass(frozen=True)
class SystemdProjection:
    output_dir: pathlib.Path
    systemd_analyze_bin: str
    python_bin: str
    source_dir: pathlib.Path
    systemctl_bin: str
    uv_bin: str
    quadlet_generator_bin: str | None = None
    podman_bin: str = "podman"
    compose_provider_bin: str = "podman-compose"
    virsh_bin: str = "virsh"
    virt_xml_validate_bin: str | None = None
    nmcli_bin: str = "nmcli"
    install_bin: str = "install"
    rm_bin: str = "rm"


@dataclass(frozen=True)
class BackupProjection:
    inventory: pathlib.Path
    restic_paths: pathlib.Path


@dataclass(frozen=True)
class FirewalldProjection:
    output_dir: pathlib.Path
    lan_zone: str
    firewall_offline_cmd: str


@dataclass(frozen=True)
class PortalProjection:
    output: pathlib.Path


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _prepare_temp(path: pathlib.Path, data: bytes, mode: int) -> pathlib.Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, raw_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp = pathlib.Path(raw_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp, mode)
        return temp
    except Exception:
        temp.unlink(missing_ok=True)
        raise


def _fsync_directory(directory: pathlib.Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _replace_bundle(files: list[tuple[pathlib.Path, bytes, int]]) -> set[pathlib.Path]:
    """Replace changed generated files as one bundle, restoring previous bytes on failure."""
    changed_files: list[tuple[pathlib.Path, bytes, int]] = []
    for path, data, mode in files:
        try:
            if path.read_bytes() == data and path.stat().st_mode & 0o777 == mode:
                continue
        except FileNotFoundError:
            pass
        changed_files.append((path, data, mode))

    prepared: list[tuple[pathlib.Path, pathlib.Path]] = []
    previous: dict[pathlib.Path, tuple[bytes, int] | None] = {}
    try:
        for path, data, mode in changed_files:
            try:
                stat_result = path.stat()
                previous[path] = (path.read_bytes(), stat_result.st_mode & 0o777)
            except FileNotFoundError:
                previous[path] = None
            prepared.append((path, _prepare_temp(path, data, mode)))

        replaced: list[pathlib.Path] = []
        try:
            for path, temp in prepared:
                os.replace(temp, path)
                replaced.append(path)
            for directory in {path.parent for path in replaced}:
                _fsync_directory(directory)
        except Exception:
            for path in reversed(replaced):
                old = previous[path]
                if old is None:
                    path.unlink(missing_ok=True)
                    continue
                rollback = _prepare_temp(path, old[0], old[1])
                os.replace(rollback, path)
                _fsync_directory(path.parent)
            raise
    finally:
        for _path, temp in prepared:
            temp.unlink(missing_ok=True)
    return {path for path, _data, _mode in changed_files}


def _compile_document_with_platform(
    document: dict[str, Any],
    schema: dict[str, Any],
    platform_path: pathlib.Path | None,
) -> dict[str, Any]:
    inventory = None if platform_path is None else load_platform_inventory(platform_path)
    effective = compile_document(
        document,
        schema,
        platform_capabilities=None if inventory is None else enabled_capabilities(inventory),
    )
    return effective if inventory is None else resolve_effective(effective, inventory)


def compile_paths(paths: ApplyPaths) -> tuple[dict[str, Any], dict[str, Any]]:
    schema = load_schema(paths.schema)
    effective = _compile_document_with_platform(parse_yaml(paths.desired), schema, paths.platform)
    return effective, build_plan(effective)


def _caddy_bytes(effective: dict[str, Any], projection: CaddyProjection) -> bytes:
    content = generate_caddyfile(
        effective,
        authentik_upstream=projection.authentik_upstream,
        authentik_path=projection.authentik_path,
        lan_host=projection.lan_host,
        wake_socket=projection.wake_socket,
    )
    validate_caddyfile(content, caddy_bin=projection.caddy_bin)
    return content.encode("utf-8")


def _systemd_files(
    effective: dict[str, Any],
    projection: SystemdProjection,
    *,
    firewalld_enabled: bool,
) -> list[tuple[pathlib.Path, bytes, int]]:
    try:
        generated, manifest = generate_systemd_projection(
            effective,
            output_dir=projection.output_dir,
            python_bin=projection.python_bin,
            source_dir=projection.source_dir,
            systemctl_bin=projection.systemctl_bin,
            uv_bin=projection.uv_bin,
            podman_bin=projection.podman_bin,
            compose_provider_bin=projection.compose_provider_bin,
            virsh_bin=projection.virsh_bin,
        )
        augment_podman_networks(
            effective,
            output_dir=projection.output_dir,
            files=generated,
            manifest=manifest,
            firewalld_enabled=firewalld_enabled,
            nmcli_bin=projection.nmcli_bin,
            install_bin=projection.install_bin,
            rm_bin=projection.rm_bin,
        )
        augment_projection(
            effective,
            output_dir=projection.output_dir,
            files=generated,
            manifest=manifest,
        )
        validate_source_watches(generated, systemd_analyze_bin=projection.systemd_analyze_bin)
    except (PodmanNetworkProjectionError, SessionProjectionError, SourceWatchProjectionError) as exc:
        raise SystemdProjectionError(str(exc)) from exc
    generated[projection.output_dir / "manifest.json"] = _json_bytes(manifest)
    validate_systemd_projection(
        generated,
        systemd_analyze_bin=projection.systemd_analyze_bin,
        quadlet_generator_bin=projection.quadlet_generator_bin,
        virt_xml_validate_bin=projection.virt_xml_validate_bin,
    )
    return [(path, content, 0o644) for path, content in generated.items()]


def _backup_files(
    effective: dict[str, Any],
    projection: BackupProjection,
) -> list[tuple[pathlib.Path, bytes, int]]:
    inventory, restic_paths = compile_backup_projection(effective)
    return [
        (projection.inventory, inventory, 0o640),
        (projection.restic_paths, restic_paths, 0o640),
    ]


def _firewalld_files(
    effective: dict[str, Any],
    projection: FirewalldProjection,
) -> list[tuple[pathlib.Path, bytes, int]]:
    return materialize_firewalld_projection(
        effective,
        output_dir=projection.output_dir,
        lan_zone=projection.lan_zone,
        firewall_offline_cmd=projection.firewall_offline_cmd,
    )


def apply(
    paths: ApplyPaths = ApplyPaths(),
    *,
    caddy: CaddyProjection | None = None,
    systemd: SystemdProjection | None = None,
    backup: BackupProjection | None = None,
    firewalld: FirewalldProjection | None = None,
    portal: PortalProjection | None = None,
) -> dict[str, Any]:
    effective, plan = compile_paths(paths)
    try:
        needs_firewalld = requires_firewalld(effective)
    except PodmanNetworkProjectionError as exc:
        raise SystemdProjectionError(str(exc)) from exc
    if needs_firewalld and firewalld is None:
        raise SystemdProjectionError(
            "desired state requires V2 firewalld policy, but this apply transaction has no firewalld projection"
        )

    files = [
        (paths.effective, _json_bytes(effective), 0o640),
        (paths.plan, _json_bytes(plan), 0o640),
    ]
    if caddy is not None:
        files.append((caddy.output, _caddy_bytes(effective, caddy), 0o644))
    if portal is not None:
        files.append((portal.output, portal_bytes(effective), 0o644))
    if systemd is not None:
        files.extend(_systemd_files(effective, systemd, firewalld_enabled=firewalld is not None))
    if backup is not None:
        files.extend(_backup_files(effective, backup))
    if firewalld is not None:
        files.extend(_firewalld_files(effective, firewalld))
    changed = _replace_bundle(files)
    plan["changedFiles"] = sorted(str(path) for path in changed)
    return plan


def save_and_apply(yaml_text: str, paths: ApplyPaths = ApplyPaths()) -> dict[str, Any]:
    """Validate draft YAML, atomically save authority, compile, and roll back on failure."""
    schema = load_schema(paths.schema)
    document = parse_yaml_text(yaml_text, source="<draft>")
    effective = _compile_document_with_platform(document, schema, paths.platform)
    plan = build_plan(effective)

    try:
        old_stat = paths.desired.stat()
        old_desired: tuple[bytes, int] | None = (paths.desired.read_bytes(), old_stat.st_mode & 0o777)
    except FileNotFoundError:
        old_desired = None

    desired_temp = _prepare_temp(paths.desired, yaml_text.encode("utf-8"), 0o660)
    try:
        os.replace(desired_temp, paths.desired)
        _fsync_directory(paths.desired.parent)
        try:
            _replace_bundle(
                [
                    (paths.effective, _json_bytes(effective), 0o640),
                    (paths.plan, _json_bytes(plan), 0o640),
                ]
            )
        except Exception:
            if old_desired is None:
                paths.desired.unlink(missing_ok=True)
            else:
                rollback = _prepare_temp(paths.desired, old_desired[0], old_desired[1])
                os.replace(rollback, paths.desired)
            _fsync_directory(paths.desired.parent)
            raise
    finally:
        desired_temp.unlink(missing_ok=True)

    return plan


__all__ = [
    "ApplyPaths",
    "BackupProjection",
    "CaddyProjection",
    "FirewalldProjection",
    "ManagedServicesV2Error",
    "PortalProjection",
    "SystemdProjection",
    "apply",
    "compile_paths",
    "save_and_apply",
]
