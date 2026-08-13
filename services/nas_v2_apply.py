#!/usr/bin/env python3
"""Transactional file-level apply primitives for Managed Services V2.

The core materializes derived effective/plan files transactionally. Native
projection adapters stage their files through the same boundary before any
reload/reconcile action is permitted.
"""

from __future__ import annotations

import copy
import json
import os
import pathlib
import stat
import tempfile
from dataclasses import dataclass, field
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

try:
    from nas_v2_editor import authority_lock
except ImportError:  # pragma: no cover - fallback for minimal test harnesses
    from contextlib import contextmanager as _cm

    @_cm
    def authority_lock(path: pathlib.Path):  # type: ignore[no-redef]  # pyright: ignore[reportAssignmentType]
        yield


def _is_directory_authority(path: pathlib.Path) -> bool:
    try:
        return path.is_dir()
    except OSError:
        return False


def _yaml_files(directory: pathlib.Path) -> list[pathlib.Path]:
    try:
        entries = list(directory.iterdir())
    except OSError:
        return []
    files = [p for p in entries if p.is_file() and p.suffix.lower() in {".yaml", ".yml"}]
    return sorted(files, key=lambda p: p.name)


def _desired_target(path: pathlib.Path) -> pathlib.Path:
    if path.is_dir():
        files = _yaml_files(path)
        if len(files) == 1:
            return files[0]
        return path / "00-default.yaml"
    if not path.exists() and path.suffix.lower() not in {".yaml", ".yml"}:
        path.mkdir(parents=True, exist_ok=True)
        return path / "00-default.yaml"
    return path


def _is_intended_directory(path: pathlib.Path) -> bool:
    if path.is_dir():
        return True
    if path.exists():
        return False
    return path.suffix.lower() not in {".yaml", ".yml"}


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
    vlan_parent: str | None = field(default_factory=lambda: os.environ.get("NAS_V2_VLAN_PARENT"))


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


def _bind_platform_vlan_parent(effective: dict[str, Any], vlan_parent: str | None) -> dict[str, Any]:
    """Bind host-owned trunk configuration to active VLAN policies for native projection only."""
    services = effective.get("services")
    profiles = effective.get("networkProfiles")
    if not isinstance(services, dict) or not isinstance(profiles, dict):
        return effective

    direct_services: set[str] = set()
    referenced_profiles: set[str] = set()
    for service_id, service in services.items():
        if not isinstance(service, dict) or not service.get("managed", True) or not service.get("enabled", True):
            continue
        profile_id = service.get("networkProfile")
        if isinstance(profile_id, str):
            policy = profiles.get(profile_id)
            if isinstance(policy, dict) and "vlanId" in policy:
                referenced_profiles.add(profile_id)
            continue
        policy = service.get("network")
        if isinstance(policy, dict) and "vlanId" in policy:
            direct_services.add(service_id)

    if not direct_services and not referenced_profiles:
        return effective
    if not vlan_parent:
        raise SystemdProjectionError(
            "network.vlanId requires host platform configuration nas.networking.applicationVlanParent"
        )

    bound = copy.deepcopy(effective)
    bound_services = bound["services"]
    bound_profiles = bound["networkProfiles"]
    for service_id in direct_services:
        bound_services[service_id]["network"]["vlanParent"] = vlan_parent
    for profile_id in referenced_profiles:
        bound_profiles[profile_id]["vlanParent"] = vlan_parent
    return bound


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


_V2_OWNED_DIRS = {
    "units",
    "descriptors",
    "networks",
    "policies",
    "zones",
    "quadlet",
    "compose",
    "vm",
    "networkmanager",
}
_V2_STALE_SUFFIXES = (".service", ".timer", ".target", ".path", ".network", ".container", ".json")


def _is_v2_stale_candidate(path: pathlib.Path, root: pathlib.Path) -> bool:
    name = path.name
    if name.startswith("nas-v2-"):
        return True
    if name.endswith(_V2_STALE_SUFFIXES):
        return True
    try:
        rel = path.relative_to(root)
    except ValueError:
        return False
    if rel.parts and rel.parts[0] in _V2_OWNED_DIRS:
        return True
    for part in rel.parts[:-1]:
        if part in _V2_OWNED_DIRS:
            return True
    return False


def _projection_stale_files(root: pathlib.Path, current: set[pathlib.Path]) -> set[pathlib.Path]:
    """Return stale regular files beneath a fully V2-owned projection root."""
    try:
        entries = list(root.rglob("*"))
    except FileNotFoundError:
        return set()
    stale: set[pathlib.Path] = set()
    for path in entries:
        try:
            mode = path.lstat().st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise SystemdProjectionError(f"unexpected non-regular entry in V2 projection root: {path}")
        if path not in current and _is_v2_stale_candidate(path, root):
            stale.add(path)
    return stale


def _replace_bundle(
    files: list[tuple[pathlib.Path, bytes, int]],
    *,
    remove_paths: set[pathlib.Path] | None = None,
) -> set[pathlib.Path]:
    """Replace/delete generated files as one bundle, restoring prior bytes on failure."""
    replacement_paths = {path for path, _data, _mode in files}
    removals = set() if remove_paths is None else set(remove_paths) - replacement_paths
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
    mutated: list[pathlib.Path] = []
    try:
        for path, data, mode in changed_files:
            try:
                stat_result = path.stat()
                previous[path] = (path.read_bytes(), stat_result.st_mode & 0o777)
            except FileNotFoundError:
                previous[path] = None
            prepared.append((path, _prepare_temp(path, data, mode)))
        for path in removals:
            try:
                stat_result = path.stat()
                previous[path] = (path.read_bytes(), stat_result.st_mode & 0o777)
            except FileNotFoundError:
                previous[path] = None

        try:
            for path, temp in prepared:
                os.replace(temp, path)
                mutated.append(path)
            for path in sorted(removals, key=str):
                try:
                    path.unlink()
                except FileNotFoundError:
                    continue
                mutated.append(path)
            for directory in {path.parent for path in mutated}:
                _fsync_directory(directory)
        except Exception:
            for path in reversed(mutated):
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
    return {path for path, _data, _mode in changed_files} | {
        path for path in removals if previous.get(path) is not None
    }


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


def _compile_paths_inner(paths: ApplyPaths) -> tuple[dict[str, Any], dict[str, Any]]:
    schema = load_schema(paths.schema)
    effective = _compile_document_with_platform(parse_yaml(paths.desired), schema, paths.platform)
    return effective, build_plan(effective)


def compile_paths(paths: ApplyPaths) -> tuple[dict[str, Any], dict[str, Any]]:
    with authority_lock(paths.desired):
        return _compile_paths_inner(paths)


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
    projection_effective = _bind_platform_vlan_parent(effective, projection.vlan_parent)
    try:
        generated, manifest = generate_systemd_projection(
            projection_effective,
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
            projection_effective,
            output_dir=projection.output_dir,
            files=generated,
            manifest=manifest,
            firewalld_enabled=firewalld_enabled,
            nmcli_bin=projection.nmcli_bin,
            install_bin=projection.install_bin,
            rm_bin=projection.rm_bin,
        )
        augment_projection(
            projection_effective,
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
    with authority_lock(paths.desired):
        effective, plan = _compile_paths_inner(paths)
        try:
            needs_firewalld = requires_firewalld(effective)
        except PodmanNetworkProjectionError as exc:
            raise SystemdProjectionError(str(exc)) from exc
        if needs_firewalld and firewalld is None:
            raise SystemdProjectionError(
                "desired state requires V2 firewalld policy, but this apply transaction has no firewalld projection"
            )

        files: list[tuple[pathlib.Path, bytes, int]] = [
            (paths.effective, _json_bytes(effective), 0o640),
        ]
        stale: set[pathlib.Path] = set()
        if caddy is not None:
            files.append((caddy.output, _caddy_bytes(effective, caddy), 0o644))
        if portal is not None:
            files.append((portal.output, portal_bytes(effective), 0o644))
        if systemd is not None:
            systemd_files = _systemd_files(effective, systemd, firewalld_enabled=firewalld is not None)
            files.extend(systemd_files)
            current_systemd_paths = {path for path, _content, _mode in systemd_files}
            stale.update(_projection_stale_files(systemd.output_dir, current_systemd_paths))
        if backup is not None:
            files.extend(_backup_files(effective, backup))
        if firewalld is not None:
            files.extend(_firewalld_files(effective, firewalld))

        def _would_change(path: pathlib.Path, data: bytes, mode: int) -> bool:
            try:
                return path.read_bytes() != data or (path.stat().st_mode & 0o777) != mode
            except FileNotFoundError:
                return True

        # Predict changed set before serializing plan so plan on disk contains changedFiles.
        predicted: set[pathlib.Path] = {path for path, data, mode in files if _would_change(path, data, mode)}
        predicted.update({p for p in stale if p.exists()})
        plan["changedFiles"] = sorted(str(p) for p in predicted)
        plan_bytes = _json_bytes(plan)
        if _would_change(paths.plan, plan_bytes, 0o640):
            predicted.add(paths.plan)
            plan["changedFiles"] = sorted(str(p) for p in predicted)
            plan_bytes = _json_bytes(plan)
        files.append((paths.plan, plan_bytes, 0o640))
        changed = _replace_bundle(files, remove_paths=stale)
        # Ensure plan's changedFiles reflects actual changed set (covers race-free prediction).
        if {str(p) for p in changed} != set(plan["changedFiles"]):
            plan["changedFiles"] = sorted(str(p) for p in changed)
            _replace_bundle([(paths.plan, _json_bytes(plan), 0o640)], remove_paths=set())
        return plan


def save_and_apply(yaml_text: str, paths: ApplyPaths = ApplyPaths()) -> dict[str, Any]:
    """Validate draft YAML, atomically save authority, compile, and roll back on failure."""
    schema = load_schema(paths.schema)
    document = parse_yaml_text(yaml_text, source="<draft>")
    effective = _compile_document_with_platform(document, schema, paths.platform)
    plan = build_plan(effective)

    with authority_lock(paths.desired):
        if _is_directory_authority(paths.desired) or _is_intended_directory(paths.desired):
            target = _desired_target(paths.desired)
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                old_stat = target.stat()
                old_mode = old_stat.st_mode & 0o777
                old_uid = old_stat.st_uid
                old_gid = old_stat.st_gid
                old_desired: tuple[bytes, int, int, int] | None = (
                    target.read_bytes(),
                    old_mode,
                    old_uid,
                    old_gid,
                )
                old_files = _yaml_files(paths.desired)
            except FileNotFoundError:
                old_mode = 0o640
                old_uid = 0
                old_gid = 0
                old_desired = None
                old_files = _yaml_files(paths.desired)

            desired_temp = _prepare_temp(target, yaml_text.encode("utf-8"), old_mode)
            if os.geteuid() == 0 and old_desired is not None:
                try:
                    os.chown(desired_temp, old_uid, old_gid)
                except OSError:
                    pass
            try:
                os.replace(desired_temp, target)
                _fsync_directory(target.parent)
                for f in old_files:
                    if f != target and f.exists():
                        try:
                            f.unlink()
                        except OSError:
                            pass
                        try:
                            _fsync_directory(f.parent)
                        except OSError:
                            pass
                try:
                    _replace_bundle(
                        [
                            (paths.effective, _json_bytes(effective), 0o640),
                            (paths.plan, _json_bytes(plan), 0o640),
                        ]
                    )
                except Exception:
                    if old_desired is None:
                        target.unlink(missing_ok=True)
                    else:
                        rollback = _prepare_temp(target, old_desired[0], old_desired[1])
                        if os.geteuid() == 0:
                            try:
                                os.chown(rollback, old_desired[2], old_desired[3])
                            except OSError:
                                pass
                        os.replace(rollback, target)
                    _fsync_directory(target.parent)
                    raise
            finally:
                desired_temp.unlink(missing_ok=True)
            return plan

        try:
            old_stat = paths.desired.stat()
            old_mode = old_stat.st_mode & 0o777
            old_uid = old_stat.st_uid
            old_gid = old_stat.st_gid
            old_desired = (
                paths.desired.read_bytes(),
                old_mode,
                old_uid,
                old_gid,
            )
        except FileNotFoundError:
            old_mode = 0o640
            old_uid = 0
            old_gid = 0
            old_desired = None

        desired_temp = _prepare_temp(paths.desired, yaml_text.encode("utf-8"), old_mode)
        if os.geteuid() == 0 and old_desired is not None:
            try:
                os.chown(desired_temp, old_uid, old_gid)
            except OSError:
                pass
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
                    if os.geteuid() == 0:
                        try:
                            os.chown(rollback, old_desired[2], old_desired[3])
                        except OSError:
                            pass
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
