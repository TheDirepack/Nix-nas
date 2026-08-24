#!/usr/bin/env python3
"""Finite Managed Services V2 reconciliation entry point for Nix.

Production reconciliation publishes one immutable runtime generation and then
atomically switches /run/nas-control/current.  Standalone/debug invocations
without configured Git history keep the direct file-output behavior used by
unit tests and developer tooling.
"""

from __future__ import annotations

import os
import pathlib
import sys
from dataclasses import replace

from nas_v2_apply import (
    ApplyPaths,
    BackupProjection,
    CaddyProjection,
    FirewalldProjection,
    PortalProjection,
    SystemdProjection,
    apply,
)
from nas_v2_generation import GenerationError, allocate_generation, discard_generation, publish_generation
from nas_v2_history import record_desired


def _relative(runtime_root: pathlib.Path, path: pathlib.Path) -> pathlib.PurePosixPath:
    try:
        value = path.relative_to(runtime_root)
    except ValueError as exc:
        raise GenerationError(f"generated runtime path must remain beneath {runtime_root}: {path}") from exc
    if not value.parts or ".." in value.parts:
        raise GenerationError(f"invalid generated runtime path {path}")
    return pathlib.PurePosixPath(value.as_posix())


def _apply_once(
    *,
    paths: ApplyPaths,
    caddy: CaddyProjection,
    systemd: SystemdProjection,
    backup: BackupProjection,
    firewalld: FirewalldProjection | None,
    portal: PortalProjection,
) -> dict:
    return apply(paths, caddy=caddy, systemd=systemd, backup=backup, firewalld=firewalld, portal=portal)


def main() -> int:
    desired = pathlib.Path(os.environ.get("NAS_V2_DESIRED", "/var/lib/nas-control/services.yaml"))
    if os.environ.get("NAS_V2_SPEC") and not os.environ.get("NAS_V2_DESIRED"):
        desired = pathlib.Path(os.environ["NAS_V2_SPEC"])
    if len(sys.argv) > 1:
        desired = pathlib.Path(sys.argv[1])

    schema = pathlib.Path(os.environ.get("NAS_V2_SCHEMA", "/etc/nas-control/managed-services-v3.schema.json"))
    platform = pathlib.Path(os.environ.get("NAS_V2_PLATFORM", "/etc/nas-control/platform-capabilities.json"))
    effective = pathlib.Path(os.environ.get("NAS_V2_EFFECTIVE", "/run/nas-control/effective.json"))
    plan = pathlib.Path(os.environ.get("NAS_V2_PLAN", "/run/nas-control/plan.json"))
    portal_output = pathlib.Path(os.environ.get("NAS_V2_PORTAL", "/run/nas-control/portal.json"))
    caddy_output = pathlib.Path(os.environ.get("NAS_V2_CADDY", "/run/nas-control/caddy-managed.conf"))
    systemd_output = pathlib.Path(os.environ.get("NAS_V2_SYSTEMD", "/run/nas-control/systemd"))
    backup_inventory = pathlib.Path(os.environ.get("NAS_V2_BACKUP_INVENTORY", "/run/nas-control/backup-resources.json"))
    restic_paths = pathlib.Path(os.environ.get("NAS_V2_RESTIC_PATHS", "/run/nas-control/restic-v2-paths"))
    firewalld_output = pathlib.Path(os.environ.get("NAS_V2_FIREWALLD", "/run/nas-control/firewalld"))
    history_repository_raw = os.environ.get("NAS_V2_HISTORY_REPOSITORY")
    history_repository = pathlib.Path(history_repository_raw) if history_repository_raw else None
    git_bin = os.environ.get("NAS_V2_GIT_BIN", "git")

    caddy = CaddyProjection(
        output=caddy_output,
        caddy_bin=os.environ.get("NAS_V2_CADDY_BIN", "caddy"),
        authentik_upstream=os.environ.get("NAS_V2_AUTHENTIK_UPSTREAM", "127.0.0.1:9010"),
        authentik_path=os.environ.get("NAS_V2_AUTHENTIK_PATH", "/identity/"),
        lan_host=os.environ.get("NAS_V2_LAN_HOST", "nas.local"),
        authentik_public_host=os.environ.get("NAS_V2_AUTHENTIK_PUBLIC_HOST")
        or os.environ.get("NAS_V2_LAN_HOST", "nas.local"),
        wake_socket=None,
    )
    systemd = SystemdProjection(
        output_dir=systemd_output,
        systemd_analyze_bin=os.environ.get("NAS_V2_SYSTEMD_ANALYZE_BIN", "systemd-analyze"),
        python_bin=os.environ.get("NAS_V2_PYTHON_BIN", sys.executable),
        source_dir=pathlib.Path(__file__).parent,
        systemctl_bin=os.environ.get("NAS_V2_SYSTEMCTL_BIN", "systemctl"),
        uv_bin=os.environ.get("NAS_V2_UV_BIN", "uv"),
        quadlet_generator_bin=os.environ.get("NAS_V2_QUADLET_GENERATOR_BIN") or None,
        podman_bin=os.environ.get("NAS_V2_PODMAN_BIN", "podman"),
        compose_provider_bin=os.environ.get("NAS_V2_COMPOSE_PROVIDER_BIN", "podman-compose"),
        virsh_bin=os.environ.get("NAS_V2_VIRSH_BIN", "virsh"),
        virt_xml_validate_bin=os.environ.get("NAS_V2_VIRT_XML_VALIDATE_BIN") or None,
        vlan_parent=os.environ.get("NAS_V2_VLAN_PARENT"),
    )
    backup = BackupProjection(inventory=backup_inventory, restic_paths=restic_paths)
    firewalld = (
        FirewalldProjection(
            output_dir=firewalld_output,
            lan_zone=os.environ.get("NAS_V2_LAN_ZONE", "nas-lan"),
            firewall_offline_cmd=os.environ.get("NAS_V2_FIREWALL_OFFLINE_CMD", "firewall-offline-cmd"),
        )
        if os.environ.get("NAS_V2_FIREWALLD_ENABLED") == "1"
        else None
    )
    portal = PortalProjection(output=portal_output)
    paths = ApplyPaths(
        desired=desired,
        schema=schema,
        platform=platform if platform.exists() else None,
        effective=effective,
        plan=plan,
        history_repository=history_repository,
        git_bin=git_bin,
    )

    try:
        if history_repository is None:
            _apply_once(paths=paths, caddy=caddy, systemd=systemd, backup=backup, firewalld=firewalld, portal=portal)
            return 0

        runtime_root = effective.parent
        generation_root = runtime_root / "generations"
        current_link = runtime_root / "current"
        stable_paths = {
            effective: _relative(runtime_root, effective),
            plan: _relative(runtime_root, plan),
            portal_output: _relative(runtime_root, portal_output),
            caddy_output: _relative(runtime_root, caddy_output),
            systemd_output: _relative(runtime_root, systemd_output),
            backup_inventory: _relative(runtime_root, backup_inventory),
            restic_paths: _relative(runtime_root, restic_paths),
            firewalld_output: _relative(runtime_root, firewalld_output),
        }

        # A services.yaml edit can race the initial history read.  Nothing is
        # published until apply() reports the same revision, so retry a bounded
        # number of times instead of ever exposing a mixed generation.
        for _attempt in range(3):
            history = record_desired(authority=desired, repository=history_repository, git_bin=git_bin)
            revision = str(history["head"])
            generation = allocate_generation(generation_root, revision)
            try:
                generated_paths = replace(
                    paths,
                    effective=generation / stable_paths[effective],
                    plan=generation / stable_paths[plan],
                )
                generated_caddy = replace(caddy, output=generation / stable_paths[caddy_output])
                generated_systemd = replace(systemd, output_dir=generation / stable_paths[systemd_output])
                generated_backup = replace(
                    backup,
                    inventory=generation / stable_paths[backup_inventory],
                    restic_paths=generation / stable_paths[restic_paths],
                )
                generated_firewalld = (
                    replace(firewalld, output_dir=generation / stable_paths[firewalld_output])
                    if firewalld is not None
                    else None
                )
                generated_portal = replace(portal, output=generation / stable_paths[portal_output])
                result = _apply_once(
                    paths=generated_paths,
                    caddy=generated_caddy,
                    systemd=generated_systemd,
                    backup=generated_backup,
                    firewalld=generated_firewalld,
                    portal=generated_portal,
                )
                if result.get("desiredRevision") != revision:
                    discard_generation(generation)
                    continue
                publish_generation(
                    generation,
                    expected_revision=revision,
                    plan=result,
                    generation_root=generation_root,
                    current_link=current_link,
                    compatibility_paths=stable_paths,
                )
                return 0
            except Exception:
                discard_generation(generation)
                raise
        raise GenerationError("desired state changed repeatedly during compilation; retry reconciliation")
    except Exception as exc:
        print(f"V2 reconcile failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
