#!/usr/bin/env python3
"""Finite V2 reconciliation entry point for Nix — not a CLI.

This is the only non-GUI entry to the V2 compiler. Cockpit (via
nas_v2_control / nas_v2_editor) is the operator surface; this module
is called only by the NixOS reconcile units with fixed paths. There
is no `nas_v2_cli` and no `compile`/`plan` subcommands.
"""

from __future__ import annotations

import pathlib
import sys

from nas_v2_apply import (
    ApplyPaths,
    BackupProjection,
    CaddyProjection,
    FirewalldProjection,
    PortalProjection,
    SystemdProjection,
    apply,
)


def main() -> int:
    import os

    # Fixed authority paths — same as the previous nas_v2_cli defaults.
    # Nix may override via environment (see managed-services.nix).
    desired = pathlib.Path(os.environ.get("NAS_V2_DESIRED", "/var/lib/nas-control/services"))
    if os.environ.get("NAS_V2_SPEC") and not os.environ.get("NAS_V2_DESIRED"):
        desired = pathlib.Path(os.environ["NAS_V2_SPEC"])
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

    # Allow Nix to override via args if invoked manually (not a supported CLI):
    # `python nas_v2_entry.py /custom/services.yaml` still works for debugging,
    # but the normal path is zero-arg.
    if len(sys.argv) > 1:
        desired = pathlib.Path(sys.argv[1])

    caddy_bin = os.environ.get("NAS_V2_CADDY_BIN", "caddy")
    authentik_upstream = os.environ.get("NAS_V2_AUTHENTIK_UPSTREAM", "127.0.0.1:9010")
    authentik_path = os.environ.get("NAS_V2_AUTHENTIK_PATH", "/identity/")
    lan_host = os.environ.get("NAS_V2_LAN_HOST", "nas.local")
    authentik_public_host = os.environ.get("NAS_V2_AUTHENTIK_PUBLIC_HOST", lan_host)
    wake_socket = os.environ.get("NAS_V2_WAKE_SOCKET", "/run/nas-control/wake.sock")
    systemd_analyze_bin = os.environ.get("NAS_V2_SYSTEMD_ANALYZE_BIN", "systemd-analyze")
    systemctl_bin = os.environ.get("NAS_V2_SYSTEMCTL_BIN", "systemctl")
    python_bin = os.environ.get("NAS_V2_PYTHON_BIN", sys.executable)
    uv_bin = os.environ.get("NAS_V2_UV_BIN", "uv")
    quadlet_generator_bin = os.environ.get("NAS_V2_QUADLET_GENERATOR_BIN", "")
    podman_bin = os.environ.get("NAS_V2_PODMAN_BIN", "podman")
    compose_provider_bin = os.environ.get("NAS_V2_COMPOSE_PROVIDER_BIN", "podman-compose")
    virsh_bin = os.environ.get("NAS_V2_VIRSH_BIN", "virsh")
    virt_xml_validate_bin = os.environ.get("NAS_V2_VIRT_XML_VALIDATE_BIN", "")
    nmcli_bin = os.environ.get("NAS_V2_NMCLI_BIN", "nmcli")
    install_bin = os.environ.get("NAS_V2_INSTALL_BIN", "install")
    rm_bin = os.environ.get("NAS_V2_RM_BIN", "rm")
    vlan_parent = os.environ.get("NAS_V2_VLAN_PARENT")
    lan_zone = os.environ.get("NAS_V2_LAN_ZONE", "nas-lan")
    firewall_offline_cmd = os.environ.get("NAS_V2_FIREWALL_OFFLINE_CMD", "firewall-offline-cmd")
    firewalld_enabled = os.environ.get("NAS_V2_FIREWALLD_ENABLED") == "1"

    try:
        apply(
            ApplyPaths(
                desired=desired,
                schema=schema,
                platform=platform if platform.exists() else None,
                effective=effective,
                plan=plan,
            ),
            caddy=CaddyProjection(
                output=caddy_output,
                caddy_bin=caddy_bin,
                authentik_upstream=authentik_upstream,
                authentik_path=authentik_path,
                lan_host=lan_host,
                authentik_public_host=authentik_public_host,
                wake_socket=wake_socket,
            ),
            systemd=SystemdProjection(
                output_dir=systemd_output,
                systemd_analyze_bin=systemd_analyze_bin,
                python_bin=python_bin,
                source_dir=pathlib.Path(__file__).parent,
                systemctl_bin=systemctl_bin,
                uv_bin=uv_bin,
                quadlet_generator_bin=quadlet_generator_bin or None,
                podman_bin=podman_bin,
                compose_provider_bin=compose_provider_bin,
                virsh_bin=virsh_bin,
                virt_xml_validate_bin=virt_xml_validate_bin or None,
                nmcli_bin=nmcli_bin,
                install_bin=install_bin,
                rm_bin=rm_bin,
                vlan_parent=vlan_parent,
            ),
            backup=BackupProjection(inventory=backup_inventory, restic_paths=restic_paths),
            firewalld=FirewalldProjection(
                output_dir=firewalld_output,
                lan_zone=lan_zone,
                firewall_offline_cmd=firewall_offline_cmd,
            )
            if firewalld_enabled
            else None,
            portal=PortalProjection(output=portal_output),
        )
    except Exception as exc:
        print(f"V2 reconcile failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
