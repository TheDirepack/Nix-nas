#!/usr/bin/env python3
"""Reject application-specific knowledge in generic Managed Services V2 code."""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

APPLICATION_NAMES = (
    "copyparty",
    "syncthing",
    "vaultwarden",
    "grafana",
    "victoriametrics",
    "telegraf",
    "vmalert",
    "ntfy",
    "nut-webgui",
)

# Required generic modules are pinned by name. A glob would drop a deleted
# module from the requirement set silently, so every generic module that must
# stay free of application knowledge is listed here.
REQUIRED_V2_MODULES = (
    "nas_v2_accelerator.py",
    "nas_v2_activation.py",
    "nas_v2_apply.py",
    "nas_v2_authentik_blueprint.py",
    "nas_v2_backup.py",
    "nas_v2_bootstrap.py",
    "nas_v2_caddy.py",
    "nas_v2_cli.py",
    "nas_v2_compose.py",
    "nas_v2_compose_import.py",
    "nas_v2_control.py",
    "nas_v2_editor.py",
    "nas_v2_entry.py",
    "nas_v2_exec_runner.py",
    "nas_v2_firewalld_reconcile.py",
    "nas_v2_generation.py",
    "nas_v2_history.py",
    "nas_v2_libvirt.py",
    "nas_v2_network.py",
    "nas_v2_nmstate.py",
    "nas_v2_plan.py",
    "nas_v2_platform_probe.py",
    "nas_v2_podman_network.py",
    "nas_v2_quadlet.py",
    "nas_v2_readiness.py",
    "nas_v2_session.py",
    "nas_v2_source_watch.py",
    "nas_v2_spec.py",
    "nas_v2_systemd_attachments.py",
    "nas_v2_systemd_native.py",
    "nas_v2_systemd_reconcile.py",
)

GENERIC_PATHS = (
    *(ROOT / "services" / name for name in REQUIRED_V2_MODULES),
    ROOT / "modules/nas/config/managed-services.nix",
    ROOT / "modules/nas/config/managed-services-lifecycle.nix",
    ROOT / "modules/nas/config/managed-services-transactions.nix",
    ROOT / "modules/nas/config/managed-services-network-platform.nix",
    ROOT / "modules/nas/config/managed-services-authentik-blueprint.nix",
    ROOT / "modules/nas/config/managed-services-compose-import.nix",
)


def violations(paths: tuple[pathlib.Path, ...] = GENERIC_PATHS) -> list[tuple[pathlib.Path, str, int]]:
    patterns = {
        name: re.compile(rf"(?<![a-z0-9]){re.escape(name)}(?![a-z0-9])", re.IGNORECASE) for name in APPLICATION_NAMES
    }
    result: list[tuple[pathlib.Path, str, int]] = []
    for path in paths:
        if not path.is_file():
            raise SystemExit(f"missing generic path: {path}")
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            for name, pattern in patterns.items():
                if pattern.search(line):
                    result.append((path.relative_to(ROOT), name, line_number))
    return result


def main() -> int:
    found = violations()
    if found:
        for path, name, line_number in found:
            print(f"architecture boundary violation: {path}:{line_number}: {name}", file=sys.stderr)
        return 1
    print(f"architecture boundary ok: {len(GENERIC_PATHS)} generic paths")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
