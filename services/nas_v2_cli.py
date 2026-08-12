#!/usr/bin/env python3
"""Command-line interface for the non-resident Managed Services V2 compiler."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
from typing import Any

from nas_v2_accelerator import AcceleratorResolutionError
from nas_v2_apply import (
    ApplyPaths,
    BackupProjection,
    CaddyProjection,
    FirewalldProjection,
    PortalProjection,
    SystemdProjection,
    apply,
    compile_paths,
)
from nas_v2_backup import BackupProjectionError
from nas_v2_caddy import CaddyProjectionError
from nas_v2_firewalld import FirewalldProjectionError
from nas_v2_plan import build_plan
from nas_v2_portal import PortalProjectionError
from nas_v2_spec import DEFAULT_PLATFORM_PATH, DEFAULT_SCHEMA_PATH, DEFAULT_SPEC_PATH, ManagedServicesV2Error
from nas_v2_systemd import SystemdProjectionError


def _json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def _paths(args: argparse.Namespace) -> ApplyPaths:
    return ApplyPaths(
        desired=pathlib.Path(args.spec),
        schema=pathlib.Path(args.schema),
        platform=None if args.no_platform else pathlib.Path(args.platform),
        effective=pathlib.Path(args.effective),
        plan=pathlib.Path(args.plan),
    )


def _caddy(args: argparse.Namespace) -> CaddyProjection | None:
    if args.caddy_output is None:
        return None
    if args.caddy_bin is None:
        raise ManagedServicesV2Error(
            "--caddy-bin is required with --caddy-output",
            path="$.caddy",
            code="caddy-config",
        )
    return CaddyProjection(
        output=pathlib.Path(args.caddy_output),
        caddy_bin=args.caddy_bin,
        authentik_upstream=args.authentik_upstream,
        authentik_path=args.authentik_path,
        lan_host=args.lan_host,
        wake_socket=args.wake_socket,
    )


def _systemd(args: argparse.Namespace) -> SystemdProjection | None:
    if args.systemd_output is None:
        return None
    return SystemdProjection(
        output_dir=pathlib.Path(args.systemd_output),
        systemd_analyze_bin=args.systemd_analyze_bin,
        python_bin=args.python_bin,
        source_dir=pathlib.Path(args.v2_source),
        systemctl_bin=args.systemctl_bin,
        uv_bin=args.uv_bin,
        quadlet_generator_bin=args.quadlet_generator_bin,
        podman_bin=args.podman_bin,
        compose_provider_bin=args.compose_provider_bin,
        virsh_bin=args.virsh_bin,
        virt_xml_validate_bin=args.virt_xml_validate_bin,
        nmcli_bin=args.nmcli_bin,
        install_bin=args.install_bin,
        rm_bin=args.rm_bin,
    )


def _backup(args: argparse.Namespace) -> BackupProjection:
    output_root = pathlib.Path(args.effective).parent
    return BackupProjection(
        inventory=pathlib.Path(args.backup_inventory)
        if args.backup_inventory
        else output_root / "backup-resources.json",
        restic_paths=pathlib.Path(args.restic_paths) if args.restic_paths else output_root / "backup-paths.txt",
    )


def _firewalld(args: argparse.Namespace) -> FirewalldProjection | None:
    if args.firewalld_output is None:
        return None
    if not args.firewalld_lan_zone:
        raise ManagedServicesV2Error(
            "--firewalld-lan-zone is required with --firewalld-output",
            path="$.network",
            code="firewalld-config",
        )
    return FirewalldProjection(
        output_dir=pathlib.Path(args.firewalld_output),
        lan_zone=args.firewalld_lan_zone,
        firewall_offline_cmd=args.firewall_offline_cmd,
    )


def _portal(args: argparse.Namespace) -> PortalProjection | None:
    return None if args.portal_output is None else PortalProjection(output=pathlib.Path(args.portal_output))


def _compile(args: argparse.Namespace) -> dict[str, Any]:
    effective, _plan = compile_paths(_paths(args))
    return effective


def _add_paths(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--spec", default=str(DEFAULT_SPEC_PATH), help="desired-state YAML path")
    parser.add_argument("--schema", default=str(DEFAULT_SCHEMA_PATH), help="JSON Schema path")
    parser.add_argument("--platform", default=str(DEFAULT_PLATFORM_PATH), help="platform capability inventory")
    parser.add_argument("--no-platform", action="store_true", help="skip host-capability validation")
    parser.add_argument(
        "--effective", default="/run/nas-control/effective.json", help="compiled effective-state output"
    )
    parser.add_argument("--plan", default="/run/nas-control/plan.json", help="projection plan output")


def _add_caddy(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--caddy-output", help="generated Caddyfile fragment output")
    parser.add_argument("--caddy-bin", help="Caddy binary used to validate the generated fragment")
    parser.add_argument("--authentik-upstream", default="127.0.0.1:9000")
    parser.add_argument("--authentik-path", default="/identity/")
    parser.add_argument("--lan-host", default="nas.local")
    parser.add_argument("--wake-socket")


def _add_systemd(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--systemd-output", help="directory for staged generated systemd files")
    parser.add_argument("--systemd-analyze-bin", default="systemd-analyze")
    parser.add_argument("--systemctl-bin", default="systemctl")
    parser.add_argument("--python-bin", default=sys.executable)
    parser.add_argument("--uv-bin", default="uv")
    parser.add_argument("--quadlet-generator-bin", default="podman-system-generator")
    parser.add_argument("--podman-bin", default=os.environ.get("NAS_V2_PODMAN_BIN", "podman"))
    parser.add_argument(
        "--compose-provider-bin",
        default=os.environ.get("NAS_V2_COMPOSE_PROVIDER_BIN", "podman-compose"),
    )
    parser.add_argument("--virsh-bin", default=os.environ.get("NAS_V2_VIRSH_BIN", "virsh"))
    parser.add_argument("--virt-xml-validate-bin", default=os.environ.get("NAS_V2_VIRT_XML_VALIDATE_BIN"))
    parser.add_argument("--nmcli-bin", default=os.environ.get("NAS_V2_NMCLI_BIN", "nmcli"))
    parser.add_argument("--install-bin", default=os.environ.get("NAS_V2_INSTALL_BIN", "install"))
    parser.add_argument("--rm-bin", default=os.environ.get("NAS_V2_RM_BIN", "rm"))
    parser.add_argument("--v2-source", default=str(pathlib.Path(__file__).resolve().parent))


def _add_backup(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--backup-inventory", help="compiled V2 backup inventory JSON output; defaults beside --effective"
    )
    parser.add_argument("--restic-paths", help="verbatim Restic path-list output; defaults beside --effective")


def _add_firewalld(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--firewalld-output", help="directory for staged V2-owned firewalld XML")
    parser.add_argument("--firewalld-lan-zone", help="existing firewalld zone representing trusted LAN traffic")
    parser.add_argument("--firewall-offline-cmd", default="firewall-offline-cmd")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nas-v2",
        description="Validate, compile, plan, or apply Managed Services V2 desired state.",
    )
    parser.add_argument("--json-errors", action="store_true", help="render validation failures as JSON")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate", help="validate and normalize without writing files")
    _add_paths(validate)
    effective = subparsers.add_parser("effective", help="print compiled effective state")
    _add_paths(effective)
    plan = subparsers.add_parser("plan", help="print the deterministic native-subsystem plan")
    _add_paths(plan)

    apply_parser = subparsers.add_parser("apply", help="atomically materialize validated projections")
    _add_paths(apply_parser)
    _add_caddy(apply_parser)
    _add_systemd(apply_parser)
    _add_backup(apply_parser)
    _add_firewalld(apply_parser)
    apply_parser.add_argument("--portal-output", help="generated V2 portal model output")
    return parser


def run(args: argparse.Namespace) -> int:
    if args.command == "validate":
        effective = _compile(args)
        sys.stdout.write(
            _json(
                {
                    "valid": True,
                    "schemaVersion": effective["schemaVersion"],
                    "generation": effective["generation"],
                    "services": len(effective["services"]),
                }
            )
        )
        return 0
    if args.command == "effective":
        sys.stdout.write(_json(_compile(args)))
        return 0
    if args.command == "plan":
        sys.stdout.write(_json(build_plan(_compile(args))))
        return 0
    if args.command == "apply":
        sys.stdout.write(
            _json(
                apply(
                    _paths(args),
                    caddy=_caddy(args),
                    systemd=_systemd(args),
                    backup=_backup(args),
                    firewalld=_firewalld(args),
                    portal=_portal(args),
                )
            )
        )
        return 0
    raise AssertionError(f"Unhandled command {args.command!r}")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return run(args)
    except ManagedServicesV2Error as exc:
        if args.json_errors:
            sys.stderr.write(_json(exc.as_dict()))
        else:
            sys.stderr.write(f"nas-v2: {exc.path}: {exc}\n")
        return 2
    except (
        AcceleratorResolutionError,
        BackupProjectionError,
        CaddyProjectionError,
        FirewalldProjectionError,
        PortalProjectionError,
        SystemdProjectionError,
    ) as exc:
        payload = {"code": "projection-error", "path": "$.projection", "message": str(exc)}
        if args.json_errors:
            sys.stderr.write(_json(payload))
        else:
            sys.stderr.write(f"nas-v2: projection: {exc}\n")
        return 2
    except OSError as exc:
        payload = {"code": "io-error", "path": "$", "message": str(exc)}
        if args.json_errors:
            sys.stderr.write(_json(payload))
        else:
            sys.stderr.write(f"nas-v2: {exc}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
