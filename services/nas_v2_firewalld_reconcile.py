#!/usr/bin/env python3
"""Activate the V2-owned firewalld namespace through firewall-cmd.

The compiler may use XML as a validated intermediate representation, but V2 no
longer installs or rolls back firewalld configuration files. firewalld owns its
permanent/native state; the outer generic V2 guarded transaction owns failure
recovery for the complete desired-state apply.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys
from typing import Any, Sequence

from defusedxml import ElementTree

_OWNED_FILE = re.compile(r"^nv2[zhwlrima][0-9a-f]{12}\.xml$")
_OWNED_NAME = re.compile(r"^nv2[zhwlrima][0-9a-f]{12}$")


class FirewalldReconcileError(RuntimeError):
    """Raised when the projected firewall cannot be activated and verified."""


def _run(command: Sequence[str], *, timeout: int = 60, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            list(command),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise FirewalldReconcileError(f"unable to execute {command[0]}: {exc}") from exc
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[:4000]
        raise FirewalldReconcileError(f"command failed ({result.returncode}): {' '.join(command)}: {detail}")
    return result


def _sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_target(raw: str) -> pathlib.PurePosixPath:
    target = pathlib.PurePosixPath(raw)
    if len(target.parts) != 2 or target.parts[0] not in {"zones", "policies"}:
        raise FirewalldReconcileError(f"unsafe firewalld target {raw!r}")
    if not _OWNED_FILE.fullmatch(target.name):
        raise FirewalldReconcileError(f"firewalld target {raw!r} is outside the V2 ownership namespace")
    expected_kind = "zones" if target.name.startswith("nv2z") else "policies"
    if target.parts[0] != expected_kind:
        raise FirewalldReconcileError(f"firewalld target {raw!r} has the wrong object kind")
    return target


def _read_projection(
    manifest_path: pathlib.Path,
    projection_root: pathlib.Path,
) -> dict[pathlib.PurePosixPath, bytes]:
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FirewalldReconcileError(f"unable to read firewalld manifest {manifest_path}: {exc}") from exc
    if (
        not isinstance(manifest, dict)
        or manifest.get("schemaVersion") != 1
        or not isinstance(manifest.get("files"), list)
    ):
        raise FirewalldReconcileError("firewalld projection manifest is invalid")

    desired: dict[pathlib.PurePosixPath, bytes] = {}
    for entry in manifest["files"]:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("target"), str)
            or not isinstance(entry.get("sha256"), str)
        ):
            raise FirewalldReconcileError("firewalld manifest file entry is invalid")
        target = _safe_target(entry["target"])
        source = projection_root / str(target)
        try:
            source.relative_to(projection_root)
            payload = source.read_bytes()
        except (ValueError, OSError) as exc:
            raise FirewalldReconcileError(f"projected firewalld file is missing or unsafe: {source}") from exc
        if hashlib.sha256(payload).hexdigest() != entry["sha256"]:
            raise FirewalldReconcileError(f"projected firewalld file changed after validation: {source}")
        if target in desired:
            raise FirewalldReconcileError(f"duplicate firewalld projection target: {target}")
        desired[target] = payload
    return desired


def _attr(element: ElementTree.Element, name: str, *, label: str) -> str:
    value = element.get(name)
    if not value or any(ch in value for ch in "\r\n\x00"):
        raise FirewalldReconcileError(f"projected {label} is missing safe attribute {name!r}")
    return value


def _rich_rule(element: ElementTree.Element) -> str:
    family = _attr(element, "family", label="rich rule")
    priority = element.get("priority")
    parts = ["rule", f'family="{family}"']
    if priority:
        parts.append(f'priority="{priority}"')
    destination = element.find("destination")
    if destination is not None:
        parts.extend(["destination", f'address="{_attr(destination, "address", label="destination")}"'])
    port = element.find("port")
    if port is not None:
        parts.extend(
            [
                "port",
                f'port="{_attr(port, "port", label="rich-rule port")}"',
                f'protocol="{_attr(port, "protocol", label="rich-rule port")}"',
            ]
        )
    if element.find("accept") is not None:
        parts.append("accept")
    elif element.find("drop") is not None:
        parts.append("drop")
    elif element.find("reject") is not None:
        parts.append("reject")
    else:
        raise FirewalldReconcileError("projected rich rule has no supported action")
    return " ".join(parts)


def _permanent(firewall_cmd: str, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return _run([firewall_cmd, "--permanent", *args], check=check)


def _apply_zone(firewall_cmd: str, name: str, payload: bytes) -> None:
    try:
        root = ElementTree.fromstring(payload)
    except ElementTree.ParseError as exc:
        raise FirewalldReconcileError(f"invalid projected zone {name}: {exc}") from exc
    if root.tag != "zone":
        raise FirewalldReconcileError(f"projected zone {name} has root {root.tag!r}")
    _permanent(firewall_cmd, f"--new-zone={name}")
    target = root.get("target")
    if target:
        _permanent(firewall_cmd, f"--zone={name}", f"--set-target={target}")
    for interface in root.findall("interface"):
        _permanent(
            firewall_cmd, f"--zone={name}", f"--add-interface={_attr(interface, 'name', label='zone interface')}"
        )
    for service in root.findall("service"):
        _permanent(firewall_cmd, f"--zone={name}", f"--add-service={_attr(service, 'name', label='zone service')}")
    for port in root.findall("port"):
        value = f"{_attr(port, 'port', label='zone port')}/{_attr(port, 'protocol', label='zone port')}"
        _permanent(firewall_cmd, f"--zone={name}", f"--add-port={value}")


def _apply_policy(firewall_cmd: str, name: str, payload: bytes) -> None:
    try:
        root = ElementTree.fromstring(payload)
    except ElementTree.ParseError as exc:
        raise FirewalldReconcileError(f"invalid projected policy {name}: {exc}") from exc
    if root.tag != "policy":
        raise FirewalldReconcileError(f"projected policy {name} has root {root.tag!r}")
    _permanent(firewall_cmd, f"--new-policy={name}")
    target = root.get("target")
    priority = root.get("priority")
    if target:
        _permanent(firewall_cmd, f"--policy={name}", f"--set-target={target}")
    if priority:
        _permanent(firewall_cmd, f"--policy={name}", f"--set-priority={priority}")
    for zone in root.findall("ingress-zone"):
        _permanent(firewall_cmd, f"--policy={name}", f"--add-ingress-zone={_attr(zone, 'name', label='ingress zone')}")
    for zone in root.findall("egress-zone"):
        _permanent(firewall_cmd, f"--policy={name}", f"--add-egress-zone={_attr(zone, 'name', label='egress zone')}")
    for port in root.findall("port"):
        value = f"{_attr(port, 'port', label='policy port')}/{_attr(port, 'protocol', label='policy port')}"
        _permanent(firewall_cmd, f"--policy={name}", f"--add-port={value}")
    for forward in root.findall("forward-port"):
        value = (
            f"port={_attr(forward, 'port', label='forward port')}:"
            f"proto={_attr(forward, 'protocol', label='forward port')}:"
            f"toport={_attr(forward, 'to-port', label='forward port')}"
        )
        _permanent(firewall_cmd, f"--policy={name}", f"--add-forward-port={value}")
    for rule in root.findall("rule"):
        _permanent(firewall_cmd, f"--policy={name}", f"--add-rich-rule={_rich_rule(rule)}")


def _current_owned(firewall_cmd: str) -> tuple[set[str], set[str]]:
    zones = set(_permanent(firewall_cmd, "--get-zones").stdout.split())
    policies = set(_permanent(firewall_cmd, "--get-policies").stdout.split())
    return (
        {name for name in zones if _OWNED_NAME.fullmatch(name)},
        {name for name in policies if _OWNED_NAME.fullmatch(name)},
    )


def _verify_runtime(*, desired: dict[pathlib.PurePosixPath, bytes], firewall_cmd: str) -> None:
    _run([firewall_cmd, "--state"])
    zones = set(_run([firewall_cmd, "--get-zones"]).stdout.split())
    policies = set(_run([firewall_cmd, "--get-policies"]).stdout.split())
    expected_zones = {target.stem for target in desired if target.parts[0] == "zones"}
    expected_policies = {target.stem for target in desired if target.parts[0] == "policies"}
    missing_zones = sorted(expected_zones - zones)
    missing_policies = sorted(expected_policies - policies)
    if missing_zones or missing_policies:
        detail: list[str] = []
        if missing_zones:
            detail.append(f"zones={','.join(missing_zones)}")
        if missing_policies:
            detail.append(f"policies={','.join(missing_policies)}")
        raise FirewalldReconcileError("firewalld reload omitted projected objects: " + " ".join(detail))


def reconcile(
    *,
    manifest_path: pathlib.Path,
    projection_root: pathlib.Path,
    system_config: pathlib.Path | None = None,
    firewall_cmd: str = "firewall-cmd",
) -> dict[str, Any]:
    """Replace the complete V2 native namespace, reload firewalld, and verify it."""
    del system_config  # retained as a no-op CLI compatibility argument during migration
    desired = _read_projection(manifest_path, projection_root)
    current_zones, current_policies = _current_owned(firewall_cmd)

    # The nv2* namespace is exclusively V2-owned. Recreate it from the validated
    # compiler IR so runtime/permanent drift cannot accumulate and no custom
    # rollback bytes or file copying are required.
    for name in sorted(current_policies):
        _permanent(firewall_cmd, f"--delete-policy={name}")
    for name in sorted(current_zones):
        _permanent(firewall_cmd, f"--delete-zone={name}")

    for target, payload in sorted(desired.items(), key=lambda item: str(item[0])):
        if target.parts[0] == "zones":
            _apply_zone(firewall_cmd, target.stem, payload)
        else:
            _apply_policy(firewall_cmd, target.stem, payload)

    _run([firewall_cmd, "--check-config"])
    _run([firewall_cmd, "--reload"])
    _verify_runtime(desired=desired, firewall_cmd=firewall_cmd)
    return {
        "ok": True,
        "changed": bool(current_zones or current_policies or desired),
        "objects": sorted(target.stem for target in desired),
        "runtimeVerified": True,
        "nativePermanentApi": True,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Activate and verify the complete V2-owned firewalld namespace")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--projection-root", required=True)
    parser.add_argument("--system-config", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--firewall-cmd", default="firewall-cmd")
    args = parser.parse_args(argv)
    try:
        result = reconcile(
            manifest_path=pathlib.Path(args.manifest),
            projection_root=pathlib.Path(args.projection_root),
            system_config=None if args.system_config is None else pathlib.Path(args.system_config),
            firewall_cmd=args.firewall_cmd,
        )
    except FirewalldReconcileError as exc:
        print(f"nas-v2-firewalld-reconcile: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


__all__ = ["FirewalldReconcileError", "reconcile"]


if __name__ == "__main__":
    raise SystemExit(main())
