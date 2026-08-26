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
import ipaddress
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import xml.etree.ElementTree as StdElementTree
from typing import Any, Sequence

from defusedxml import ElementTree

_OWNED_FILE = re.compile(r"^nv2[zhwlrima][0-9a-f]{12}\.xml$")
_OWNED_NAME = re.compile(r"^nv2[zhwlrima][0-9a-f]{12}$")
_PORT_RANGE = re.compile(r"^(?P<start>[1-9][0-9]{0,4})(?:-(?P<end>[1-9][0-9]{0,4}))?$")
_SAFE_INTERFACE = re.compile(r"^[A-Za-z0-9_.:@-]{1,64}$")
_SAFE_FIREWALL_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_ALLOWED_PROTOCOLS = frozenset({"tcp", "udp", "sctp", "dccp"})
_ALLOWED_FAMILIES = frozenset({"ipv4", "ipv6"})
_ALLOWED_TARGETS = frozenset({"ACCEPT", "DROP", "REJECT", "default"})
_MAX_PROJECTION_FILE_BYTES = 4 * 1024 * 1024


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


def _read_regular_file(path: pathlib.Path, *, label: str) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise FirewalldReconcileError(f"{label} is missing or unsafe: {path}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise FirewalldReconcileError(f"{label} must be a regular non-symlink file: {path}")
        if metadata.st_size > _MAX_PROJECTION_FILE_BYTES:
            raise FirewalldReconcileError(f"{label} exceeds the projection size limit: {path}")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            payload = handle.read(_MAX_PROJECTION_FILE_BYTES + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(payload) > _MAX_PROJECTION_FILE_BYTES:
        raise FirewalldReconcileError(f"{label} exceeds the projection size limit: {path}")
    return payload


def _read_projection(
    manifest_path: pathlib.Path,
    projection_root: pathlib.Path,
) -> dict[pathlib.PurePosixPath, bytes]:
    try:
        manifest = json.loads(_read_regular_file(manifest_path, label="firewalld manifest").decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise FirewalldReconcileError(f"unable to read firewalld manifest {manifest_path}: {exc}") from exc
    if (
        not isinstance(manifest, dict)
        or manifest.get("schemaVersion") != 1
        or not isinstance(manifest.get("files"), list)
    ):
        raise FirewalldReconcileError("firewalld projection manifest is invalid")

    try:
        resolved_root = projection_root.resolve(strict=True)
    except OSError as exc:
        raise FirewalldReconcileError(f"firewalld projection root is unavailable: {projection_root}") from exc
    if not resolved_root.is_dir():
        raise FirewalldReconcileError("firewalld projection root must be a directory")

    desired: dict[pathlib.PurePosixPath, bytes] = {}
    for entry in manifest["files"]:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("target"), str)
            or not isinstance(entry.get("sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", entry.get("sha256", "")) is None
        ):
            raise FirewalldReconcileError("firewalld manifest file entry is invalid")
        target = _safe_target(entry["target"])
        source = resolved_root / str(target)
        try:
            source.relative_to(resolved_root)
        except ValueError as exc:
            raise FirewalldReconcileError(f"projected firewalld file is outside the projection root: {source}") from exc
        payload = _read_regular_file(source, label="projected firewalld file")
        if hashlib.sha256(payload).hexdigest() != entry["sha256"]:
            raise FirewalldReconcileError(f"projected firewalld file changed after validation: {source}")
        if target in desired:
            raise FirewalldReconcileError(f"duplicate firewalld projection target: {target}")
        desired[target] = payload
    return desired


def _attr(element: StdElementTree.Element, name: str, *, label: str) -> str:
    value = element.get(name)
    if not value or any(ch in value for ch in "\r\n\x00"):
        raise FirewalldReconcileError(f"projected {label} is missing safe attribute {name!r}")
    return value


def _port(value: str, *, label: str) -> str:
    match = _PORT_RANGE.fullmatch(value)
    if match is None:
        raise FirewalldReconcileError(f"projected {label} has invalid port {value!r}")
    start = int(match.group("start"))
    end = int(match.group("end") or start)
    if start > 65535 or end > 65535 or end < start:
        raise FirewalldReconcileError(f"projected {label} has invalid port {value!r}")
    return value


def _protocol(value: str, *, label: str) -> str:
    if value not in _ALLOWED_PROTOCOLS:
        raise FirewalldReconcileError(f"projected {label} has invalid protocol {value!r}")
    return value


def _priority(value: str, *, label: str) -> str:
    if re.fullmatch(r"-?[0-9]{1,6}", value) is None:
        raise FirewalldReconcileError(f"projected {label} has invalid priority {value!r}")
    number = int(value)
    if not -32768 <= number <= 32767:
        raise FirewalldReconcileError(f"projected {label} has invalid priority {value!r}")
    return value


def _family(value: str) -> str:
    if value not in _ALLOWED_FAMILIES:
        raise FirewalldReconcileError(f"projected rich rule has invalid family {value!r}")
    return value


def _network(value: str, *, family: str) -> str:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise FirewalldReconcileError(f"projected rich rule has invalid destination {value!r}") from exc
    expected = 4 if family == "ipv4" else 6
    if network.version != expected:
        raise FirewalldReconcileError("projected rich-rule destination does not match its address family")
    return value


def _target_value(value: str, *, label: str) -> str:
    if value not in _ALLOWED_TARGETS:
        raise FirewalldReconcileError(f"projected {label} has invalid target {value!r}")
    return value


def _firewall_name(value: str, *, label: str) -> str:
    if _SAFE_FIREWALL_NAME.fullmatch(value) is None:
        raise FirewalldReconcileError(f"projected {label} has invalid name {value!r}")
    return value


def _interface_name(value: str) -> str:
    if _SAFE_INTERFACE.fullmatch(value) is None:
        raise FirewalldReconcileError(f"projected zone has invalid interface {value!r}")
    return value


def _rich_rule(element: StdElementTree.Element) -> str:
    family = _family(_attr(element, "family", label="rich rule"))
    priority = element.get("priority")
    parts = ["rule", f'family="{family}"']
    if priority:
        parts.append(f'priority="{_priority(priority, label="rich rule")}"')
    destination = element.find("destination")
    if destination is not None:
        address = _network(_attr(destination, "address", label="destination"), family=family)
        parts.extend(["destination", f'address="{address}"'])
    port = element.find("port")
    if port is not None:
        port_value = _port(_attr(port, "port", label="rich-rule port"), label="rich-rule port")
        protocol = _protocol(_attr(port, "protocol", label="rich-rule port"), label="rich-rule port")
        parts.extend(["port", f'port="{port_value}"', f'protocol="{protocol}"'])
    actions = [name for name in ("accept", "drop", "reject") if element.find(name) is not None]
    if len(actions) != 1:
        raise FirewalldReconcileError("projected rich rule must have exactly one supported action")
    parts.append(actions[0])
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
        _permanent(firewall_cmd, f"--zone={name}", f"--set-target={_target_value(target, label='zone')}")
    for interface in root.findall("interface"):
        value = _interface_name(_attr(interface, "name", label="zone interface"))
        _permanent(firewall_cmd, f"--zone={name}", f"--add-interface={value}")
    for service in root.findall("service"):
        value = _firewall_name(_attr(service, "name", label="zone service"), label="zone service")
        _permanent(firewall_cmd, f"--zone={name}", f"--add-service={value}")
    for port in root.findall("port"):
        port_value = _port(_attr(port, "port", label="zone port"), label="zone port")
        protocol = _protocol(_attr(port, "protocol", label="zone port"), label="zone port")
        _permanent(firewall_cmd, f"--zone={name}", f"--add-port={port_value}/{protocol}")


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
        _permanent(firewall_cmd, f"--policy={name}", f"--set-target={_target_value(target, label='policy')}")
    if priority:
        _permanent(firewall_cmd, f"--policy={name}", f"--set-priority={_priority(priority, label='policy')}")
    for zone in root.findall("ingress-zone"):
        value = _firewall_name(_attr(zone, "name", label="ingress zone"), label="ingress zone")
        _permanent(firewall_cmd, f"--policy={name}", f"--add-ingress-zone={value}")
    for zone in root.findall("egress-zone"):
        value = _firewall_name(_attr(zone, "name", label="egress zone"), label="egress zone")
        _permanent(firewall_cmd, f"--policy={name}", f"--add-egress-zone={value}")
    for port in root.findall("port"):
        port_value = _port(_attr(port, "port", label="policy port"), label="policy port")
        protocol = _protocol(_attr(port, "protocol", label="policy port"), label="policy port")
        _permanent(firewall_cmd, f"--policy={name}", f"--add-port={port_value}/{protocol}")
    for forward in root.findall("forward-port"):
        source_port = _port(_attr(forward, "port", label="forward port"), label="forward port")
        protocol = _protocol(_attr(forward, "protocol", label="forward port"), label="forward port")
        target_port = _port(_attr(forward, "to-port", label="forward port"), label="forward port")
        value = f"port={source_port}:proto={protocol}:toport={target_port}"
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
    firewall_cmd: str = "firewall-cmd",
) -> dict[str, Any]:
    """Replace the complete V2 native namespace, reload firewalld, and verify it."""
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
    parser.add_argument("--firewall-cmd", default="firewall-cmd")
    args = parser.parse_args(argv)
    try:
        result = reconcile(
            manifest_path=pathlib.Path(args.manifest),
            projection_root=pathlib.Path(args.projection_root),
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
