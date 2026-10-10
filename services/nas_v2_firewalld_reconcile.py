#!/usr/bin/env python3
"""Reconcile compiled native firewalld objects through firewall-cmd.

The V2 projection is already a native-object manifest. Validate every object
before the first mutation; the outer guarded V2 transaction owns rollback.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import pathlib
import re
import subprocess
import sys
from typing import Any, Sequence

_OWNED_NAME = re.compile(r"^nv2[zhwlrima][0-9a-f]{12}$")
_INTERFACE = re.compile(r"^nv2[0-9a-f]{11}$")
_ZONE = re.compile(r"^(?:nv2z[0-9a-f]{12}|[A-Za-z0-9_][A-Za-z0-9_-]{0,16}|HOST|ANY)$")
_PORT = re.compile(r"^[0-9]{1,5}(?:-[0-9]{1,5})?$")


class FirewalldReconcileError(RuntimeError):
    """The native firewall policy could not be validated, applied or verified."""


def _run(command: Sequence[str], *, timeout: int = 60, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            list(command), stdin=subprocess.DEVNULL, capture_output=True, text=True,
            timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise FirewalldReconcileError(f"unable to execute {command[0]}: {exc}") from exc
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[:4000]
        raise FirewalldReconcileError(f"command failed ({result.returncode}): {command[0]}: {detail}")
    return result


def _permanent(firewall_cmd: str, *args: str) -> subprocess.CompletedProcess[str]:
    return _run([firewall_cmd, "--permanent", *args])


def _port(value: Any, protocol: Any) -> str:
    if not isinstance(value, str) or not _PORT.fullmatch(value) or protocol not in {"tcp", "udp"}:
        raise FirewalldReconcileError("invalid native firewalld port or protocol")
    bounds = [int(item) for item in value.split("-")]
    if any(not 1 <= item <= 65535 for item in bounds) or len(bounds) == 2 and bounds[0] > bounds[1]:
        raise FirewalldReconcileError("invalid native firewalld port range")
    return f"{value}/{protocol}"


def _check_object(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise FirewalldReconcileError("invalid native firewall object")
    kind, name = value.get("kind"), value.get("name")
    if kind not in {"zone", "policy"} or not isinstance(name, str) or not _OWNED_NAME.fullmatch(name):
        raise FirewalldReconcileError("outside the V2 ownership namespace")
    if kind == "zone":
        if not name.startswith("nv2z") or set(value) != {"kind", "name", "interface"}:
            raise FirewalldReconcileError("invalid projected native zone")
        if not isinstance(value["interface"], str) or not _INTERFACE.fullmatch(value["interface"]):
            raise FirewalldReconcileError("unsafe projected interface")
        return value
    if name.startswith("nv2z") or set(value) != {
        "kind", "name", "target", "priority", "ingress", "egress", "ports", "forwardPorts", "richRules",
    }:
        raise FirewalldReconcileError("invalid projected native policy")
    if value["target"] not in {"ACCEPT", "DROP", "CONTINUE"} or type(value["priority"]) is not int or (
        value["priority"] == 0 or not -32767 <= value["priority"] <= 32767
    ):
        raise FirewalldReconcileError("invalid policy target or priority")
    for field in ("ingress", "egress"):
        if not isinstance(value[field], str) or not _ZONE.fullmatch(value[field]):
            raise FirewalldReconcileError("unsafe projected policy zone")
    if not all(isinstance(value[key], list) for key in ("ports", "forwardPorts", "richRules")):
        raise FirewalldReconcileError("invalid native policy collections")
    for item in value["ports"]:
        if not isinstance(item, list) or len(item) != 2:
            raise FirewalldReconcileError("invalid native policy port")
        _port(item[0], item[1])
    for item in value["forwardPorts"]:
        if not isinstance(item, list) or len(item) != 3:
            raise FirewalldReconcileError("invalid native forward port")
        _port(item[0], item[1])
        _port(item[2], item[1])
    for rule in value["richRules"]:
        if not isinstance(rule, dict) or set(rule) not in (
            {"family", "destination"}, {"family", "destination", "port", "protocol"}
        ):
            raise FirewalldReconcileError("invalid native rich rule")
        try:
            network = ipaddress.ip_network(rule["destination"], strict=False)
        except (TypeError, ValueError) as exc:
            raise FirewalldReconcileError("invalid native rich-rule destination") from exc
        if rule["family"] != ("ipv4" if network.version == 4 else "ipv6"):
            raise FirewalldReconcileError("invalid native rich-rule family")
        if "port" in rule:
            _port(rule["port"], rule["protocol"])
    return value


def _read_projection(manifest_path: pathlib.Path) -> dict[str, dict[str, Any]]:
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FirewalldReconcileError(f"unable to read native firewall manifest: {exc}") from exc
    if (
        not isinstance(manifest, dict)
        or manifest.get("schemaVersion") != 2
        or not isinstance(manifest.get("objects"), list)
    ):
        raise FirewalldReconcileError("native firewalld projection manifest is invalid")
    desired: dict[str, dict[str, Any]] = {}
    for entry in manifest["objects"]:
        value = _check_object(entry)
        if value["name"] in desired:
            raise FirewalldReconcileError("duplicate native firewall object")
        desired[value["name"]] = value
    zones = {name for name, obj in desired.items() if obj["kind"] == "zone"}
    for obj in desired.values():
        if obj["kind"] == "policy":
            for zone in (obj["ingress"], obj["egress"]):
                if zone.startswith("nv2z") and zone not in zones:
                    raise FirewalldReconcileError(f"projected policy references missing zone {zone}: INVALID_ZONE")
    return desired


def _current_owned(firewall_cmd: str) -> tuple[set[str], set[str]]:
    zones = set(_permanent(firewall_cmd, "--get-zones").stdout.split())
    policies = set(_permanent(firewall_cmd, "--get-policies").stdout.split())
    return (
        {name for name in zones if _OWNED_NAME.fullmatch(name) and name.startswith("nv2z")},
        {name for name in policies if _OWNED_NAME.fullmatch(name) and not name.startswith("nv2z")},
    )


def _rich_rule(rule: dict[str, Any]) -> str:
    parts = [
        "rule", f'family="{rule["family"]}"', 'priority="-10"',
        "destination", f'address="{rule["destination"]}"',
    ]
    if "port" in rule:
        parts.extend(["port", f'port="{rule["port"]}"', f'protocol="{rule["protocol"]}"'])
    parts.append("accept")
    return " ".join(parts)


def _apply_zone(firewall_cmd: str, zone: dict[str, Any]) -> None:
    name = zone["name"]
    _permanent(firewall_cmd, f"--new-zone={name}")
    _permanent(firewall_cmd, f"--zone={name}", f"--add-interface={zone['interface']}")


def _apply_policy(firewall_cmd: str, policy: dict[str, Any]) -> None:
    name = policy["name"]
    _permanent(firewall_cmd, f"--new-policy={name}")
    _permanent(firewall_cmd, f"--policy={name}", f"--set-target={policy['target']}")
    _permanent(firewall_cmd, f"--policy={name}", f"--set-priority={policy['priority']}")
    for key, option in (("ingress", "--add-ingress-zone"), ("egress", "--add-egress-zone")):
        _permanent(firewall_cmd, f"--policy={name}", f"{option}={policy[key]}")
    for port, protocol in policy["ports"]:
        _permanent(firewall_cmd, f"--policy={name}", f"--add-port={port}/{protocol}")
    for port, protocol, destination in policy["forwardPorts"]:
        _permanent(
            firewall_cmd, f"--policy={name}",
            f"--add-forward-port=port={port}:proto={protocol}:toport={destination}",
        )
    for rule in policy["richRules"]:
        _permanent(firewall_cmd, f"--policy={name}", f"--add-rich-rule={_rich_rule(rule)}")


def _verify_runtime(*, desired: dict[str, dict[str, Any]], firewall_cmd: str) -> None:
    _run([firewall_cmd, "--state"])
    zones = set(_run([firewall_cmd, "--get-zones"]).stdout.split())
    policies = set(_run([firewall_cmd, "--get-policies"]).stdout.split())
    missing_zones = sorted(n for n, obj in desired.items() if obj["kind"] == "zone" and n not in zones)
    missing_policies = sorted(n for n, obj in desired.items() if obj["kind"] == "policy" and n not in policies)
    if missing_zones or missing_policies:
        raise FirewalldReconcileError(
            "firewalld reload omitted projected objects: "
            + f"zones={','.join(missing_zones)} policies={','.join(missing_policies)}"
        )


def reconcile(*, manifest_path: pathlib.Path, firewall_cmd: str = "firewall-cmd") -> dict[str, Any]:
    """Apply validated native objects, then check, reload and verify."""
    desired = _read_projection(manifest_path)
    current_zones, current_policies = _current_owned(firewall_cmd)
    for name in sorted(current_policies):
        _permanent(firewall_cmd, f"--delete-policy={name}")
    for name in sorted(current_zones):
        _permanent(firewall_cmd, f"--delete-zone={name}")
    for value in sorted((obj for obj in desired.values() if obj["kind"] == "zone"), key=lambda x: x["name"]):
        _apply_zone(firewall_cmd, value)
    for value in sorted(
        (obj for obj in desired.values() if obj["kind"] == "policy"),
        key=lambda x: (x["priority"], x["name"]),
    ):
        _apply_policy(firewall_cmd, value)
    _run([firewall_cmd, "--check-config"])
    _run([firewall_cmd, "--reload"])
    _verify_runtime(desired=desired, firewall_cmd=firewall_cmd)
    return {"ok": True, "changed": bool(current_zones or current_policies or desired),
            "objects": sorted(desired), "runtimeVerified": True, "nativePermanentApi": True}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--firewall-cmd", default="firewall-cmd")
    args = parser.parse_args(argv)
    try:
        result = reconcile(manifest_path=pathlib.Path(args.manifest), firewall_cmd=args.firewall_cmd)
    except FirewalldReconcileError as exc:
        print(f"nas-v2-firewalld-reconcile: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


__all__ = ["FirewalldReconcileError", "reconcile"]


if __name__ == "__main__":
    raise SystemExit(main())
