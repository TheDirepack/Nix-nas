#!/usr/bin/env python3
"""Reconcile Managed Services V2 host VLAN/VRF topology with nmstate.

This module is deliberately finite and stateless. ``services.yaml`` remains the
only mutable desired-state authority; nmstate/NetworkManager own the native
host configuration. Podman bridge networks remain Quadlet-owned.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys
from typing import Any, Sequence

from nas_v2_network import network_policy, vlan_binding

_VRF_RE = re.compile(r"^nv2vrf[0-9a-f]{7}$")
_VLAN_RE = re.compile(r"^nv2vl[0-9a-f]{8}$")


class NmstateReconcileError(RuntimeError):
    """Raised when host network state cannot be reconciled safely."""


def _run(
    command: Sequence[str], *, input_text: str | None = None, timeout: int = 60
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            list(command),
            input=input_text,
            stdin=None if input_text is not None else subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise NmstateReconcileError(f"unable to execute {command[0]}: {exc}") from exc


def _load_effective(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise NmstateReconcileError(f"unable to read compiled effective state {path}: {exc}") from exc
    if not isinstance(value, dict) or value.get("schemaVersion") != 3:
        raise NmstateReconcileError("compiled effective state must be a Managed Services V2 schemaVersion 3 object")
    return value


def _bound_policy(policy: dict[str, Any], vlan_parent: str | None) -> dict[str, Any]:
    if "vlanId" not in policy or "vlanParent" in policy:
        return policy
    if not vlan_parent:
        raise NmstateReconcileError(
            "network.vlanId requires host platform configuration nas.networking.applicationVlanParent"
        )
    return {**policy, "vlanParent": vlan_parent}


def desired_state(effective: dict[str, Any], *, vlan_parent: str | None = None) -> dict[str, Any]:
    """Compile the host-owned VLAN/VRF subset into nmstate desired state."""
    services = effective.get("services")
    if not isinstance(services, dict):
        raise NmstateReconcileError("compiled effective state is missing services")

    bindings: dict[str, dict[str, Any]] = {}
    for service_id in sorted(services):
        service = services[service_id]
        if not isinstance(service, dict) or not service.get("managed", True) or not service.get("enabled", True):
            continue
        try:
            policy = _bound_policy(network_policy(effective, service), vlan_parent)
            binding = vlan_binding(policy)
        except RuntimeError as exc:
            raise NmstateReconcileError(str(exc)) from exc
        if binding is not None:
            bindings[binding["key"]] = binding

    interfaces: list[dict[str, Any]] = []
    for key in sorted(bindings):
        binding = bindings[key]
        vlan_name = binding["vlanInterface"]
        vrf_name = binding["vrfInterface"]
        interfaces.extend(
            [
                {
                    "name": vlan_name,
                    "type": "vlan",
                    "state": "up",
                    "vlan": {"base-iface": binding["parent"], "id": binding["id"]},
                    "ipv4": {
                        "enabled": True,
                        "dhcp": True,
                        "auto-dns": False,
                        "auto-routes": True,
                        "auto-gateway": True,
                    },
                    "ipv6": {
                        "enabled": True,
                        "dhcp": True,
                        "autoconf": True,
                        "auto-dns": False,
                        "auto-routes": True,
                        "auto-gateway": True,
                    },
                },
                {
                    "name": vrf_name,
                    "type": "vrf",
                    "state": "up",
                    "vrf": {"port": [vlan_name], "route-table-id": binding["table"]},
                    "ipv4": {"enabled": False},
                    "ipv6": {"enabled": False},
                },
            ]
        )
    return {"interfaces": interfaces}


def _current_state(nmstatectl: str) -> dict[str, Any]:
    result = _run([nmstatectl, "show", "--json"], timeout=30)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[:4000]
        raise NmstateReconcileError(f"nmstatectl show failed ({result.returncode}): {detail}")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise NmstateReconcileError(f"nmstatectl show returned invalid JSON: {exc}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("interfaces"), list):
        raise NmstateReconcileError("nmstatectl show returned an invalid network state")
    return value


def _with_stale_absent(desired: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    desired_ifaces = desired.get("interfaces")
    current_ifaces = current.get("interfaces")
    if not isinstance(desired_ifaces, list) or not isinstance(current_ifaces, list):
        raise NmstateReconcileError("nmstate interface state must contain interface lists")
    wanted = {
        iface.get("name") for iface in desired_ifaces if isinstance(iface, dict) and isinstance(iface.get("name"), str)
    }
    stale: set[str] = set()
    for iface in current_ifaces:
        name = iface.get("name") if isinstance(iface, dict) else None
        if isinstance(name, str) and (_VRF_RE.fullmatch(name) or _VLAN_RE.fullmatch(name)) and name not in wanted:
            stale.add(name)
    # Remove VRFs before their VLAN ports. nmstate still receives one atomic
    # desired state, but deterministic order makes diagnostics easier.
    absent = [
        {"name": name, "state": "absent"}
        for name in sorted(stale, key=lambda item: (0 if _VRF_RE.fullmatch(item) else 1, item))
    ]
    return {"interfaces": [*desired_ifaces, *absent]}


def reconcile(
    effective: dict[str, Any],
    *,
    nmstatectl: str = "nmstatectl",
    vlan_parent: str | None = None,
) -> dict[str, Any]:
    """Apply the complete V2-owned host topology through nmstate's transaction."""
    desired = desired_state(effective, vlan_parent=vlan_parent)
    current = _current_state(nmstatectl)
    state = _with_stale_absent(desired, current)
    payload = json.dumps(state, sort_keys=True)
    result = _run([nmstatectl, "apply", "-"], input_text=payload, timeout=90)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[:4000]
        raise NmstateReconcileError(f"nmstatectl apply failed ({result.returncode}): {detail}")
    return {
        "ok": True,
        "desiredInterfaces": sorted(
            iface["name"]
            for iface in desired["interfaces"]
            if isinstance(iface, dict) and isinstance(iface.get("name"), str)
        ),
        "removedInterfaces": sorted(
            iface["name"] for iface in state["interfaces"] if isinstance(iface, dict) and iface.get("state") == "absent"
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--effective", required=True)
    parser.add_argument("--nmstatectl", default="nmstatectl")
    parser.add_argument("--vlan-parent", default=None)
    args = parser.parse_args(argv)
    try:
        result = reconcile(
            _load_effective(pathlib.Path(args.effective)),
            nmstatectl=args.nmstatectl,
            vlan_parent=args.vlan_parent,
        )
    except NmstateReconcileError as exc:
        print(f"nas-v2-nmstate: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


__all__ = ["NmstateReconcileError", "desired_state", "reconcile"]


if __name__ == "__main__":
    raise SystemExit(main())
