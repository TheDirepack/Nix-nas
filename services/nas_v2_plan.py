#!/usr/bin/env python3
"""Build generic native-subsystem plans from the Managed Services V2 effective model."""

from __future__ import annotations

import copy
from typing import Any


def _runtime_action(service_id: str, service: dict[str, Any], owner_unit: str) -> dict[str, Any]:
    workload = service["workload"]
    return {
        "action": "ensure-runtime",
        "service": service_id,
        "runtimeType": service["runtime"]["type"],
        "ownerUnit": owner_unit,
        "enabled": service["enabled"],
        "managed": service["managed"],
        "workloadKind": workload["kind"],
        "activation": workload.get("activation"),
    }


def build_plan(effective: dict[str, Any]) -> dict[str, Any]:
    """Return deterministic plans. No plan action assigns users or authorizes a request."""
    plan: dict[str, Any] = {
        "schemaVersion": 1,
        "generation": effective["generation"],
        "runtime": [],
        "systemd": [],
        "authentik": [],
        "caddy": [],
        "network": [],
        "storageBackup": [],
    }

    derived = effective["derived"]
    services = effective["services"]

    for service_id in sorted(services):
        service = services[service_id]
        runtime_meta = derived["runtime"][service_id]
        plan["runtime"].append(_runtime_action(service_id, service, runtime_meta["ownerUnit"]))

        for dependency in service["dependencies"]:
            plan["systemd"].append(
                {
                    "action": "dependency",
                    "service": service_id,
                    "dependsOn": dependency["service"],
                    "condition": dependency["condition"],
                }
            )

        workload = service["workload"]
        if workload["kind"] == "job":
            for index, schedule in enumerate(workload["schedules"]):
                plan["systemd"].append(
                    {
                        "action": "timer",
                        "service": service_id,
                        "scheduleIndex": index,
                        "schedule": copy.deepcopy(schedule),
                    }
                )
        elif workload["kind"] == "daemon" and workload["activation"] == "on-demand":
            plan["systemd"].append(
                {
                    "action": "socket-activation",
                    "service": service_id,
                    "routes": sorted(service["routes"]),
                    "idleSeconds": workload["idleSeconds"],
                }
            )

        for capability_id, canonical_name in sorted(derived["authorization"][service_id]["capabilities"].items()):
            plan["authentik"].append(
                {
                    "action": "ensure-capability",
                    "service": service_id,
                    "capability": capability_id,
                    "canonicalName": canonical_name,
                }
            )

        if "networkProfile" in service:
            policy = effective["networkProfiles"][service["networkProfile"]]
        else:
            policy = service.get("network")
        if policy is not None:
            plan["network"].append(
                {
                    "action": "service-policy",
                    "service": service_id,
                    "policy": copy.deepcopy(policy),
                }
            )

        for listener_id, listener in sorted(service["listeners"].items()):
            plan["network"].append(
                {
                    "action": "listener",
                    "service": service_id,
                    "listener": listener_id,
                    "protocol": listener["protocol"],
                    "exposure": copy.deepcopy(listener["exposure"]),
                    "firewall": listener["firewall"],
                }
            )

    for route in derived["routes"]:
        plan["caddy"].append({"action": "route", **copy.deepcopy(route)})

    for resource_id in sorted(effective["storageResources"]):
        resource = effective["storageResources"][resource_id]
        plan["storageBackup"].append(
            {
                "action": "resource",
                "resource": resource_id,
                "path": resource["path"],
                "stateClass": resource["stateClass"],
                "backup": copy.deepcopy(resource["backup"]),
                "fileBrowser": copy.deepcopy(resource["fileBrowser"]),
            }
        )

    for service_id in sorted(services):
        for attachment in services[service_id]["storage"]:
            plan["storageBackup"].append(
                {
                    "action": "attach",
                    "service": service_id,
                    "attachment": copy.deepcopy(attachment),
                }
            )

    return plan
