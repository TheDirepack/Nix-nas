"""Finite deadlines derived from the desired V2 dependency graph."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
from typing import Any

from nas_v2_spec import parse_yaml_text


def document_budget(document: dict[str, Any], previous_units: int = 0) -> dict[str, int]:
    services = document.get("services", {})
    if not isinstance(services, dict):
        raise ValueError("services must be an object for apply budgeting")
    costs: list[int] = []
    for name in services:
        visited: set[str] = set()
        gates: set[str] = set()

        def visit(current: str) -> None:
            if current in visited or current not in services:
                return
            visited.add(current)
            service = services[current]
            for dependency in service.get("dependencies", []):
                target = dependency["service"]
                if dependency.get("condition", "ready") == "ready":
                    gates.add(target)
                visit(target)

        visit(name)
        # Count each dependency once, even through a diamond. Summing parallel
        # branches is conservative; no readiness/start allowance is omitted.
        probe_seconds = sum(
            int(services[target].get("readiness", {}).get("timeoutSeconds", 60)) + 10
            for target in gates
            if target in services
        )
        costs.append(180 * len(visited) + probe_seconds)
    command = max([180, *costs])
    probes = sum(
        int(service.get("readiness", {}).get("timeoutSeconds", 60)) + 10
        for service in services.values()
        if "readiness" in service
    )
    schedules = sum(len(service.get("workload", {}).get("schedules", [])) for service in services.values())
    # Covers sequential activation and compensation, retired units, and the
    # final gate dispatch, with the original allowance for other projections.
    transaction = 300 + 2 * sum(costs) + 180 * (previous_units + 2 * schedules) + command + probes
    return {"commandSeconds": command + probes, "transactionSeconds": transaction + probes}


def authority_budget(desired: pathlib.Path, state: pathlib.Path) -> dict[str, Any]:
    raw = desired.read_bytes()
    previous = json.loads(state.read_text()) if state.exists() else {}
    budget = document_budget(parse_yaml_text(raw.decode(), source=str(desired)), len(previous.get("ownedUnits", [])))
    prior_command = previous.get("activationTimeoutSeconds", 180)
    if not isinstance(prior_command, int) or isinstance(prior_command, bool) or prior_command < 180:
        raise ValueError("invalid previous activation budget")
    budget["transactionSeconds"] += len(previous.get("ownedUnits", [])) * prior_command
    budget["commandSeconds"] = max(budget["commandSeconds"], prior_command)
    return {**budget, "desiredSha256": hashlib.sha256(raw).hexdigest()}


def client_timeout() -> int:
    try:
        budget = authority_budget(
            pathlib.Path(
                os.environ.get("NAS_V2_DESIRED", os.environ.get("NAS_V2_SPEC", "/var/lib/nas-control/services.yaml"))
            ),
            pathlib.Path("/run/nas-control/systemd-reconciled.json"),
        )
        return budget["transactionSeconds"] + 30
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RuntimeError):
        # The canonical worker reports malformed/missing authority. Its budget
        # preparation cannot arm or mutate an invalid transaction.
        return 330


def verify_budget_revision(raw: bytes) -> None:
    packet = os.environ.get("NAS_V2_APPLY_BUDGET")
    if packet:
        value = json.loads(pathlib.Path(packet).read_text())
        if value.get("desiredSha256") != hashlib.sha256(raw).hexdigest():
            raise ValueError("desired state changed after apply budgeting; retry reconciliation")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--desired", type=pathlib.Path, required=True)
    parser.add_argument("--state", type=pathlib.Path, required=True)
    args = parser.parse_args()
    print(json.dumps(authority_budget(args.desired, args.state), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
