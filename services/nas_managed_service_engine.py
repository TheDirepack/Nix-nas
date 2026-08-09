#!/usr/bin/env python3
"""Composed Managed Services V2 engine.

The engine is assembled from generic policy layers. Adding or changing an
application does not require Python changes: service definitions provide the
runtime, dependencies, lifecycle, storage, network, authorization, readiness,
and device-resource intent.
"""

from __future__ import annotations

from typing import Any

from nas_managed_devices import normalize_gpu_requests
from nas_managed_resources import ManagedResourceError
import nas_managed_service_devices as _devices

# Device resolution decorates the generic runtime boundary first; dependency
# ordering then calls that same boundary for every runtime in the graph.
_devices._install()

import nas_managed_service_dependencies as _dependencies  # noqa: E402

_dependencies._install()


def effective_registry(*args: Any, **kwargs: Any) -> dict[str, Any]:
    effective = _dependencies.effective_registry(*args, **kwargs)
    services = effective.get("services") or {}
    if not isinstance(services, dict):
        raise ManagedResourceError("Effective managed service registry services must be an object")
    for service_id, service in services.items():
        if not isinstance(service, dict):
            raise ManagedResourceError(f"Service {service_id!r} must be an object")
        resources = service.get("resources") or {}
        if not isinstance(resources, dict):
            raise ManagedResourceError(f"Service {service_id}: resources must be an object")
        normalize_gpu_requests(resources.get("gpus", []))
    return effective


# Install the validated registry at the dependency boundary too, so every CLI
# action and authorization-gate wake sees exactly the same contract.
_dependencies.effective_registry = effective_registry

dependency_order = _dependencies.dependency_order
start_service = _dependencies.start_service
stop_service = _dependencies.stop_service
touch_service = _dependencies.touch_service
reconcile_lifecycle = _dependencies.reconcile_lifecycle
reap_lifecycle = _dependencies.reap_lifecycle


def main(argv: list[str] | None = None) -> int:
    _devices._install()
    _dependencies._install()
    _dependencies.effective_registry = effective_registry
    return _dependencies._v2.main(argv)


__all__ = [
    "dependency_order",
    "effective_registry",
    "main",
    "reap_lifecycle",
    "reconcile_lifecycle",
    "start_service",
    "stop_service",
    "touch_service",
]


if __name__ == "__main__":
    raise SystemExit(main())
