#!/usr/bin/env python3
"""Composed Managed Services V2 engine.

The engine is assembled from generic policy layers. Adding or changing an
application does not require Python changes: service definitions provide the
runtime, dependencies, lifecycle, storage, network, authorization, and device
resource intent.
"""

from __future__ import annotations

from typing import Any

import nas_managed_service_devices as _devices

# Device resolution decorates the generic runtime boundary first; dependency
# ordering then calls that same boundary for every runtime in the graph.
_devices._install()

import nas_managed_service_dependencies as _dependencies  # noqa: E402

_dependencies._install()

effective_registry = _dependencies.effective_registry
dependency_order = _dependencies.dependency_order
start_service = _dependencies.start_service
stop_service = _dependencies.stop_service
touch_service = _dependencies.touch_service
reconcile_lifecycle = _dependencies.reconcile_lifecycle
reap_lifecycle = _dependencies.reap_lifecycle


def main(argv: list[str] | None = None) -> int:
    _devices._install()
    _dependencies._install()
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
