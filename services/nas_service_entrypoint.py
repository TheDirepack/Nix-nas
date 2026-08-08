#!/usr/bin/env python3
"""Installed entrypoint for managed services.

Keeps compatibility helpers in nas_managed_service while selecting the hardened
orchestrator and runtime-only Caddy projection for actual appliance mutations.
"""
from __future__ import annotations

import nas_service_caddy_runtime
import nas_service_orchestrator


def main(argv: list[str] | None = None) -> int:
    nas_service_orchestrator.nas_service_caddy = nas_service_caddy_runtime
    return nas_service_orchestrator.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
