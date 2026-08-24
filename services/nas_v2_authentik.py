#!/usr/bin/env python3
"""Compatibility exports for the native Authentik Blueprint projection.

Managed Services V2 no longer performs Authentik REST CRUD. Production applies
``nas_v2_authentik_blueprint`` with Authentik's own ``ak apply_blueprint``
command. Keep these pure compiler exports temporarily for callers that only
consume desired capability metadata; no HTTP or mutation path remains here.
"""

from nas_v2_authentik_blueprint import (
    AuthentikBlueprintError as AuthentikProjectionError,
    desired_applications,
    desired_capabilities,
    render_blueprint,
)

__all__ = [
    "AuthentikProjectionError",
    "desired_applications",
    "desired_capabilities",
    "render_blueprint",
]
