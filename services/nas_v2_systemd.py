#!/usr/bin/env python3
"""Compatibility facade for the native Managed Services V2 systemd projection."""

from __future__ import annotations

import pathlib
from typing import Any

import nas_v2_systemd_native as _native
from nas_v2_systemd_attachments import SystemdAttachmentError, attachment_lines

SystemdProjectionError = _native.SystemdProjectionError
APP_ROOT = _native.APP_ROOT


def generate_projection(
    effective: dict[str, Any],
    *,
    output_dir: pathlib.Path,
    python_bin: str,
    source_dir: pathlib.Path,
    systemctl_bin: str,
    uv_bin: str,
    podman_bin: str = "podman",
    compose_provider_bin: str = "podman-compose",
    virsh_bin: str = "virsh",
) -> tuple[dict[pathlib.Path, bytes], dict[str, Any]]:
    # Preserve the long-standing test/embedding hook that patches
    # nas_v2_systemd.APP_ROOT while keeping implementation details isolated.
    _native.APP_ROOT = pathlib.Path(APP_ROOT)
    return _native.generate_projection(
        effective,
        output_dir=output_dir,
        python_bin=python_bin,
        source_dir=source_dir,
        systemctl_bin=systemctl_bin,
        uv_bin=uv_bin,
        podman_bin=podman_bin,
        compose_provider_bin=compose_provider_bin,
        virsh_bin=virsh_bin,
    )


def validate_projection(
    files: dict[pathlib.Path, bytes],
    *,
    systemd_analyze_bin: str,
    quadlet_generator_bin: str | None = None,
    virt_xml_validate_bin: str | None = None,
) -> None:
    _native.validate_projection(
        files,
        systemd_analyze_bin=systemd_analyze_bin,
        quadlet_generator_bin=quadlet_generator_bin,
        virt_xml_validate_bin=virt_xml_validate_bin,
    )


__all__ = [
    "APP_ROOT",
    "SystemdAttachmentError",
    "SystemdProjectionError",
    "attachment_lines",
    "generate_projection",
    "validate_projection",
]
