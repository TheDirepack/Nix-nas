#!/usr/bin/env python3
"""Compatibility facade for the native Managed Services V2 systemd projection.

Compose is accepted only as an import format here.  It is converted to a
cached, namespaced Quadlet bundle before the native projector runs; runtime
lifecycle is therefore systemd + Quadlet rather than ``podman compose``.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import pathlib
from typing import Any

import nas_v2_systemd_native as _native
from nas_v2_compose_import import ComposeImportError, import_compose
from nas_v2_systemd_attachments import SystemdAttachmentError, attachment_lines

SystemdProjectionError = _native.SystemdProjectionError
APP_ROOT = _native.APP_ROOT


def _unit_value(value: str, *, label: str) -> str:
    if any(character in value for character in ("\x00", "\r", "\n")):
        raise SystemdProjectionError(f"{label} contains a forbidden control character")
    return value.replace("%", "%%")


def _compose_native_view(effective: dict[str, Any]) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    """Hide the obsolete Compose execution adapter from the native projector."""
    native = copy.deepcopy(effective)
    imports: dict[str, dict[str, Any]] = {}
    for service_id, original in effective.get("services", {}).items():
        if not isinstance(original, dict) or original.get("runtime", {}).get("type") != "compose":
            continue
        imports[service_id] = original
        service = native["services"][service_id]
        owner = effective["derived"]["runtime"][service_id]["ownerUnit"]
        # Keep workload/routes/readiness so the existing native activation and
        # readiness machinery still targets the aggregate owner unit.  Policy
        # that belongs inside containers is already present in the Compose
        # import override and must not also be attached to the aggregate unit.
        service["runtime"] = {"type": "systemd", "unit": owner}
        service["dependencies"] = []
        service["resources"] = {"accelerators": []}
        service["sandbox"] = {"mode": "inherit"}
        service["storage"] = []
        service["credentials"] = []
    return native, imports


def _dependency_units(effective: dict[str, Any], service: dict[str, Any]) -> tuple[set[str], set[str]]:
    requires: set[str] = set()
    after: set[str] = set()
    for dependency in service.get("dependencies", []):
        target = dependency["service"]
        owner = effective["derived"]["runtime"][target]["ownerUnit"]
        requires.add(owner)
        after.add(owner)
        if dependency["condition"] == "ready":
            ready = f"nas-v2-ready-{target}.service"
            requires.add(ready)
            after.add(ready)
    return requires, after


def _aggregate_unit(
    effective: dict[str, Any],
    service_id: str,
    service: dict[str, Any],
    entry_units: list[str],
) -> bytes:
    owner = effective["derived"]["runtime"][service_id]["ownerUnit"]
    requires, after = _dependency_units(effective, service)
    requires.update(entry_units)
    after.update(entry_units)
    lines = [
        "[Unit]",
        "Description=" + _unit_value(service["name"], label="Compose service name"),
    ]
    workload = service["workload"]
    if service["managed"] and workload["kind"] == "daemon" and workload.get("activation") == "on-demand":
        lines.append("StopWhenUnneeded=yes")
    if requires:
        lines.append("Requires=" + " ".join(sorted(requires)))
    if after:
        lines.append("After=" + " ".join(sorted(after)))
    lines.extend(
        [
            "",
            "[Service]",
            "Type=oneshot",
            "ExecStart=/run/current-system/sw/bin/true",
            "RemainAfterExit=yes",
            "",
        ]
    )
    del owner  # name is carried by the projection path/manifest
    return "\n".join(lines).encode("utf-8")


def _augment_compose_imports(
    effective: dict[str, Any],
    imports: dict[str, dict[str, Any]],
    *,
    output_dir: pathlib.Path,
    files: dict[pathlib.Path, bytes],
    manifest: dict[str, Any],
    podlet_bin: str,
    podman_bin: str,
    compose_provider_bin: str,
) -> None:
    if not imports:
        return
    links = {entry["target"]: entry["source"] for entry in manifest.get("links", [])}
    quadlet_links = {entry["target"]: entry["source"] for entry in manifest.get("quadletLinks", [])}
    owned = set(manifest.get("ownedUnits", []))
    stop = set(manifest.get("stopUnits", []))
    fingerprints = dict(manifest.get("fingerprints", {}))
    quadlet_dir = output_dir / "quadlet"
    unit_dir = output_dir / "units"

    for service_id, service in sorted(imports.items()):
        try:
            bundle, imported = import_compose(
                effective,
                service_id,
                service,
                podlet_bin=podlet_bin,
                podman_bin=podman_bin,
                compose_provider_bin=compose_provider_bin,
            )
        except ComposeImportError as exc:
            raise SystemdProjectionError(str(exc)) from exc
        entry_units = imported.get("entryUnits")
        if not isinstance(entry_units, list) or not entry_units or any(not isinstance(unit, str) for unit in entry_units):
            raise SystemdProjectionError(f"Compose import for {service_id!r} has no native entry units")
        for name, content in sorted(bundle.items()):
            path = quadlet_dir / name
            files[path] = content
            quadlet_links[name] = str(path)
        owner = effective["derived"]["runtime"][service_id]["ownerUnit"]
        owner_path = unit_dir / owner
        files[owner_path] = _aggregate_unit(effective, service_id, service, entry_units)
        links[owner] = str(owner_path)
        owned.update(entry_units)
        if not service["enabled"]:
            stop.update(entry_units)
        fingerprints[owner] = hashlib.sha256(
            json.dumps(
                {
                    "composeImport": imported["fingerprint"],
                    "dependencies": service["dependencies"],
                    "workload": service["workload"],
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()

    manifest["links"] = [
        {"target": target, "source": source} for target, source in sorted(links.items())
    ]
    manifest["quadletLinks"] = [
        {"target": target, "source": source} for target, source in sorted(quadlet_links.items())
    ]
    manifest["ownedUnits"] = sorted(owned)
    manifest["stopUnits"] = sorted(stop)
    manifest["fingerprints"] = fingerprints
    files[output_dir / "manifest.json"] = (
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


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
    import nas_v2_compose_import as _compose_import

    _compose_import.APP_ROOT = pathlib.Path(APP_ROOT)
    native_effective, compose_imports = _compose_native_view(effective)
    files, manifest = _native.generate_projection(
        native_effective,
        output_dir=output_dir,
        python_bin=python_bin,
        source_dir=source_dir,
        systemctl_bin=systemctl_bin,
        uv_bin=uv_bin,
        podman_bin=podman_bin,
        compose_provider_bin=compose_provider_bin,
        virsh_bin=virsh_bin,
    )
    if compose_imports:
        podlet_bin = os.environ.get("NAS_V2_PODLET_BIN", "podlet")
        _augment_compose_imports(
            effective,
            compose_imports,
            output_dir=output_dir,
            files=files,
            manifest=manifest,
            podlet_bin=podlet_bin,
            podman_bin=podman_bin,
            compose_provider_bin=compose_provider_bin,
        )
    return files, manifest


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
