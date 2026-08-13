#!/usr/bin/env python3
"""Generate native systemd path watches for Managed Services V2 source artifacts."""

from __future__ import annotations

import pathlib
import subprocess
import tempfile
from typing import Any


class SourceWatchProjectionError(RuntimeError):
    """Raised when a managed source watch cannot be represented safely."""


APP_ROOT = pathlib.Path("/var/lib/nas-control/apps")


def _quote(value: str) -> str:
    if any(character in value for character in ("\x00", "\r", "\n")):
        raise SourceWatchProjectionError("managed source path contains a forbidden control character")
    return '"' + value.replace("%", "%%").replace("\\", "\\\\").replace('"', '\\"') + '"'


def _managed_source(service_id: str, value: str) -> pathlib.Path:
    candidate = pathlib.Path(value)
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to((APP_ROOT / service_id).resolve(strict=False))
    except (OSError, ValueError) as exc:
        raise SourceWatchProjectionError(
            f"managed source for service {service_id!r} must exist beneath its managed app root"
        ) from exc
    if not resolved.is_file():
        raise SourceWatchProjectionError(f"managed source for service {service_id!r} must name a file")
    return resolved


def source_paths(effective: dict[str, Any], service_id: str, service: dict[str, Any]) -> list[pathlib.Path]:
    """Return validated source files whose edits require recompiling one active managed service."""
    del effective
    if not service["managed"] or not service.get("enabled", True):
        return []

    runtime = service["runtime"]
    runtime_type = runtime["type"]
    paths: list[pathlib.Path] = []
    if runtime_type in {"compose", "vm", "quadlet"}:
        source = runtime.get("source")
        if not isinstance(source, str):
            raise SourceWatchProjectionError(f"runtime source for service {service_id!r} is missing")
        paths.append(_managed_source(service_id, source))
    elif runtime_type == "python":
        requirements = runtime["dependencies"].get("requirementsFile")
        if requirements is not None:
            if not isinstance(requirements, str):
                raise SourceWatchProjectionError(f"Python requirements source for service {service_id!r} is invalid")
            paths.append(_managed_source(service_id, requirements))

    return sorted(set(paths), key=str)


def _path_unit(service_id: str, paths: list[pathlib.Path]) -> bytes:
    lines = [
        "[Unit]",
        f"Description=Managed Services V2 source watch for {service_id}",
        "",
        "[Path]",
    ]
    lines.extend("PathChanged=" + _quote(str(path)) for path in paths)
    lines.extend(
        [
            "Unit=nas-managed-services-reconcile.service",
            "",
            "[Install]",
            "WantedBy=multi-user.target",
            "",
        ]
    )
    return "\n".join(lines).encode()


def augment_projection(
    effective: dict[str, Any],
    *,
    output_dir: pathlib.Path,
    files: dict[pathlib.Path, bytes],
    manifest: dict[str, Any],
) -> None:
    """Add source watches to an existing staged systemd projection and manifest."""
    links = manifest.get("links")
    owned = manifest.get("ownedUnits")
    start = manifest.get("startUnits")
    if not isinstance(links, list) or not isinstance(owned, list) or not isinstance(start, list):
        raise SourceWatchProjectionError("systemd projection manifest is missing lifecycle fields")

    known_targets = {item.get("target") for item in links if isinstance(item, dict)}
    for service_id in sorted(effective["services"]):
        service = effective["services"][service_id]
        paths = source_paths(effective, service_id, service)
        if not paths:
            continue
        unit = f"nas-v2-source-{service_id}.path"
        if unit in known_targets:
            raise SourceWatchProjectionError(f"duplicate systemd source watch target {unit!r}")
        unit_path = output_dir / "units" / unit
        files[unit_path] = _path_unit(service_id, paths)
        links.append({"target": unit, "source": str(unit_path)})
        owned.append(unit)
        start.append(unit)
        known_targets.add(unit)

    links.sort(key=lambda item: item["target"])
    owned[:] = sorted(set(owned))
    start[:] = sorted(set(start))


def validate_source_watches(files: dict[pathlib.Path, bytes], *, systemd_analyze_bin: str) -> None:
    """Validate generated .path units with systemd-analyze before activation."""
    watches = {path: content for path, content in files.items() if path.suffix == ".path"}
    if not watches:
        return
    with tempfile.TemporaryDirectory(prefix="nas-v2-source-watch-verify-") as raw_tmp:
        root = pathlib.Path(raw_tmp)
        paths: list[str] = []
        for source, content in watches.items():
            destination = root / source.name
            destination.write_bytes(content)
            paths.append(str(destination))
        result = subprocess.run(
            [systemd_analyze_bin, "verify", *paths],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[:4000]
        raise SourceWatchProjectionError(f"systemd-analyze rejected generated source watches: {detail}")


__all__ = [
    "SourceWatchProjectionError",
    "augment_projection",
    "source_paths",
    "validate_source_watches",
]
