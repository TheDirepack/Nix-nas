#!/usr/bin/env python3
"""Import Compose sources into native Podman Quadlet bundles with Podlet.

Compose is an ingestion format only.  The finite V2 reconcile asks the Compose
provider to resolve/merge the source with V2's policy override, then asks
Podlet to translate that canonical Compose model to Quadlet.  The resulting
bundle is cached beneath the service app root and reused until the canonical
Compose model or tool identities change.  Runtime lifecycle never calls
``podman compose``.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
from typing import Any, Sequence

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from nas_v2_compose import ComposeProjectionError, render_compose_override


class ComposeImportError(RuntimeError):
    """Raised when a Compose source cannot be imported safely as Quadlet."""


APP_ROOT = pathlib.Path("/var/lib/nas-control/apps")
_CACHE_DIR = ".nas-v2-compose-quadlet"
_MANIFEST = "manifest.json"
_ALLOWED_SUFFIXES = frozenset({".container", ".pod", ".network", ".volume", ".kube", ".build", ".image"})
_SAFE_FILE = re.compile(r"^[A-Za-z0-9_.-]{1,255}$")
_EXPLICIT_SERVICE_NAME = re.compile(r"(?mi)^\s*ServiceName\s*=")
_EXPLICIT_CONTAINER_NAME = re.compile(r"(?mi)^\s*ContainerName\s*=")
_UNIT_HEADER = re.compile(r"(?mi)^\s*\[Unit\]\s*$")
_SECTION = re.compile(r"(?m)^\s*\[[^]]+\]\s*$")


def _absolute_binary(value: str, *, label: str) -> str:
    candidate = pathlib.PurePosixPath(value)
    if not candidate.is_absolute() or ".." in candidate.parts:
        raise ComposeImportError(f"{label} must be an absolute safe path")
    return value


def _run(
    command: Sequence[str],
    *,
    env: dict[str, str] | None = None,
    timeout: int = 120,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            list(command),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ComposeImportError(f"unable to execute {command[0]}: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[:4000]
        raise ComposeImportError(f"Compose import command failed ({result.returncode}): {' '.join(command)}: {detail}")
    return result


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _canonical_compose(
    effective: dict[str, Any],
    service_id: str,
    service: dict[str, Any],
    *,
    podman_bin: str,
    compose_provider_bin: str,
) -> tuple[pathlib.Path, bytes, bytes]:
    _absolute_binary(podman_bin, label=f"Compose service {service_id!r} Podman binary")
    _absolute_binary(compose_provider_bin, label=f"Compose service {service_id!r} provider binary")
    try:
        source, override = render_compose_override(effective, service_id, service)
    except ComposeProjectionError as exc:
        raise ComposeImportError(str(exc)) from exc
    try:
        source_bytes = source.read_bytes()
    except OSError as exc:
        raise ComposeImportError(f"unable to read Compose source {source}: {exc}") from exc
    # Podlet deliberately does not implement Compose interpolation.  Refuse a
    # model whose meaning would depend on ambient reconciliation environment;
    # V2 credentials/environment-file attachments are the deterministic secret
    # path instead.
    if b"${" in source_bytes:
        raise ComposeImportError(
            f"Compose service {service_id!r} uses interpolation, which Podlet import does not support; "
            "use literal configuration or V2 credential/environment-file attachments"
        )

    with tempfile.TemporaryDirectory(prefix=f"nas-v2-compose-config-{service_id}-") as raw:
        root = pathlib.Path(raw)
        override_path = root / "v2.override.yaml"
        override_path.write_bytes(override)
        env = os.environ.copy()
        env["PODMAN_COMPOSE_PROVIDER"] = compose_provider_bin
        command = [
            podman_bin,
            "compose",
            "--project-name",
            f"nas-v2-{service_id}",
            "--file",
            str(source),
            "--file",
            str(override_path),
            "config",
        ]
        canonical = _run(command, env=env).stdout.encode("utf-8")
    if not canonical.strip():
        raise ComposeImportError(f"Compose service {service_id!r} resolved to an empty model")
    _validate_canonical_networking(service_id, canonical)
    return source, override, canonical


def _validate_canonical_networking(service_id: str, canonical: bytes) -> None:
    """Fail closed if a multi-service model still relies on an implicit network.

    Podlet 0.3.2 does not synthesize Compose's implicit default network.  Most
    Compose ``config`` providers make that network explicit; if the selected
    provider does not, importing would silently break service-to-service DNS.
    """
    parser = YAML(typ="safe", pure=True)
    parser.version = (1, 2)
    parser.allow_duplicate_keys = False
    try:
        value = parser.load(canonical.decode("utf-8"))
    except (UnicodeError, YAMLError) as exc:
        raise ComposeImportError(f"Compose provider returned invalid canonical YAML for {service_id!r}: {exc}") from exc
    services = value.get("services") if isinstance(value, dict) else None
    if not isinstance(services, dict) or not services:
        raise ComposeImportError(f"Compose provider returned no services for {service_id!r}")
    if len(services) < 2:
        return
    for name, definition in services.items():
        if not isinstance(definition, dict):
            raise ComposeImportError(f"canonical Compose service {name!r} is invalid")
        if "network_mode" not in definition and "networks" not in definition:
            raise ComposeImportError(
                f"Compose provider left service {name!r} on an implicit default network; "
                "refusing Podlet import because Podlet 0.3.2 does not synthesize that network"
            )


def _inject_part_of(text: str, owner_unit: str) -> str:
    directive = f"PartOf={owner_unit}"
    if directive in text:
        return text
    match = _UNIT_HEADER.search(text)
    if match is not None:
        insertion = match.end()
        return text[:insertion] + "\n" + directive + text[insertion:]
    first_section = _SECTION.search(text)
    prefix = f"[Unit]\n{directive}\n\n"
    return prefix + text if first_section is not None else prefix + text


def _namespace_bundle(
    service_id: str,
    generated_dir: pathlib.Path,
    *,
    owner_unit: str,
) -> tuple[dict[str, bytes], list[str]]:
    raw_files: dict[str, str] = {}
    for path in sorted(generated_dir.iterdir(), key=lambda p: p.name):
        try:
            path.lstat()
        except OSError as exc:
            raise ComposeImportError(f"unable to inspect Podlet output {path}: {exc}") from exc
        if not path.is_file() or path.is_symlink():
            raise ComposeImportError(f"Podlet output must contain regular files only: {path.name}")
        if path.suffix not in _ALLOWED_SUFFIXES or _SAFE_FILE.fullmatch(path.name) is None:
            raise ComposeImportError(f"Podlet emitted unsupported file {path.name!r}")
        try:
            raw_files[path.name] = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise ComposeImportError(f"unable to read Podlet output {path}: {exc}") from exc
    if not raw_files:
        raise ComposeImportError("Podlet emitted no Quadlet files")

    mapping = {name: f"nas-v2-{service_id}-{name}" for name in raw_files}
    output: dict[str, bytes] = {}
    entry_units: list[str] = []
    # References between generated Quadlets use their filenames.  Prefix every
    # generated filename and rewrite exact filename references as one closed
    # namespace so common Compose names such as web/data/default cannot collide
    # across managed applications.
    replacements = sorted(mapping.items(), key=lambda item: len(item[0]), reverse=True)
    for old_name, text in raw_files.items():
        if _EXPLICIT_SERVICE_NAME.search(text):
            raise ComposeImportError(
                f"Podlet output {old_name!r} overrides ServiceName=; managed Compose imports require namespaced native units"
            )
        if _EXPLICIT_CONTAINER_NAME.search(text):
            raise ComposeImportError(
                f"Compose source for {service_id!r} sets container_name; remove it so V2 can provide collision-free native names"
            )
        for old_ref, new_ref in replacements:
            text = text.replace(old_ref, new_ref)
        new_name = mapping[old_name]
        if pathlib.Path(new_name).suffix in {".container", ".pod", ".kube"}:
            text = _inject_part_of(text, owner_unit)
        if not text.endswith("\n"):
            text += "\n"
        output[new_name] = text.encode("utf-8")
        if pathlib.Path(new_name).suffix == ".container":
            entry_units.append(pathlib.Path(new_name).with_suffix(".service").name)
    if not entry_units:
        raise ComposeImportError("Podlet Compose import emitted no .container entry units")
    return output, sorted(entry_units)


def _read_cached(cache: pathlib.Path, fingerprint: str) -> tuple[dict[str, bytes], dict[str, Any]] | None:
    manifest_path = cache / _MANIFEST
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if (
        not isinstance(manifest, dict)
        or manifest.get("schemaVersion") != 1
        or manifest.get("fingerprint") != fingerprint
    ):
        return None
    entries = manifest.get("files")
    entry_units = manifest.get("entryUnits")
    if not isinstance(entries, list) or not isinstance(entry_units, list) or not entry_units:
        return None
    files: dict[str, bytes] = {}
    for entry in entries:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("name"), str)
            or not isinstance(entry.get("sha256"), str)
        ):
            return None
        name = entry["name"]
        if _SAFE_FILE.fullmatch(name) is None or pathlib.Path(name).suffix not in _ALLOWED_SUFFIXES:
            return None
        path = cache / name
        try:
            if path.is_symlink() or not path.is_file():
                return None
            data = path.read_bytes()
        except OSError:
            return None
        if _sha256(data) != entry["sha256"]:
            return None
        files[name] = data
    return files, manifest


def _commit_cache(cache: pathlib.Path, files: dict[str, bytes], manifest: dict[str, Any]) -> None:
    parent = cache.parent
    parent.mkdir(parents=True, exist_ok=True)
    temporary = pathlib.Path(tempfile.mkdtemp(prefix=f".{cache.name}.", dir=parent))
    moved = False
    try:
        for name, data in files.items():
            path = temporary / name
            path.write_bytes(data)
            os.chmod(path, 0o640)
        (temporary / _MANIFEST).write_bytes(_json_bytes(manifest))
        os.chmod(temporary / _MANIFEST, 0o640)
        # Cache is derived state, never authority.  Replacing a directory is
        # intentionally simple: if a crash lands between removal and rename,
        # the next finite reconcile regenerates it from services.yaml.
        shutil.rmtree(cache, ignore_errors=True)
        os.replace(temporary, cache)
        moved = True
    finally:
        if not moved:
            shutil.rmtree(temporary, ignore_errors=True)


def import_compose(
    effective: dict[str, Any],
    service_id: str,
    service: dict[str, Any],
    *,
    podlet_bin: str,
    podman_bin: str,
    compose_provider_bin: str,
) -> tuple[dict[str, bytes], dict[str, Any]]:
    """Return the cached/native Quadlet bundle for one Compose import."""
    podlet_bin = _absolute_binary(podlet_bin, label=f"Compose service {service_id!r} Podlet binary")
    source, override, canonical = _canonical_compose(
        effective,
        service_id,
        service,
        podman_bin=podman_bin,
        compose_provider_bin=compose_provider_bin,
    )
    fingerprint = _sha256(
        b"nas-v2-compose-import-v1\0"
        + str(source).encode("utf-8")
        + b"\0"
        + override
        + b"\0"
        + canonical
        + b"\0"
        + podlet_bin.encode("utf-8")
        + b"\0"
        + podman_bin.encode("utf-8")
        + b"\0"
        + compose_provider_bin.encode("utf-8")
    )
    cache = APP_ROOT / service_id / _CACHE_DIR
    cached = _read_cached(cache, fingerprint)
    if cached is not None:
        return cached

    with tempfile.TemporaryDirectory(prefix=f"nas-v2-podlet-{service_id}-") as raw:
        root = pathlib.Path(raw)
        merged = root / "compose.yaml"
        generated = root / "quadlet"
        generated.mkdir()
        merged.write_bytes(canonical)
        _run([podlet_bin, "--file", str(generated), "compose", str(merged)])
        owner_unit = effective["derived"]["runtime"][service_id]["ownerUnit"]
        files, entry_units = _namespace_bundle(service_id, generated, owner_unit=owner_unit)

    manifest = {
        "schemaVersion": 1,
        "fingerprint": fingerprint,
        "source": str(source),
        "entryUnits": entry_units,
        "files": [{"name": name, "sha256": _sha256(data)} for name, data in sorted(files.items())],
    }
    _commit_cache(cache, files, manifest)
    return files, manifest


__all__ = ["APP_ROOT", "ComposeImportError", "import_compose"]
