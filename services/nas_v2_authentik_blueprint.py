#!/usr/bin/env python3
"""Render Managed Services V2 Authentik objects as one native blueprint.

Caddy is the request-time authorization boundary. V2 therefore needs only:

* inert ``application.<service>.<capability>`` groups whose membership remains
  entirely Authentik-owned;
* providerless launcher applications for portal-visible identity routes; and
* direct application bindings to the required capability and ``nas_admin``.

No Authentik REST client, proxy-provider CRUD, outpost mutation, pagination or
resident controller is needed. ``ak apply_blueprint`` validates and applies the
result atomically inside Authentik.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys
import tempfile
from typing import Any

CAPABILITY_RE = re.compile(r"^application\.[a-z][a-z0-9-]{0,63}\.[a-z][a-z0-9.-]{0,127}$")
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,127}$")
ADMIN_GROUP = "nas_admin"


class AuthentikBlueprintError(RuntimeError):
    """Raised when effective state cannot be represented safely as a blueprint."""


def _json_object(path: pathlib.Path, *, missing_ok: bool = False) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        if missing_ok:
            return {}
        raise AuthentikBlueprintError(f"missing JSON input: {path}") from None
    except OSError as exc:
        raise AuthentikBlueprintError(f"unable to read {path}: {exc}") from exc
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AuthentikBlueprintError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise AuthentikBlueprintError(f"JSON input must contain an object: {path}")
    return value


def _q(value: str) -> str:
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise AuthentikBlueprintError("Authentik blueprint string contains a control character")
    return json.dumps(value, ensure_ascii=False)


def _find(model: str, field: str, value: str) -> str:
    return f"!Find [{model}, [{field}, {_q(value)}]]"


def desired_capabilities(effective: dict[str, Any]) -> dict[str, str]:
    if effective.get("schemaVersion") != 3:
        raise AuthentikBlueprintError("compiled effective state must use schema version 3")
    derived = effective.get("derived")
    authorization = derived.get("authorization") if isinstance(derived, dict) else None
    if not isinstance(authorization, dict):
        raise AuthentikBlueprintError("compiled effective state is missing authorization metadata")

    capabilities: dict[str, str] = {}
    for service_id in sorted(authorization):
        service_auth = authorization[service_id]
        mapping = service_auth.get("capabilities") if isinstance(service_auth, dict) else None
        if not isinstance(mapping, dict):
            raise AuthentikBlueprintError(f"authorization metadata for {service_id!r} is invalid")
        for canonical_name in mapping.values():
            if not isinstance(canonical_name, str) or not CAPABILITY_RE.fullmatch(canonical_name):
                raise AuthentikBlueprintError(f"canonical capability name is unsafe: {canonical_name!r}")
            previous = capabilities.setdefault(canonical_name, service_id)
            if previous != service_id:
                raise AuthentikBlueprintError(f"canonical capability {canonical_name!r} is shared by multiple services")
    return capabilities


def _launch_url(exposure: dict[str, Any], *, public_host: str) -> str:
    exposure_type = exposure.get("type")
    if exposure_type == "path":
        paths = exposure.get("paths")
        path = paths[0] if isinstance(paths, list) and paths and isinstance(paths[0], str) else None
        if not path or not path.startswith("/") or path.startswith("//"):
            raise AuthentikBlueprintError("portal-visible path route has no safe launch path")
        return f"https://{public_host}{path}"
    if exposure_type == "hostname":
        hostnames = exposure.get("hostnames")
        hostname = hostnames[0] if isinstance(hostnames, list) and hostnames and isinstance(hostnames[0], str) else None
        path = exposure.get("path", "/")
        if not hostname or not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
            raise AuthentikBlueprintError("portal-visible hostname route has no safe launch URL")
        return f"https://{hostname}{path}"
    raise AuthentikBlueprintError(f"unsupported route exposure type {exposure_type!r}")


def desired_applications(effective: dict[str, Any], *, public_host: str) -> dict[str, dict[str, str]]:
    if not public_host or any(character in public_host for character in "/\r\n\x00"):
        raise AuthentikBlueprintError("public host is unsafe")
    services = effective.get("services")
    derived = effective.get("derived")
    routes = derived.get("routes") if isinstance(derived, dict) else None
    if not isinstance(services, dict) or not isinstance(routes, list):
        raise AuthentikBlueprintError("compiled effective state is missing services or routes")

    apps: dict[str, dict[str, str]] = {}
    for route in sorted(routes, key=lambda item: (str(item.get("service")), str(item.get("route")))):
        if not isinstance(route, dict) or route.get("authMode") != "identity":
            continue
        service_id = route.get("service")
        route_id = route.get("route")
        if not isinstance(service_id, str) or not isinstance(route_id, str):
            raise AuthentikBlueprintError("compiled identity route has invalid identifiers")
        service = services.get(service_id)
        if not isinstance(service, dict) or service.get("enabled") is not True:
            continue
        portal = route.get("portal")
        if not isinstance(portal, dict) or portal.get("visible") is not True:
            continue
        capability = route.get("requiredCapability")
        if not isinstance(capability, str) or not CAPABILITY_RE.fullmatch(capability):
            raise AuthentikBlueprintError(f"identity route {service_id}.{route_id} has invalid capability")
        slug = f"v2-{service_id}-{route_id}"
        if not SLUG_RE.fullmatch(slug):
            raise AuthentikBlueprintError(f"generated Authentik application slug is unsafe: {slug!r}")
        title = portal.get("title")
        name = title if isinstance(title, str) and title else service.get("name")
        if not isinstance(name, str) or not name:
            name = f"NAS {service_id} ({route_id})"
        exposure = route.get("exposure")
        if not isinstance(exposure, dict):
            raise AuthentikBlueprintError(f"identity route {service_id}.{route_id} has invalid exposure")
        if slug in apps:
            raise AuthentikBlueprintError(f"duplicate Authentik application slug {slug!r}")
        apps[slug] = {
            "name": name,
            "launchUrl": _launch_url(exposure, public_host=public_host),
            "capability": capability,
        }
    return apps


def _previous_objects(previous: dict[str, Any]) -> tuple[set[str], set[str]]:
    if not previous:
        return set(), set()
    if previous.get("schemaVersion") != 1:
        raise AuthentikBlueprintError("previous Authentik object manifest has unsupported schemaVersion")
    raw_groups = previous.get("groups", [])
    raw_apps = previous.get("applications", [])
    if not isinstance(raw_groups, list) or not isinstance(raw_apps, list):
        raise AuthentikBlueprintError("previous Authentik object manifest is invalid")
    groups = {value for value in raw_groups if isinstance(value, str) and CAPABILITY_RE.fullmatch(value)}
    apps = {value for value in raw_apps if isinstance(value, str) and SLUG_RE.fullmatch(value)}
    if len(groups) != len(raw_groups) or len(apps) != len(raw_apps):
        raise AuthentikBlueprintError("previous Authentik object manifest contains unsafe identifiers")
    return groups, apps


def render_blueprint(
    effective: dict[str, Any],
    *,
    public_host: str,
    previous: dict[str, Any] | None = None,
) -> tuple[bytes, dict[str, Any]]:
    capabilities = desired_capabilities(effective)
    applications = desired_applications(effective, public_host=public_host)
    previous_groups, previous_apps = _previous_objects(previous or {})

    lines = [
        "# yaml-language-server: $schema=https://goauthentik.io/blueprints/schema.json",
        "# Generated by Managed Services V2 — do not edit",
        "version: 1",
        "metadata:",
        "  name: Managed Services V2 applications",
        "entries:",
    ]

    for group, service_id in sorted(capabilities.items()):
        lines.extend(
            [
                "  - model: authentik_core.group",
                "    state: present",
                "    identifiers:",
                f"      name: {_q(group)}",
                "    attrs:",
                "      is_superuser: false",
                "      attributes:",
                "        nasManagedCapability: true",
                f"        nasManagedService: {_q(service_id)}",
            ]
        )

    for slug, app in sorted(applications.items()):
        lines.extend(
            [
                "  - model: authentik_core.application",
                "    state: present",
                "    identifiers:",
                f"      slug: {_q(slug)}",
                "    attrs:",
                f"      name: {_q(app['name'])}",
                f"      meta_launch_url: {_q(app['launchUrl'])}",
                "      provider: null",
                "  - model: authentik_policies.policybinding",
                "    state: present",
                "    identifiers:",
                f"      target: {_find('authentik_core.application', 'slug', slug)}",
                "      order: 0",
                "    attrs:",
                f"      group: {_find('authentik_core.group', 'name', app['capability'])}",
                "      enabled: true",
                "      negate: false",
                "  - model: authentik_policies.policybinding",
                "    state: present",
                "    identifiers:",
                f"      target: {_find('authentik_core.application', 'slug', slug)}",
                "      order: 1",
                "    attrs:",
                f"      group: {_find('authentik_core.group', 'name', ADMIN_GROUP)}",
                "      enabled: true",
                "      negate: false",
            ]
        )

    # Removing a file-backed blueprint does not delete objects it created, so
    # explicit state=absent entries are generated from the last successfully
    # applied generated-object manifest. This manifest is a cache/projection,
    # never a desired-state authority.
    for slug in sorted(previous_apps - set(applications)):
        lines.extend(
            [
                "  - model: authentik_core.application",
                "    state: absent",
                "    identifiers:",
                f"      slug: {_q(slug)}",
            ]
        )
    for group in sorted(previous_groups - set(capabilities)):
        lines.extend(
            [
                "  - model: authentik_core.group",
                "    state: absent",
                "    identifiers:",
                f"      name: {_q(group)}",
            ]
        )

    manifest = {
        "schemaVersion": 1,
        "groups": sorted(capabilities),
        "applications": sorted(applications),
    }
    return ("\n".join(lines) + "\n").encode("utf-8"), manifest


def _atomic_write(path: pathlib.Path, data: bytes, *, mode: int = 0o640) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, raw = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp = pathlib.Path(raw)
    replaced = False
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp, mode)
        os.replace(temp, path)
        replaced = True
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if not replaced:
            temp.unlink(missing_ok=True)


def generate(
    *,
    effective_path: pathlib.Path,
    blueprint_path: pathlib.Path,
    manifest_path: pathlib.Path,
    next_manifest_path: pathlib.Path,
    public_host: str,
) -> dict[str, Any]:
    effective = _json_object(effective_path)
    previous = _json_object(manifest_path, missing_ok=True)
    blueprint, manifest = render_blueprint(effective, public_host=public_host, previous=previous)
    _atomic_write(blueprint_path, blueprint, mode=0o644)
    _atomic_write(
        next_manifest_path,
        (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        mode=0o640,
    )
    return {"ok": True, **manifest, "blueprint": str(blueprint_path), "nextManifest": str(next_manifest_path)}


def commit_manifest(*, next_manifest_path: pathlib.Path, manifest_path: pathlib.Path) -> dict[str, Any]:
    next_manifest = _json_object(next_manifest_path)
    if next_manifest.get("schemaVersion") != 1:
        raise AuthentikBlueprintError("next Authentik manifest is invalid")
    _atomic_write(
        manifest_path,
        (json.dumps(next_manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        mode=0o640,
    )
    next_manifest_path.unlink(missing_ok=True)
    return {"ok": True, "manifest": str(manifest_path)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    render = sub.add_parser("generate")
    render.add_argument("--effective", required=True)
    render.add_argument("--blueprint", required=True)
    render.add_argument("--manifest", required=True)
    render.add_argument("--next-manifest", required=True)
    render.add_argument("--public-host", required=True)
    commit = sub.add_parser("commit")
    commit.add_argument("--manifest", required=True)
    commit.add_argument("--next-manifest", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "generate":
            result = generate(
                effective_path=pathlib.Path(args.effective),
                blueprint_path=pathlib.Path(args.blueprint),
                manifest_path=pathlib.Path(args.manifest),
                next_manifest_path=pathlib.Path(args.next_manifest),
                public_host=args.public_host,
            )
        else:
            result = commit_manifest(
                next_manifest_path=pathlib.Path(args.next_manifest),
                manifest_path=pathlib.Path(args.manifest),
            )
    except AuthentikBlueprintError as exc:
        print(f"nas-v2-authentik-blueprint: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


__all__ = [
    "ADMIN_GROUP",
    "AuthentikBlueprintError",
    "commit_manifest",
    "desired_applications",
    "desired_capabilities",
    "generate",
    "render_blueprint",
]


if __name__ == "__main__":
    raise SystemExit(main())
