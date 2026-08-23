#!/usr/bin/env python3
"""Caddy projection for Managed Services V2 — translates compiled routes to Caddyfile."""

from __future__ import annotations

import json
import pathlib
import re
import shutil
import subprocess
import tempfile
from typing import Any

PATH_SNIPPET = "nas_v2_managed_paths"
HOSTNAME_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE,
)
HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
MATCHER_RE = re.compile(r"[^A-Za-z0-9_]")
ADMIN_GROUP = "nas_admin"

IDENTITY_HEADERS = (
    "Remote-User",
    "Remote-Groups",
    "Remote-Name",
    "Remote-Email",
    "Remote-UID",
    "Remote-Role",
    "X-Authentik-Username",
    "X-Authentik-Groups",
    "X-Authentik-Name",
    "X-Authentik-Email",
    "X-Authentik-Uid",
    "X-Authentik-Jwt",
    "X-Authentik-Entitlements",
    "X-Authentik-Meta-Outpost",
    "X-Authentik-Meta-App",
    "X-Authentik-Meta-Provider",
    "X-Authentik-Meta-User",
    "X-Authentik-Meta-Is-Superuser",
    "X-Authentik-Role",
)
TRUSTED_IDENTITY_HEADERS = frozenset(IDENTITY_HEADERS)
AUTHENTIK_COPY_HEADERS = (
    "X-Authentik-Username",
    "X-Authentik-Groups",
    "X-Authentik-Name",
    "X-Authentik-Email",
    "X-Authentik-Uid",
)


class CaddyProjectionError(RuntimeError):
    """Raised when a V2 route cannot be represented safely in Caddy."""


_ctl = lambda value: "\x00" in value or "\r" in value or "\n" in value  # noqa: E731


def _q(value: str) -> str:
    if _ctl(value):
        raise CaddyProjectionError("Caddy value contains a forbidden control character")
    return json.dumps(value)


def _header_name(value: str) -> str:
    if not HEADER_NAME_RE.fullmatch(value):
        raise CaddyProjectionError(f"Unsafe HTTP header name {value!r}")
    return value


def _matcher(service_id: str, route_id: str, suffix: str) -> str:
    return MATCHER_RE.sub("_", f"v2_{service_id}_{route_id}_{suffix}")


def _safe_posix(path: str, msg: str) -> pathlib.PurePosixPath:
    if _ctl(path) or "{" in path or "}" in path:
        raise CaddyProjectionError(msg)
    socket = pathlib.PurePosixPath(path)
    if not socket.is_absolute() or ".." in socket.parts:
        raise CaddyProjectionError(msg)
    return socket


def _path_patterns(path: str) -> tuple[str, ...]:
    if not path.startswith("/") or _ctl(path) or "{" in path or "}" in path:
        raise CaddyProjectionError(f"Unsafe route path {path!r}")
    if path == "/":
        return ("/*",)
    if path.endswith("/"):
        return (path, path + "*")
    return (path, path + "/*")


def _render_identity_auth(
    lines: list[str],
    *,
    service_id: str,
    route_id: str,
    required_capability: str,
    authentik_upstream: str,
    authentik_path: str,
    authentik_public_host: str,
    indent: str,
) -> None:
    if _ctl(authentik_upstream) or "{" in authentik_upstream or "}" in authentik_upstream:
        raise CaddyProjectionError("Unsafe Authentik upstream")
    if not authentik_path.startswith("/") or _ctl(authentik_path):
        raise CaddyProjectionError("Authentik path must be an absolute HTTP path")
    prefix = authentik_path if authentik_path.endswith("/") else authentik_path + "/"
    authentik_uri = prefix + "outpost.goauthentik.io/auth/caddy"
    for header in IDENTITY_HEADERS:
        lines.append(f"{indent}request_header -{header}")
    lines.extend(
        [
            f"{indent}forward_auth {authentik_upstream} {{",
            f"{indent}  uri {_q(authentik_uri)}",
            f"{indent}  header_up X-Original-URL {{http.request.scheme}}://{{http.request.host}}{{http.request.orig_uri}}",
            f"{indent}  header_up X-Forwarded-Proto {{scheme}}",
            f"{indent}  header_up X-Forwarded-Host {{host}}",
            f"{indent}  header_up X-Forwarded-Uri {{uri}}",
            f"{indent}  copy_headers {' '.join(AUTHENTIK_COPY_HEADERS)}",
            f"{indent}}}",
        ]
    )
    missing_identity = _matcher(service_id, route_id, "missing_identity")
    missing_capability = _matcher(service_id, route_id, "missing_capability")
    groups = (required_capability, ADMIN_GROUP)
    if not groups:
        raise CaddyProjectionError("At least one authorization group is required")
    for group in groups:
        if group != ADMIN_GROUP and not group.startswith("application."):
            raise CaddyProjectionError(f"Invalid service capability name {group!r}")
    allowed_groups = rf"(^|[|,][[:space:]]*)({'|'.join(re.escape(g) for g in groups)})([[:space:]]*[|,]|$)"
    lines.extend(
        [
            f"{indent}@{missing_identity} not header X-Authentik-Username *",
            f"{indent}respond @{missing_identity} 403",
            f"{indent}@{missing_capability} {{",
            f"{indent}  not header_regexp X-Authentik-Groups {_q(allowed_groups)}",
            f"{indent}}}",
            f"{indent}respond @{missing_capability} 403",
            f"{indent}request_header Remote-User {{http.request.header.X-Authentik-Username}}",
            f"{indent}request_header Remote-Groups {{http.request.header.X-Authentik-Groups}}",
            f"{indent}request_header Remote-Name {{http.request.header.X-Authentik-Name}}",
            f"{indent}request_header Remote-Email {{http.request.header.X-Authentik-Email}}",
            f"{indent}request_header Remote-UID {{http.request.header.X-Authentik-Uid}}",
        ]
    )


def _render_wake(
    lines: list[str],
    *,
    service_id: str,
    auth_mode: str,
    wake_socket: str | None,
    indent: str,
) -> None:
    if auth_mode == "upstream":
        raise CaddyProjectionError(
            f"On-demand service {service_id!r} uses upstream-native authentication; "
            "a pre-upstream authorization mechanism is required before Caddy may wake it"
        )
    if wake_socket is None:
        raise CaddyProjectionError(f"On-demand service {service_id!r} requires the authorization-free V2 wake socket")
    socket = _safe_posix(wake_socket, "Wake socket must be an absolute safe path")
    lines.extend(
        [
            f"{indent}forward_auth unix/{socket} {{",
            f"{indent}  uri {_q('/wake?service=' + service_id)}",
            f"{indent}}}",
        ]
    )


def _render_proxy(
    lines: list[str],
    *,
    route: dict[str, Any],
    service_id: str,
    route_id: str,
    indent: str,
) -> None:
    proxy = route["proxy"]
    request_headers = proxy["requestHeaders"]
    for name in request_headers:
        if _header_name(name) in TRUSTED_IDENTITY_HEADERS:
            raise CaddyProjectionError(f"Static request header may not overwrite trusted identity header {name}")
    for name in proxy["removeRequestHeaders"]:
        lines.append(f"{indent}request_header -{_header_name(name)}")
    for name, value in sorted(request_headers.items()):
        lines.append(f"{indent}request_header {_header_name(name)} {_q(value)}")
    if proxy["trustedIdentityHeaders"] and route["authMode"] != "identity":
        raise CaddyProjectionError("trustedIdentityHeaders requires identity route authentication")
    for name in proxy["trustedIdentityHeaders"]:
        if name not in TRUSTED_IDENTITY_HEADERS:
            raise CaddyProjectionError(f"Unsupported trusted identity header {name!r}")
    strip_prefix = proxy.get("stripPrefix")
    if strip_prefix:
        lines.append(f"{indent}uri strip_prefix {_q(strip_prefix)}")
    target = route["target"]
    target_type = target["type"]
    if target_type in {"http", "https"}:
        host = target["host"]
        if _ctl(host) or " " in host or "{" in host or "}" in host:
            raise CaddyProjectionError(f"Unsafe upstream host {host!r}")
        upstream = f"{host}:{target['port']}"
        is_https = target_type == "https"
    elif target_type == "unix-http":
        upstream = f"unix/{_safe_posix(target['socket'], 'Unix HTTP target socket must be an absolute safe path')}"
        is_https = False
    else:  # pragma: no cover
        raise CaddyProjectionError(f"Unsupported route target type {target_type!r}")
    lines.append(f"{indent}reverse_proxy {upstream} {{")
    for name, value in sorted(proxy["responseHeaders"].items()):
        lines.append(f"{indent}  header_down {_header_name(name)} {_q(value)}")
    if is_https:
        lines.extend([f"{indent}  transport http {{", f"{indent}    tls", f"{indent}  }}"])
    lines.append(f"{indent}}}")


def _render_handler(
    lines: list[str],
    *,
    route: dict[str, Any],
    authentik_upstream: str,
    authentik_path: str,
    authentik_public_host: str,
    wake_socket: str | None,
    indent: str,
) -> None:
    service_id = route["service"]
    route_id = route["route"]
    lines.append(f"{indent}route {{")
    inner = indent + "  "
    for header in IDENTITY_HEADERS:
        lines.append(f"{inner}request_header -{header}")
    for index, (name, value) in enumerate(sorted(route["proxy"]["requireHeaders"].items())):
        header = _header_name(name)
        matcher = _matcher(service_id, route_id, f"missing_required_{index}")
        lines.extend(
            [
                f"{inner}@{matcher} {{",
                f"{inner}  not header {header} {_q(value)}",
                f"{inner}}}",
                f"{inner}respond @{matcher} 403",
            ]
        )
    if route["authMode"] == "identity":
        capability = route["requiredCapability"]
        if not capability:
            raise CaddyProjectionError("Identity route is missing its compiled required capability")
        _render_identity_auth(
            lines,
            service_id=service_id,
            route_id=route_id,
            required_capability=capability,
            authentik_upstream=authentik_upstream,
            authentik_path=authentik_path,
            authentik_public_host=authentik_public_host,
            indent=inner,
        )
    elif route["authMode"] not in {"public", "upstream"}:
        raise CaddyProjectionError(f"Unknown V2 route auth mode {route['authMode']!r}")
    if route["onDemandWake"]:
        _render_wake(lines, service_id=service_id, auth_mode=route["authMode"], wake_socket=wake_socket, indent=inner)
    _render_proxy(lines, route=route, service_id=service_id, route_id=route_id, indent=inner)
    lines.append(f"{indent}}}")


def generate_caddyfile(
    effective: dict[str, Any],
    *,
    authentik_upstream: str = "127.0.0.1:9010",
    authentik_path: str = "/identity/",
    lan_host: str = "nas.local",
    authentik_public_host: str | None = None,
    wake_socket: str | None = None,
) -> str:
    if not HOSTNAME_RE.fullmatch(lan_host):
        raise CaddyProjectionError(f"Invalid appliance hostname {lan_host!r}")
    public_host = authentik_public_host or lan_host
    if _ctl(public_host) or "/" in public_host or "{" in public_host or "}" in public_host:
        raise CaddyProjectionError(f"Invalid Authentik public host {public_host!r}")
    services = effective.get("services")
    derived = effective.get("derived")
    if not isinstance(services, dict) or not isinstance(derived, dict) or not isinstance(derived.get("routes"), list):
        raise CaddyProjectionError("Effective V2 document is missing compiled routes")
    routes = [
        r
        for r in derived["routes"]
        if isinstance(r, dict)
        and isinstance(r.get("service"), str)
        and isinstance(services.get(r["service"]), dict)
        and services[r["service"]].get("enabled") is True
    ]
    routes.sort(key=lambda item: (item["service"], item["route"]))
    path_routes: list[tuple[dict[str, Any], str]] = []
    hostname_routes: list[tuple[dict[str, Any], str, str]] = []
    for route in routes:
        exposure = route["exposure"]
        if exposure["type"] == "path":
            for path in exposure["paths"]:
                path_routes.append((route, path))
        elif exposure["type"] == "hostname":
            route_path = exposure["path"]
            for hostname in exposure["hostnames"]:
                if not HOSTNAME_RE.fullmatch(hostname):
                    raise CaddyProjectionError(f"Invalid route hostname {hostname!r}")
                if hostname.lower() == lan_host.lower():
                    raise CaddyProjectionError(f"Route hostname {hostname!r} collides with the appliance site")
                hostname_routes.append((route, hostname, route_path))
        else:  # pragma: no cover
            raise CaddyProjectionError(f"Unsupported route exposure type {exposure['type']!r}")

    # Guarantee longest-path-first ordering so parent/child routes are unambiguous.
    # More specific paths must be matched before their parents; see invariants.
    def _path_sort_key(item: tuple[dict[str, Any], str]) -> tuple[int, int, str, str, str]:
        route, path = item
        norm = path.rstrip("/") or "/"
        if norm == "/":
            seg_count = 0
        else:
            seg_count = len(norm.strip("/").split("/"))
        return (-seg_count, -len(norm), path, route["service"], route["route"])

    def _hostname_sort_key(item: tuple[dict[str, Any], str, str]) -> tuple[str, int, int, str, str, str]:
        route, hostname, path = item
        norm = path.rstrip("/") or "/"
        if norm == "/":
            seg_count = 0
        else:
            seg_count = len(norm.strip("/").split("/"))
        return (hostname, -seg_count, -len(norm), path, route["service"], route["route"])

    path_routes.sort(key=_path_sort_key)
    hostname_routes.sort(key=_hostname_sort_key)
    lines = ["# Generated by Managed Services V2 — do not edit", "", f"({PATH_SNIPPET}) {{"]
    for index, (route, path) in enumerate(path_routes):
        matcher = _matcher(route["service"], route["route"], f"path_{index}")
        patterns = " ".join(_q(item) for item in _path_patterns(path))
        lines.extend([f"  @{matcher} path {patterns}", f"  handle @{matcher} {{"])
        _render_handler(
            lines,
            route=route,
            authentik_upstream=authentik_upstream,
            authentik_path=authentik_path,
            authentik_public_host=public_host,
            wake_socket=wake_socket,
            indent="    ",
        )
        lines.append("  }")
    lines.extend(["}", ""])
    for index, (route, hostname, path) in enumerate(hostname_routes):
        lines.extend([f"https://{hostname} {{", "  tls internal"])
        matcher = _matcher(route["service"], route["route"], f"hostpath_{index}")
        patterns = " ".join(_q(item) for item in _path_patterns(path))
        lines.extend([f"  @{matcher} path {patterns}", f"  handle @{matcher} {{"])
        _render_handler(
            lines,
            route=route,
            authentik_upstream=authentik_upstream,
            authentik_path=authentik_path,
            authentik_public_host=public_host,
            wake_socket=wake_socket,
            indent="    ",
        )
        lines.extend(["  }", "}", ""])
    return "\n".join(lines).rstrip() + "\n"


def validate_caddyfile(caddyfile: str, *, caddy_bin: str | None = None) -> None:
    binary = caddy_bin or shutil.which("caddy")
    if not binary:
        raise CaddyProjectionError("Caddy binary is required for configuration validation")
    with tempfile.TemporaryDirectory(prefix="nas-v2-caddy-") as raw_tmp:
        path = pathlib.Path(raw_tmp) / "Caddyfile"
        path.write_text(caddyfile, encoding="utf-8")
        result = subprocess.run(
            [binary, "validate", "--config", str(path), "--adapter", "caddyfile"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[:4000]
        raise CaddyProjectionError(f"Caddy rejected generated V2 configuration: {detail}")


class PortalProjectionError(RuntimeError):
    """Raised when portal metadata cannot be projected safely."""


def _canonical_capability(service_id: str, capability: str) -> str:
    return f"application.{service_id}.{capability}"


def _route_url(exposure: dict[str, Any], portal: dict[str, Any]) -> str:
    explicit = portal.get("url")
    if isinstance(explicit, str) and explicit.startswith("/") and not explicit.startswith("//"):
        return explicit
    exposure_type = exposure.get("type")
    if exposure_type == "path":
        paths = exposure.get("paths")
        candidate = paths[0] if isinstance(paths, list) and paths and isinstance(paths[0], str) else None
        if isinstance(candidate, str) and candidate.startswith("/") and not candidate.startswith("//"):
            return candidate
        raise PortalProjectionError("visible portal path route has no safe path")
    if exposure_type == "hostname":
        hostnames = exposure.get("hostnames")
        path = exposure.get("path", "/")
        if (
            isinstance(hostnames, list)
            and hostnames
            and isinstance(hostnames[0], str)
            and isinstance(path, str)
            and path.startswith("/")
        ):
            return f"https://{hostnames[0]}{path}"
    raise PortalProjectionError("visible portal route has no safe URL")


def _access(service_id: str, route: dict[str, Any]) -> dict[str, Any]:
    auth = route.get("auth")
    if not isinstance(auth, dict):
        raise PortalProjectionError(f"route {service_id!r} has no normalized auth policy")
    mode = auth.get("mode")
    if mode == "identity":
        capability = auth.get("capability", "access")
        if not isinstance(capability, str) or not capability:
            raise PortalProjectionError(f"route {service_id!r} has an invalid capability")
        return {
            "mode": "groups",
            "allow": "groups",
            "groups": [_canonical_capability(service_id, capability), ADMIN_GROUP],
            "users": [],
        }
    if mode == "public":
        return {"mode": "public", "allow": "any", "groups": [], "users": []}
    if mode == "upstream":
        # The portal is already behind appliance authentication. Upstream-native
        # application auth remains authoritative after the user follows the link.
        return {"mode": "upstream", "allow": "any", "groups": [], "users": []}
    raise PortalProjectionError(f"route {service_id!r} has unsupported auth mode {mode!r}")


def compile_portal_projection(effective: dict[str, Any]) -> dict[str, Any]:
    if effective.get("schemaVersion") != 3:
        raise PortalProjectionError("effective state must use schema version 3")
    services = effective.get("services")
    if not isinstance(services, dict):
        raise PortalProjectionError("effective state is missing services")
    # Prefer the already-compiled derived routes (single source of truth for Caddy)
    # to avoid re-traversing services and re-deriving capabilities. Fall back to
    # services for unit tests that provide a minimal effective without derived.
    derived = effective.get("derived")
    if isinstance(derived, dict) and isinstance(derived.get("routes"), list):
        entries: list[dict[str, Any]] = []
        for route in derived["routes"]:
            if not isinstance(route, dict):
                continue
            service_id = route.get("service")
            route_id = route.get("route")
            if not isinstance(service_id, str) or not isinstance(route_id, str):
                continue
            service = services.get(service_id)
            if not isinstance(service, dict) or service.get("enabled", True) is False:
                continue
            portal = route.get("portal", {})
            if not isinstance(portal, dict) or portal.get("visible") is not True:
                continue
            exposure = route.get("exposure")
            if not isinstance(exposure, dict):
                raise PortalProjectionError(f"visible route {service_id}.{route_id} has invalid exposure")
            auth_mode = route.get("authMode")
            if auth_mode == "identity" and isinstance(route.get("requiredCapability"), str):
                access = {
                    "mode": "groups",
                    "allow": "groups",
                    "groups": [route["requiredCapability"], ADMIN_GROUP],
                    "users": [],
                }
            elif auth_mode == "public":
                access = {"mode": "public", "allow": "any", "groups": [], "users": []}
            elif auth_mode == "upstream":
                access = {"mode": "upstream", "allow": "any", "groups": [], "users": []}
            else:
                access = _access(service_id, route)
            entries.append(
                {
                    "id": f"{service_id}.{route_id}",
                    "service": service_id,
                    "route": route_id,
                    "label": portal.get("title") or service.get("name") or service_id,
                    "description": portal.get("description") or service.get("description", ""),
                    "category": portal.get("category") or "Other",
                    "icon": portal.get("icon") or "box",
                    "order": portal.get("order", 0),
                    "url": _route_url(exposure, portal),
                    "access": access,
                }
            )
        entries.sort(key=lambda item: (item["order"], item["category"], item["label"], item["id"]))
        return {"schemaVersion": 2, "source": "managed-services-v2", "entries": entries}

    entries: list[dict[str, Any]] = []
    for service_id in sorted(services):
        service = services[service_id]
        if not isinstance(service, dict) or service.get("enabled", True) is False:
            continue
        routes = service.get("routes", {})
        if not isinstance(routes, dict):
            raise PortalProjectionError(f"service {service_id!r} has invalid routes")
        for route_id in sorted(routes):
            route = routes[route_id]
            if not isinstance(route, dict):
                continue
            portal = route.get("portal", {})
            if not isinstance(portal, dict) or portal.get("visible") is not True:
                continue
            exposure = route.get("exposure")
            if not isinstance(exposure, dict):
                raise PortalProjectionError(f"visible route {service_id}.{route_id} has invalid exposure")
            entries.append(
                {
                    "id": f"{service_id}.{route_id}",
                    "service": service_id,
                    "route": route_id,
                    "label": portal.get("title") or service.get("name") or service_id,
                    "description": portal.get("description") or service.get("description", ""),
                    "category": portal.get("category") or "Other",
                    "icon": portal.get("icon") or "box",
                    "order": portal.get("order", 0),
                    "url": _route_url(exposure, portal),
                    "access": _access(service_id, route),
                }
            )
    entries.sort(key=lambda item: (item["order"], item["category"], item["label"], item["id"]))
    return {"schemaVersion": 2, "source": "managed-services-v2", "entries": entries}


def portal_bytes(effective: dict[str, Any]) -> bytes:
    return (json.dumps(compile_portal_projection(effective), indent=2, sort_keys=True) + "\n").encode("utf-8")


__all__ = [
    "CaddyProjectionError",
    "generate_caddyfile",
    "validate_caddyfile",
    "PortalProjectionError",
    "compile_portal_projection",
    "portal_bytes",
]
