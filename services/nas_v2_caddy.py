#!/usr/bin/env python3
"""Caddy projection for Managed Services V2 routes.

Authorization remains in Caddy + Authentik. This module only translates the
compiled V2 route model into Caddy configuration and optionally validates that
configuration with the Caddy binary. It never evaluates users/groups itself.

The base ``nas_admin`` role is an appliance-wide administrator bypass. Normal
application access is granted only by canonical
``application.<service>.<capability>`` Authentik groups emitted by V2.
"""

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


def _q(value: str) -> str:
    if any(character in value for character in ("\x00", "\r", "\n")):
        raise CaddyProjectionError("Caddy value contains a forbidden control character")
    return json.dumps(value)


def _header_name(value: str) -> str:
    if not HEADER_NAME_RE.fullmatch(value):
        raise CaddyProjectionError(f"Unsafe HTTP header name {value!r}")
    return value


def _matcher(service_id: str, route_id: str, suffix: str) -> str:
    raw = f"v2_{service_id}_{route_id}_{suffix}"
    return MATCHER_RE.sub("_", raw)


def _authentik_uri(authentik_path: str) -> str:
    if not authentik_path.startswith("/") or any(character in authentik_path for character in ("\x00", "\r", "\n")):
        raise CaddyProjectionError("Authentik path must be an absolute HTTP path")
    prefix = authentik_path if authentik_path.endswith("/") else authentik_path + "/"
    return prefix + "outpost.goauthentik.io/auth/caddy"


def _group_pattern(groups: tuple[str, ...]) -> str:
    if not groups:
        raise CaddyProjectionError("At least one authorization group is required")
    for group in groups:
        if group != ADMIN_GROUP and not group.startswith("application."):
            raise CaddyProjectionError(f"Invalid service capability name {group!r}")
    alternatives = "|".join(re.escape(group) for group in groups)
    return rf"(^|[|,][[:space:]]*)({alternatives})([[:space:]]*[|,]|$)"


def _render_required_headers(
    lines: list[str],
    *,
    service_id: str,
    route_id: str,
    headers: dict[str, str],
    indent: str,
) -> None:
    for index, (name, value) in enumerate(sorted(headers.items())):
        header = _header_name(name)
        matcher = _matcher(service_id, route_id, f"missing_required_{index}")
        lines.extend(
            [
                f"{indent}@{matcher} {{",
                f"{indent}  not header {header} {_q(value)}",
                f"{indent}}}",
                f"{indent}respond @{matcher} 403",
            ]
        )


def _render_identity_auth(
    lines: list[str],
    *,
    service_id: str,
    route_id: str,
    required_capability: str,
    authentik_upstream: str,
    authentik_path: str,
    indent: str,
) -> None:
    if any(character in authentik_upstream for character in ("\x00", "\r", "\n", "{", "}")):
        raise CaddyProjectionError("Unsafe Authentik upstream")
    for header in IDENTITY_HEADERS:
        lines.append(f"{indent}request_header -{header}")
    lines.extend(
        [
            f"{indent}forward_auth {authentik_upstream} {{",
            f"{indent}  uri {_q(_authentik_uri(authentik_path))}",
            f"{indent}  copy_headers {' '.join(AUTHENTIK_COPY_HEADERS)}",
            f"{indent}}}",
        ]
    )

    missing_identity = _matcher(service_id, route_id, "missing_identity")
    missing_capability = _matcher(service_id, route_id, "missing_capability")
    allowed_groups = _group_pattern((required_capability, ADMIN_GROUP))
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
    if any(character in wake_socket for character in ("\x00", "\r", "\n", "{", "}")):
        raise CaddyProjectionError("Wake socket must be an absolute safe path")
    socket = pathlib.PurePosixPath(wake_socket)
    if not socket.is_absolute() or ".." in socket.parts:
        raise CaddyProjectionError("Wake socket must be an absolute safe path")
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
        header = _header_name(name)
        if header in TRUSTED_IDENTITY_HEADERS:
            raise CaddyProjectionError(f"Static request header may not overwrite trusted identity header {header}")
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
        if any(character in host for character in ("\x00", "\r", "\n", " ", "{", "}")):
            raise CaddyProjectionError(f"Unsafe upstream host {host!r}")
        upstream = f"{host}:{target['port']}"
        lines.append(f"{indent}reverse_proxy {upstream} {{")
        for name, value in sorted(proxy["responseHeaders"].items()):
            lines.append(f"{indent}  header_down {_header_name(name)} {_q(value)}")
        if target_type == "https":
            lines.extend(
                [
                    f"{indent}  transport http {{",
                    f"{indent}    tls",
                    f"{indent}  }}",
                ]
            )
        lines.append(f"{indent}}}")
    elif target_type == "unix-http":
        socket = pathlib.PurePosixPath(target["socket"])
        if not socket.is_absolute() or ".." in socket.parts:
            raise CaddyProjectionError("Unix HTTP target socket must be an absolute safe path")
        lines.append(f"{indent}reverse_proxy unix/{socket} {{")
        for name, value in sorted(proxy["responseHeaders"].items()):
            lines.append(f"{indent}  header_down {_header_name(name)} {_q(value)}")
        lines.append(f"{indent}}}")
    else:  # pragma: no cover - schema validation should make this unreachable
        raise CaddyProjectionError(f"Unsupported route target type {target_type!r}")


def _render_handler(
    lines: list[str],
    *,
    route: dict[str, Any],
    authentik_upstream: str,
    authentik_path: str,
    wake_socket: str | None,
    indent: str,
) -> None:
    service_id = route["service"]
    route_id = route["route"]
    lines.append(f"{indent}route {{")
    inner = indent + "  "
    for header in IDENTITY_HEADERS:
        lines.append(f"{inner}request_header -{header}")

    _render_required_headers(
        lines,
        service_id=service_id,
        route_id=route_id,
        headers=route["proxy"]["requireHeaders"],
        indent=inner,
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
            indent=inner,
        )
    elif route["authMode"] not in {"public", "upstream"}:
        raise CaddyProjectionError(f"Unknown V2 route auth mode {route['authMode']!r}")

    if route["onDemandWake"]:
        _render_wake(
            lines,
            service_id=service_id,
            auth_mode=route["authMode"],
            wake_socket=wake_socket,
            indent=inner,
        )

    _render_proxy(lines, route=route, service_id=service_id, route_id=route_id, indent=inner)
    lines.append(f"{indent}}}")


def _path_patterns(path: str) -> tuple[str, ...]:
    if not path.startswith("/") or any(character in path for character in ("\x00", "\r", "\n", "{", "}")):
        raise CaddyProjectionError(f"Unsafe route path {path!r}")
    if path == "/":
        return ("/*",)
    if path.endswith("/"):
        return (path, path + "*")
    return (path, path + "/*")


def generate_caddyfile(
    effective: dict[str, Any],
    *,
    authentik_upstream: str = "127.0.0.1:9000",
    authentik_path: str = "/identity/",
    lan_host: str = "nas.local",
    wake_socket: str | None = None,
) -> str:
    """Render V2 routes as a Caddyfile fragment imported by the appliance."""
    if not HOSTNAME_RE.fullmatch(lan_host):
        raise CaddyProjectionError(f"Invalid appliance hostname {lan_host!r}")

    services = effective.get("services")
    derived = effective.get("derived")
    if not isinstance(services, dict) or not isinstance(derived, dict) or not isinstance(derived.get("routes"), list):
        raise CaddyProjectionError("Effective V2 document is missing compiled routes")

    routes = [
        route
        for route in derived["routes"]
        if isinstance(route, dict)
        and isinstance(route.get("service"), str)
        and isinstance(services.get(route["service"]), dict)
        and services[route["service"]].get("enabled") is True
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
        else:  # pragma: no cover - schema validation should make this unreachable
            raise CaddyProjectionError(f"Unsupported route exposure type {exposure['type']!r}")

    lines = ["# Generated by Managed Services V2 — do not edit", "", f"({PATH_SNIPPET}) {{"]
    for index, (route, path) in enumerate(path_routes):
        matcher = _matcher(route["service"], route["route"], f"path_{index}")
        patterns = " ".join(_q(item) for item in _path_patterns(path))
        lines.append(f"  @{matcher} path {patterns}")
        lines.append(f"  handle @{matcher} {{")
        _render_handler(
            lines,
            route=route,
            authentik_upstream=authentik_upstream,
            authentik_path=authentik_path,
            wake_socket=wake_socket,
            indent="    ",
        )
        lines.append("  }")
    lines.extend(["}", ""])

    for index, (route, hostname, path) in enumerate(hostname_routes):
        lines.extend([f"https://{hostname} {{", "  tls internal"])
        matcher = _matcher(route["service"], route["route"], f"hostpath_{index}")
        patterns = " ".join(_q(item) for item in _path_patterns(path))
        lines.append(f"  @{matcher} path {patterns}")
        lines.append(f"  handle @{matcher} {{")
        _render_handler(
            lines,
            route=route,
            authentik_upstream=authentik_upstream,
            authentik_path=authentik_path,
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


__all__ = ["CaddyProjectionError", "generate_caddyfile", "validate_caddyfile"]
