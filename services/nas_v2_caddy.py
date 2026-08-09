#!/usr/bin/env python3
"""Direct Caddy projection for the canonical Managed Services V2 route schema.

V2 only generates configuration. Authentik owns capability assignments and
Caddy is the request-time enforcement point. The optional Unix-socket wake
bridge is called only after Caddy has authorized the request.
"""

from __future__ import annotations

import hashlib
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
from typing import Any

from nas_managed_resources import capability_group_name as legacy_group_name
from nas_managed_resources import validate_capability_reference as validate_legacy_capability
from nas_v2_authorization import capability_group_name, route_capability, validate_capability

DEFAULT_OUTPUT = pathlib.Path("/run/nas-control/caddy-managed.conf")
GATE_SOCKET = os.environ.get("NAS_ON_DEMAND_GATE_SOCKET", "/run/nas-control/on-demand-gate.sock")
PATH_SNIPPET = "nas_managed_paths"
HOST_RE = re.compile(r"^(?:[A-Za-z0-9-]{1,63}\.)*[A-Za-z0-9-]{1,63}$")


class V2CaddyError(RuntimeError):
    pass


def _route_key(service_id: str, route_id: str) -> str:
    return f"{service_id}:{route_id}"


def _matcher_id(service_id: str, route_id: str, path: str) -> str:
    digest = hashlib.blake2s(
        f"{service_id}\0{route_id}\0{path}".encode("utf-8"), digest_size=6, person=b"nas-v2-caddy"
    ).hexdigest()
    return f"v2_{service_id}_{route_id}_{digest}".replace("-", "_")


def _group_for_capability(service_id: str, route: dict[str, Any]) -> str:
    auth = route.get("auth") or {}
    explicit = auth.get("capability") if isinstance(auth, dict) else None
    if explicit is None:
        required = route_capability(service_id, route)
        if required is None:
            raise V2CaddyError(f"Service {service_id}: identity route has no capability")
        return capability_group_name(required)
    try:
        return capability_group_name(validate_capability(explicit, service_id=service_id))
    except Exception:
        try:
            legacy = validate_legacy_capability(explicit)
        except Exception as exc:
            raise V2CaddyError(f"Service {service_id}: invalid route capability {explicit!r}") from exc
        if not legacy.startswith(f"application.{service_id}."):
            raise V2CaddyError(f"Service {service_id}: route capability belongs to another service")
        return legacy_group_name(legacy)


def _render_gate(lines: list[str], service_id: str, route_id: str, indent: str) -> None:
    lines.extend(
        [
            f"{indent}forward_auth unix/{GATE_SOCKET} {{",
            f"{indent}  uri /authorize?scope=service:{_route_key(service_id, route_id)}",
            f"{indent}}}",
        ]
    )


def _render_auth(
    lines: list[str],
    service_id: str,
    route_id: str,
    route: dict[str, Any],
    indent: str,
    matcher_suffix: str,
) -> None:
    auth = route["auth"]
    mode = auth["mode"]
    if mode == "identity":
        required_group = _group_for_capability(service_id, route)
        for header in (
            "Remote-User",
            "Remote-Groups",
            "Remote-Name",
            "Remote-Email",
            "Remote-UID",
            "X-Authentik-Username",
            "X-Authentik-Groups",
            "X-Authentik-Name",
            "X-Authentik-Email",
            "X-Authentik-Uid",
        ):
            lines.append(f"{indent}request_header -{header}")
        denied = f"v2_denied_{matcher_suffix}"
        lines.extend(
            [
                f"{indent}forward_auth 127.0.0.1:9000 {{",
                f"{indent}  uri /outpost.goauthentik.io/auth/caddy",
                f"{indent}  copy_headers X-Authentik-Username X-Authentik-Groups X-Authentik-Name X-Authentik-Email X-Authentik-Uid",
                f"{indent}}}",
                f"{indent}@{denied} not header X-Authentik-Groups *{required_group}*",
                f"{indent}respond @{denied} 403",
                f"{indent}request_header Remote-User {{http.request.header.X-Authentik-Username}}",
                f"{indent}request_header Remote-Groups {{http.request.header.X-Authentik-Groups}}",
                f"{indent}request_header Remote-Name {{http.request.header.X-Authentik-Name}}",
                f"{indent}request_header Remote-Email {{http.request.header.X-Authentik-Email}}",
                f"{indent}request_header Remote-UID {{http.request.header.X-Authentik-Uid}}",
            ]
        )
    elif mode == "secret":
        raise V2CaddyError(
            f"Service {service_id} route {route_id}: V2 secret authorization was removed; use identity or upstream auth"
        )
    elif mode not in {"public", "upstream"}:
        raise V2CaddyError(f"Service {service_id} route {route_id}: unsupported auth mode {mode!r}")

    # This is wake-only plumbing. Caddy has already completed any required
    # authorization before the request is allowed to reach the Unix socket.
    _render_gate(lines, service_id, route_id, indent)


def _render_proxy(lines: list[str], route: dict[str, Any], indent: str) -> None:
    proxy = route.get("proxy", {})
    strip = proxy.get("stripPrefix")
    if isinstance(strip, str):
        lines.append(f"{indent}uri strip_prefix {strip}")
        lines.append(f"{indent}request_header X-Forwarded-Prefix {strip}")
    for header in proxy.get("removeRequestHeaders", []):
        lines.append(f"{indent}request_header -{header}")
    for header, value in sorted(proxy.get("requestHeaders", {}).items()):
        lines.append(f"{indent}request_header {header} {value}")

    target = route["target"]
    typ = target["type"]
    if typ == "unix-http":
        lines.append(f"{indent}reverse_proxy unix/{target['path']}")
    else:
        host = target.get("host", "127.0.0.1")
        port = int(target["port"])
        if any(char in str(host) for char in ("\r", "\n", "{", "}")):
            raise V2CaddyError("Route target host contains unsafe characters")
        upstream = f"{host}:{port}"
        if typ == "https":
            lines.extend(
                [
                    f"{indent}reverse_proxy {upstream} {{",
                    f"{indent}  transport http {{",
                    f"{indent}    tls",
                    f"{indent}    tls_insecure_skip_verify",
                    f"{indent}  }}",
                    f"{indent}}}",
                ]
            )
        elif typ == "http":
            lines.append(f"{indent}reverse_proxy {upstream}")
        else:
            raise V2CaddyError(f"Unsupported Caddy route target {typ!r}")


def _render_handler(
    lines: list[str],
    service_id: str,
    route_id: str,
    route: dict[str, Any],
    indent: str,
    matcher_suffix: str,
) -> None:
    _render_auth(lines, service_id, route_id, route, indent, matcher_suffix)
    _render_proxy(lines, route, indent)


def generate_caddyfile(effective: dict[str, Any]) -> str:
    path_routes: list[tuple[int, str, str, dict[str, Any], str]] = []
    host_routes: list[tuple[int, str, str, dict[str, Any], str, str]] = []
    seen_paths: set[str] = set()
    seen_hosts: set[tuple[str, str]] = set()

    services = effective.get("services", {})
    if not isinstance(services, dict):
        raise V2CaddyError("effective services must be an object")
    for service_id, service in services.items():
        if not isinstance(service, dict) or not service.get("enabled"):
            continue
        routes = service.get("routes", {})
        if not isinstance(routes, dict):
            raise V2CaddyError(f"Service {service_id}: routes must be an object")
        for route_id, route in routes.items():
            exposure = route["exposure"]
            priority = int(route.get("priority", 0))
            if exposure["type"] == "path":
                for path in exposure["paths"]:
                    if path in seen_paths:
                        raise V2CaddyError(f"Duplicate managed path exposure {path!r}")
                    seen_paths.add(path)
                    path_routes.append((priority, service_id, route_id, route, path))
            elif exposure["type"] == "hostname":
                hostname = exposure["hostname"]
                path = exposure.get("path", "/")
                if not isinstance(hostname, str) or HOST_RE.fullmatch(hostname) is None:
                    raise V2CaddyError(f"Invalid managed hostname {hostname!r}")
                key = (hostname.lower(), path)
                if key in seen_hosts:
                    raise V2CaddyError(f"Duplicate managed hostname exposure {hostname!r}{path}")
                seen_hosts.add(key)
                host_routes.append((priority, service_id, route_id, route, hostname, path))
            else:
                raise V2CaddyError(f"Service {service_id} route {route_id}: invalid exposure")

    path_routes.sort(key=lambda item: (-item[0], item[4], item[1], item[2]))
    host_routes.sort(key=lambda item: (-item[0], item[4], item[5], item[1], item[2]))
    lines = ["# Generated by nas-v2-runtime; do not edit.", "", f"({PATH_SNIPPET}) {{"]
    for _, service_id, route_id, route, path in path_routes:
        matcher = _matcher_id(service_id, route_id, path)
        lines.append(f"  @{matcher} path {path} {path}*")
        lines.append(f"  handle @{matcher} {{")
        _render_handler(lines, service_id, route_id, route, "    ", matcher)
        lines.append("  }")
    lines.extend(["}", ""])

    for _, service_id, route_id, route, hostname, path in host_routes:
        matcher = _matcher_id(service_id, route_id, f"{hostname}{path}")
        lines.append(f"https://{hostname} {{")
        lines.append("  tls internal")
        if path != "/":
            lines.append(f"  handle_path {path}* {{")
            _render_handler(lines, service_id, route_id, route, "    ", matcher)
            lines.append("  }")
        else:
            _render_handler(lines, service_id, route_id, route, "  ", matcher)
        lines.extend(["}", ""])
    return "\n".join(lines)


def write_caddyfile(
    effective: dict[str, Any],
    path: pathlib.Path = DEFAULT_OUTPUT,
    *,
    validate: bool = True,
    reload: bool = True,
) -> str:
    text = generate_caddyfile(effective)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = pathlib.Path(name)
    previous = path.read_text(encoding="utf-8") if path.exists() else None
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        caddy = shutil.which("caddy")
        if validate and caddy:
            result = subprocess.run(
                [caddy, "adapt", "--adapter", "caddyfile", "--config", str(temporary)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                raise V2CaddyError(f"Caddy validation failed: {result.stderr.strip()}")
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
        if reload and shutil.which("systemctl"):
            result = subprocess.run(["systemctl", "reload", "caddy"], capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                if previous is not None:
                    path.write_text(previous, encoding="utf-8")
                    subprocess.run(["systemctl", "reload", "caddy"], capture_output=True, timeout=10)
                raise V2CaddyError(f"Caddy reload failed: {result.stderr.strip()}")
    finally:
        temporary.unlink(missing_ok=True)
    return text
