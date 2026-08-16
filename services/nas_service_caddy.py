#!/usr/bin/env python3
"""Caddy adapter for managed services.

The generated file is imported at Caddy's top level. Hostname and dedicated
port exposures become complete site blocks. Path exposures are emitted inside
a named snippet which the appliance's existing ``nas.local`` virtual host
imports, avoiding duplicate site definitions.
"""

from __future__ import annotations

import os
import pathlib
import re
import shutil
import subprocess
import tempfile
from typing import Any

import nas_managed_service as msvc

HOSTNAME_RE = re.compile(r"^(?:[a-z0-9-]{1,63}\.)*[a-z0-9-]{1,63}$", re.IGNORECASE)
ON_DEMAND_GATE = os.environ.get("NAS_ON_DEMAND_GATE_SOCKET", "/run/nas-control/on-demand-gate.sock")
AUTHENTIK_OUTPOST_PORT = os.environ.get("NAS_AUTHENTIK_OUTPOST_PORT", "9000")
PATH_SNIPPET = "nas_managed_paths"


class CaddyError(ValueError, RuntimeError):
    pass


def _validate_exposure(exposure: dict[str, Any]) -> None:
    typ = exposure.get("type")
    if typ is None:
        raise CaddyError("exposure.type is mandatory")
    if typ not in ("path", "hostname", "dns", "port", "none"):
        raise CaddyError(f"Invalid exposure type {typ!r}")
    if typ == "none":
        raise CaddyError("exposure type 'none' must not produce a route")
    val = exposure.get("value", "")
    if val is None or val == "":
        raise CaddyError(f"exposure value is required for type {typ!r}")
    if isinstance(val, str) and any(c in val for c in ("\r", "\n", "{", "}")):
        raise CaddyError(f"Invalid exposure value {val!r}: contains invalid characters")
    if typ in ("hostname", "dns"):
        if not isinstance(val, str) or not HOSTNAME_RE.fullmatch(val):
            raise CaddyError(f"Invalid hostname {val!r}")
        lan_host = os.environ.get("NAS_LAN_HOST", "nas.local")
        if val == lan_host or val.endswith(f".{lan_host}"):
            raise CaddyError(f"Hostname {val!r} collides with NAS host")
    elif typ == "port":
        try:
            port = int(val) if isinstance(val, str) else val
        except (ValueError, TypeError) as exc:
            raise CaddyError(f"Invalid port {val!r}") from exc
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise CaddyError(f"Invalid port {val!r}")
    elif typ == "path":
        if not isinstance(val, str) or not val.startswith("/"):
            raise CaddyError(f"Invalid path {val!r}: must start with '/'")
        reserved_prefixes = (
            "/api",
            "/outpost.goauthentik.io",
            "/identity",
            "/console",
            "/shares",
            "/share",
            "/dav",
            "/vault",
            "/ai",
            "/syncthing",
            "/metrics",
            "/victoriametrics",
            "/alerts",
            "/ups",
            "/notifications",
            "/settings",
        )
        if any(val == prefix or val.startswith(prefix + "/") for prefix in reserved_prefixes):
            raise CaddyError(f"Path {val!r} conflicts with reserved NAS path")


def _collect_routes(effective: dict[str, Any]) -> list[dict[str, Any]]:
    routes: list[dict[str, Any]] = []
    for key, endpoint in effective.get("endpoints", {}).items():
        # Managed-service projections explicitly mark disabled services as
        # unavailable. Do not leave an old proxy route reachable merely because
        # the endpoint metadata still exists in the effective registry.
        if endpoint.get("available") is False:
            continue
        if endpoint.get("transport") not in ("http", "https", None):
            continue
        if "publicPath" in endpoint:
            continue
        exposure = endpoint.get("exposure")
        if not isinstance(exposure, dict):
            raise CaddyError(f"Endpoint {key!r}: exposure is mandatory")
        _validate_exposure(exposure)
        auth = endpoint.get("auth")
        if not isinstance(auth, dict):
            raise CaddyError(f"Endpoint {key!r}: auth is mandatory for HTTP endpoints")
        mode = auth.get("mode")
        if mode not in ("public", "forward-auth", "oidc"):
            raise CaddyError(f"Endpoint {key!r}: unknown auth mode {mode!r} — failing closed")
        target_port = endpoint.get("targetPort")
        if target_port is None:
            raise CaddyError(f"Endpoint {key!r}: targetPort is mandatory")
        msvc._validate_port(target_port)
        if isinstance(target_port, bool) or not isinstance(target_port, int):
            raise CaddyError(f"Endpoint {key!r}: targetPort must be an integer")

        typ = exposure["type"]
        value = exposure.get("value")
        route_port: int | None = None
        if typ == "port":
            if isinstance(value, bool) or not isinstance(value, (int, str)) or not str(value).isdigit():
                raise CaddyError(f"Endpoint {key!r}: exposure port is invalid")
            route_port = int(value)
        prefix = exposure.get("prefix", True)
        if not isinstance(prefix, bool):
            prefix = True
        route = {
            "id": f"nas-managed-{key.replace(':', '-')}",
            "key": key,
            "host": value if typ in ("hostname", "dns") else None,
            "path": value if typ == "path" else None,
            "path_prefix": prefix,
            "port": route_port,
            "targetPort": int(target_port),
            "auth": auth,
            "exposure": exposure,
            "transport": endpoint.get("transport", "http") or "http",
        }
        routes.append(route)

    routes.sort(key=lambda route: route["id"])
    seen: set[tuple[Any, ...]] = set()
    for route in routes:
        dedup_key = (route["host"], route["path"], route["port"])
        if dedup_key in seen:
            raise CaddyError(f"Duplicate exposure {dedup_key} for route {route['id']}")
        seen.add(dedup_key)
        if route["host"] is None and route["path"] is None and route["port"] is None:
            raise CaddyError(f"Route {route['id']} has no matcher — refusing catch-all")
    return routes


def generate_caddy_fragment(effective: dict[str, Any] | None = None) -> dict[str, Any]:
    if effective is None:
        effective = msvc.effective_registry()
    return {"routes": _collect_routes(effective)}


def _render_auth(lines: list[str], route: dict[str, Any], indent: str) -> None:
    auth = route["auth"]
    if auth.get("mode") not in ("forward-auth", "oidc"):
        return
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
    lines.extend(
        [
            f"{indent}forward_auth 127.0.0.1:{AUTHENTIK_OUTPOST_PORT} {{",
            f"{indent}  uri /outpost.goauthentik.io/auth/caddy",
            f"{indent}  copy_headers X-Authentik-Username X-Authentik-Groups X-Authentik-Name X-Authentik-Email X-Authentik-Uid",
            f"{indent}}}",
            f"{indent}@missingAuthentikIdentity not header X-Authentik-Username *",
            f"{indent}respond @missingAuthentikIdentity 403",
            f"{indent}request_header Remote-User {{http.request.header.X-Authentik-Username}}",
            f"{indent}request_header Remote-Groups {{http.request.header.X-Authentik-Groups}}",
            f"{indent}request_header Remote-Name {{http.request.header.X-Authentik-Name}}",
            f"{indent}request_header Remote-Email {{http.request.header.X-Authentik-Email}}",
            f"{indent}request_header Remote-UID {{http.request.header.X-Authentik-Uid}}",
            f"{indent}forward_auth unix/{ON_DEMAND_GATE} {{",
            f"{indent}  uri /authorize?scope=service:{route['key']}",
            f"{indent}  header_up Remote-User {{http.request.header.X-Authentik-Username}}",
            f"{indent}  header_up Remote-Groups {{http.request.header.X-Authentik-Groups}}",
            f"{indent}  header_up Remote-Name {{http.request.header.X-Authentik-Name}}",
            f"{indent}  header_up Remote-Email {{http.request.header.X-Authentik-Email}}",
            f"{indent}  header_up Remote-UID {{http.request.header.X-Authentik-Uid}}",
            f"{indent}}}",
        ]
    )


def _render_proxy(lines: list[str], route: dict[str, Any], indent: str) -> None:
    path = route["path"]
    if path and route["path_prefix"]:
        lines.append(f"{indent}uri strip_prefix {path}")
        lines.append(f"{indent}request_header X-Forwarded-Prefix {path}")
    target = route["targetPort"]
    if route["transport"] == "https":
        lines.extend(
            [
                f"{indent}reverse_proxy 127.0.0.1:{target} {{",
                f"{indent}  transport http {{",
                f"{indent}    tls",
                f"{indent}    tls_insecure_skip_verify",
                f"{indent}  }}",
                f"{indent}}}",
            ]
        )
    else:
        lines.append(f"{indent}reverse_proxy 127.0.0.1:{target}")


def _render_handler(lines: list[str], route: dict[str, Any], indent: str) -> None:
    _render_auth(lines, route, indent)
    _render_proxy(lines, route, indent)


def generate_caddyfile(effective: dict[str, Any] | None = None) -> str:
    if effective is None:
        effective = msvc.effective_registry()
    routes = _collect_routes(effective)
    path_routes = [route for route in routes if route["path"] is not None]
    site_routes = [route for route in routes if route["path"] is None]
    lines: list[str] = ["# Generated by nas-managed-service — do not edit", ""]

    # This snippet is imported by the existing nas.local virtual host.
    lines.append(f"({PATH_SNIPPET}) {{")
    for route in path_routes:
        matcher = f"nas_{route['id']}"
        path = route["path"]
        if route["path_prefix"]:
            lines.append(f"  @{matcher} path {path} {path}*")
        else:
            lines.append(f"  @{matcher} path {path}")
        lines.append(f"  handle @{matcher} {{")
        _render_handler(lines, route, "    ")
        lines.append("  }")
    lines.append("}")
    lines.append("")

    lan_host = os.environ.get("NAS_LAN_HOST", "nas.local")
    for route in site_routes:
        site = f"https://{route['host']}" if route["host"] else f"https://{lan_host}:{route['port']}"
        lines.append(f"{site} {{")
        lines.append("  tls internal")
        _render_handler(lines, route, "  ")
        lines.append("}")
        lines.append("")
    return "\n".join(lines)


def write_caddy_fragment(
    path: pathlib.Path | None = None,
    effective: dict[str, Any] | None = None,
    *,
    reload_caddy: bool = True,
) -> dict[str, Any]:
    if path is None:
        path = pathlib.Path("/run/nas-control/caddy-managed.conf")
    if effective is None:
        effective = msvc.effective_registry()
    fragment = generate_caddy_fragment(effective)
    caddyfile_content = generate_caddyfile(effective)
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".caddy-managed.", dir=parent)
    tmp_path = pathlib.Path(tmp)
    previous_content: str | None = None
    try:
        if path.exists():
            try:
                previous_content = path.read_text(encoding="utf-8")
            except OSError:
                previous_content = None
        with open(fd, "w", encoding="utf-8") as handle:
            handle.write(caddyfile_content)
            handle.flush()
            os.fsync(handle.fileno())
        caddy_bin = shutil.which("caddy")
        if caddy_bin and os.environ.get("NAS_SKIP_CADDY_VALIDATE") != "1":
            vfd, vtmp = tempfile.mkstemp(prefix="caddy-validate-", suffix=".caddyfile")
            validate_tmp = pathlib.Path(vtmp)
            try:
                os.close(vfd)
                validate_tmp.write_text(caddyfile_content, encoding="utf-8")
                fmt_result = subprocess.run(
                    [caddy_bin, "fmt", "--overwrite", str(validate_tmp)],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if fmt_result.returncode != 0:
                    raise CaddyError(f"Caddy fmt failed: {fmt_result.stderr.strip()}")
                adapt_result = subprocess.run(
                    [caddy_bin, "adapt", "--adapter", "caddyfile", "--config", str(validate_tmp)],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if adapt_result.returncode != 0:
                    raise CaddyError(f"Caddy adapt failed: {adapt_result.stderr.strip()}")
            finally:
                validate_tmp.unlink(missing_ok=True)
        tmp_path.chmod(0o644)
        tmp_path.replace(path)
        dir_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        if reload_caddy and os.environ.get("NAS_SKIP_CADDY_RELOAD") != "1" and shutil.which("systemctl"):
            try:
                reload_result = subprocess.run(
                    ["systemctl", "reload", "caddy"], capture_output=True, text=True, timeout=10
                )
                if reload_result.returncode != 0:
                    if previous_content is not None:
                        path.write_text(previous_content, encoding="utf-8")
                        subprocess.run(["systemctl", "reload", "caddy"], capture_output=True, timeout=10)
                    raise CaddyError(f"Caddy reload failed: {reload_result.stderr.strip()}")
            except OSError as exc:
                if previous_content is not None:
                    try:
                        path.write_text(previous_content, encoding="utf-8")
                    except OSError:
                        pass
                raise CaddyError(f"Caddy reload OSError: {exc}") from exc
    except CaddyError:
        tmp_path.unlink(missing_ok=True)
        raise
    except Exception as exc:
        tmp_path.unlink(missing_ok=True)
        raise CaddyError(str(exc)) from exc
    finally:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
    return fragment
