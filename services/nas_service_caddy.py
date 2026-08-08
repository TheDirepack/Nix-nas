#!/usr/bin/env python3
"""Caddy adapter for managed-services — generates Caddyfile fragments from effective registry."""

from __future__ import annotations

import json
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
            if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
                raise CaddyError(f"Invalid port {val!r}")
        except (ValueError, TypeError):
            raise CaddyError(f"Invalid port {val!r}")
    elif typ == "path":
        if not isinstance(val, str) or not val.startswith("/"):
            raise CaddyError(f"Invalid path {val!r}: must start with '/'")
        reserved_prefixes = ("/api", "/outpost.goauthentik.io", "/identity", "/console", "/shares", "/share", "/dav", "/vault", "/ai", "/syncthing", "/metrics", "/victoriametrics", "/alerts", "/ups", "/notifications", "/settings")
        if any(val == rp or val.startswith(rp + "/") for rp in reserved_prefixes):
            raise CaddyError(f"Path {val!r} conflicts with reserved NAS path")



def _collect_routes(effective: dict[str, Any]) -> list[dict[str, Any]]:
    routes: list[dict[str, Any]] = []
    for key, endpoint in effective.get("endpoints", {}).items():
        if endpoint.get("transport") not in ("http", "https", None):
            continue
        if "publicPath" in endpoint:
            continue
        exposure = endpoint.get("exposure")
        if exposure is None or not isinstance(exposure, dict):
            raise CaddyError(f"Endpoint {key!r}: exposure is mandatory")
        _validate_exposure(exposure)
        if exposure.get("type") == "none":
            raise CaddyError(f"Endpoint {key!r}: exposure type 'none' must not produce a route")
        auth = endpoint.get("auth")
        if auth is None or not isinstance(auth, dict):
            raise CaddyError(f"Endpoint {key!r}: auth is mandatory for HTTP endpoints")
        mode = auth.get("mode")
        if mode not in ("public", "forward-auth", "oidc"):
            raise CaddyError(f"Endpoint {key!r}: unknown auth mode {mode!r} — failing closed")
        target_port = endpoint.get("targetPort")
        if target_port is None:
            raise CaddyError(f"Endpoint {key!r}: targetPort is mandatory")
        msvc._validate_port(target_port)
        route_id = f"nas-managed-{key.replace(':', '-')}"
        typ = exposure.get("type")
        value = exposure.get("value", "")
        prefix = exposure.get("prefix", True)
        if not isinstance(prefix, bool):
            prefix = True
        host = None
        path = None
        port: int | None = None
        if typ in ("hostname", "dns"):
            host = value
        elif typ == "path":
            path = value
        elif typ == "port":
            port = int(value) if isinstance(value, str) else int(value)
        route: dict[str, Any] = {
            "id": route_id,
            "key": key,
            "host": host,
            "path": path,
            "path_prefix": prefix,
            "port": port,
            "targetPort": int(target_port),
            "auth": auth,
            "exposure": exposure,
        }
        routes.append(route)
    routes.sort(key=lambda r: r["id"])
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
    routes = _collect_routes(effective)
    return {"routes": routes}


def generate_caddyfile(effective: dict[str, Any] | None = None) -> str:
    if effective is None:
        effective = msvc.effective_registry()
    routes = _collect_routes(effective)
    if not routes:
        return "# No managed-service HTTP endpoints\n"
    lines: list[str] = ["# Generated by nas-managed-service — do not edit", ""]
    for route in routes:
        rid = route["id"]
        host = route["host"]
        path = route["path"]
        prefix = route["path_prefix"]
        port = route["port"]
        target_port = route["targetPort"]
        auth = route["auth"]
        transport = effective.get("endpoints", {}).get(route["key"], {}).get("transport", "http")
        if port is not None:
            lines.append(f"https://nas.local:{port} {{")
            lines.append(f"  tls internal")
            lines.append(f"  handle {{")
        elif host:
            lines.append(f"@nas_{rid} host {host}")
            lines.append(f"handle @nas_{rid} {{")
        elif path:
            if path == "/":
                matcher = "@nas_" + rid
                if prefix:
                    lines.append(f"@{matcher} path {path} {path}*")
                else:
                    lines.append(f"@{matcher} path {path}")
                lines.append(f"handle @{matcher} {{")
            else:
                matcher = "nas_" + rid
                if prefix:
                    lines.append(f"@{matcher} path {path} {path}*")
                else:
                    lines.append(f"@{matcher} path {path}")
                lines.append(f"handle @{matcher} {{")
        else:
            raise CaddyError(f"Route {rid} has no matcher")
        if auth.get("mode") in ("forward-auth", "oidc"):
            lines.append(f"  request_header -Remote-User")
            lines.append(f"  request_header -Remote-Groups")
            lines.append(f"  request_header -Remote-Name")
            lines.append(f"  request_header -Remote-Email")
            lines.append(f"  request_header -Remote-UID")
            lines.append(f"  request_header -X-Authentik-Username")
            lines.append(f"  request_header -X-Authentik-Groups")
            lines.append(f"  request_header -X-Authentik-Name")
            lines.append(f"  request_header -X-Authentik-Email")
            lines.append(f"  request_header -X-Authentik-Uid")
            lines.append(f"  forward_auth 127.0.0.1:9000 {{")
            lines.append(f"    uri /outpost.goauthentik.io/auth/caddy")
            lines.append(f"    copy_headers X-Authentik-Username X-Authentik-Groups X-Authentik-Name X-Authentik-Email X-Authentik-Uid")
            lines.append(f"  }}")
            lines.append(f"  @missingAuthentikIdentity not header X-Authentik-Username *")
            lines.append(f"  respond @missingAuthentikIdentity 403")
            lines.append(f"  request_header Remote-User {{http.request.header.X-Authentik-Username}}")
            lines.append(f"  request_header Remote-Groups {{http.request.header.X-Authentik-Groups}}")
            lines.append(f"  request_header Remote-Name {{http.request.header.X-Authentik-Name}}")
            lines.append(f"  request_header Remote-Email {{http.request.header.X-Authentik-Email}}")
            lines.append(f"  request_header Remote-UID {{http.request.header.X-Authentik-Uid}}")
            scope = f"service:{route['key']}"
            lines.append(f"  forward_auth unix/{ON_DEMAND_GATE} {{")
            lines.append(f"    uri /authorize?scope={scope}")
            lines.append(f"    header_up Remote-User {{http.request.header.Remote-User}}")
            lines.append(f"    header_up Remote-Groups {{http.request.header.Remote-Groups}}")
            lines.append(f"    header_up Remote-Name {{http.request.header.Remote-Name}}")
            lines.append(f"    header_up Remote-Email {{http.request.header.Remote-Email}}")
            lines.append(f"    header_up Remote-UID {{http.request.header.Remote-UID}}")
            lines.append(f"  }}")
        if path and prefix:
            lines.append(f"  uri strip_prefix {path}")
            lines.append(f"  header_up X-Forwarded-Prefix {path}")
        if transport == "https":
            lines.append(f"  reverse_proxy 127.0.0.1:{target_port} {{")
            lines.append(f"    transport http {{")
            lines.append(f"      tls")
            lines.append(f"      tls_insecure_skip_verify")
            lines.append(f"    }}")
            lines.append(f"  }}")
        else:
            lines.append(f"  reverse_proxy 127.0.0.1:{target_port}")
        lines.append("}")
        if port is not None:
            lines.append("}")
        lines.append("")
    return "\n".join(lines)


def write_caddy_fragment(path: pathlib.Path | None = None, effective: dict[str, Any] | None = None) -> dict[str, Any]:
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
            import os as _os

            _os.fsync(handle.fileno())
        caddy_bin = shutil.which("caddy")
        if caddy_bin and os.environ.get("NAS_SKIP_CADDY_VALIDATE") != "1":
            vfd, vtmp = tempfile.mkstemp(prefix="caddy-validate-", suffix=".caddyfile")
            validate_tmp = pathlib.Path(vtmp)
            try:
                os.close(vfd)
                validate_tmp.write_text(caddyfile_content, encoding="utf-8")
                fmt_result = subprocess.run([caddy_bin, "fmt", "--overwrite", str(validate_tmp)], capture_output=True, text=True, timeout=10)
                if fmt_result.returncode != 0:
                    raise CaddyError(f"Caddy fmt failed: {fmt_result.stderr.strip()}")
                adapt_result = subprocess.run([caddy_bin, "adapt", "--adapter", "caddyfile", "--config", str(validate_tmp)], capture_output=True, text=True, timeout=10)
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
        if os.environ.get("NAS_SKIP_CADDY_RELOAD") != "1" and shutil.which("systemctl"):
            try:
                reload_result = subprocess.run(["systemctl", "reload", "caddy"], capture_output=True, text=True, timeout=10)
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
