#!/usr/bin/env python3
"""Shared naming and endpoint helpers for native V2 socket activation."""

from __future__ import annotations

import pathlib
import hashlib
import re
from typing import Any


class ActivationProjectionError(RuntimeError):
    """Raised when an on-demand route cannot be represented safely."""


_ID = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
ACTIVATION_ROOT = pathlib.PurePosixPath("/run/nas-control/activate")


def _safe_id(value: str, *, field: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ActivationProjectionError(f"invalid {field} identifier {value!r}")
    return value


def _route_name(service_id: str, route_id: str) -> str:
    service = _safe_id(service_id, field="service")
    route = _safe_id(route_id, field="route")
    name = f"{service}-{route}"
    # An underscore cannot occur in IDs. Hash ambiguous/long pairs to keep
    # socket names distinct and within Linux's 108-byte sockaddr_un buffer.
    if "-" in service or "-" in route or len(str(ACTIVATION_ROOT / (name + ".sock")).encode()) > 107:
        return "h_" + hashlib.sha256(f"{service}\0{route}".encode()).hexdigest()
    return name


def unit_base(service_id: str, route_id: str) -> str:
    return "nas-v2-activate-" + _route_name(service_id, route_id)


def socket_unit(service_id: str, route_id: str) -> str:
    return unit_base(service_id, route_id) + ".socket"


def proxy_unit(service_id: str, route_id: str) -> str:
    return unit_base(service_id, route_id) + ".service"


def socket_path(service_id: str, route_id: str) -> pathlib.PurePosixPath:
    return ACTIVATION_ROOT / (_route_name(service_id, route_id) + ".sock")


def backend_target(route: dict[str, Any]) -> str:
    target = route.get("target")
    if not isinstance(target, dict):
        raise ActivationProjectionError("compiled on-demand route is missing its target")
    target_type = target.get("type")
    if target_type in {"http", "https"}:
        host = target.get("host")
        port = target.get("port")
        if not isinstance(host, str) or any(ch in host for ch in "\x00\r\n {}"):
            raise ActivationProjectionError(f"unsafe on-demand upstream host {host!r}")
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise ActivationProjectionError(f"invalid on-demand upstream port {port!r}")
        return f"{host}:{port}"
    if target_type == "unix-http":
        raw = target.get("socket")
        if not isinstance(raw, str) or any(ch in raw for ch in "\x00\r\n"):
            raise ActivationProjectionError("invalid on-demand Unix upstream socket")
        path = pathlib.PurePosixPath(raw)
        if not path.is_absolute() or ".." in path.parts:
            raise ActivationProjectionError("on-demand Unix upstream socket must be an absolute safe path")
        return str(path)
    raise ActivationProjectionError(f"unsupported on-demand route target type {target_type!r}")


__all__ = [
    "ACTIVATION_ROOT",
    "ActivationProjectionError",
    "backend_target",
    "proxy_unit",
    "socket_path",
    "socket_unit",
    "unit_base",
]
