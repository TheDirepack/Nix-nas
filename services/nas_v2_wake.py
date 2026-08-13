#!/usr/bin/env python3
"""Handle one trusted local Caddy wake request and exit.

Authorization is deliberately outside this helper. The Unix socket is the
trust boundary: Caddy connects only after it has authenticated and authorized
the request. This helper accepts only a service ID, maps it through compiled V2
effective state, acquires native systemd leases for the workload and its
on-demand dependencies, resets their native idle timers, responds, and exits.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import socket
import subprocess
import sys
from typing import Any
from urllib.parse import parse_qs, urlsplit


class WakeError(RuntimeError):
    """Raised when a wake request cannot be safely fulfilled."""


SERVICE_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
UNIT_RE = re.compile(r"^[A-Za-z0-9_.@:-]+\.(?:service|target)$")
MAX_REQUEST_BYTES = 16 * 1024
SOCKET_TIMEOUT_SECONDS = 5.0
SYSTEMCTL_TIMEOUT_SECONDS = 120.0


def _lease_unit(service_id: str) -> str:
    return f"nas-v2-lease-{service_id}.target"


def _idle_timer(service_id: str) -> str:
    return f"nas-v2-idle-{service_id}.timer"


def _load_effective(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WakeError(f"unable to read compiled effective state: {exc}") from exc
    if not isinstance(value, dict) or value.get("schemaVersion") != 3:
        raise WakeError("compiled effective state is invalid")
    return value


def parse_request(data: bytes) -> str:
    """Parse the bounded HTTP request and return its sole service identity."""
    if len(data) > MAX_REQUEST_BYTES:
        raise WakeError("request is too large")
    header_end = data.find(b"\r\n\r\n")
    if header_end < 0:
        raise WakeError("incomplete HTTP request")
    head = data[:header_end]
    lines = head.split(b"\r\n")
    if not lines:
        raise WakeError("missing HTTP request line")
    try:
        request_line = lines[0].decode("ascii")
    except UnicodeDecodeError as exc:
        raise WakeError("HTTP request line must be ASCII") from exc
    parts = request_line.split(" ")
    if len(parts) != 3 or parts[0] != "GET" or parts[2] not in {"HTTP/1.0", "HTTP/1.1"}:
        raise WakeError("wake endpoint requires an HTTP GET request")

    target = urlsplit(parts[1])
    if target.scheme or target.netloc or target.fragment or target.path != "/wake":
        raise WakeError("invalid wake endpoint")
    try:
        query = parse_qs(target.query, keep_blank_values=True, strict_parsing=True, max_num_fields=2)
    except ValueError as exc:
        raise WakeError("invalid wake query") from exc
    if set(query) != {"service"} or len(query["service"]) != 1:
        raise WakeError("wake endpoint accepts only one service parameter")
    service_id = query["service"][0]
    if not SERVICE_ID_RE.fullmatch(service_id):
        raise WakeError("invalid service identity")
    return service_id


def _service_map(effective: dict[str, Any]) -> dict[str, Any]:
    services = effective.get("services")
    derived = effective.get("derived")
    runtime = derived.get("runtime") if isinstance(derived, dict) else None
    if not isinstance(services, dict) or not isinstance(runtime, dict):
        raise WakeError("compiled effective state is missing service metadata")
    return services


def _validate_runtime_owner(effective: dict[str, Any], service_id: str) -> None:
    derived = effective.get("derived")
    runtime = derived.get("runtime") if isinstance(derived, dict) else None
    entry = runtime.get(service_id) if isinstance(runtime, dict) else None
    owner = entry.get("ownerUnit") if isinstance(entry, dict) else None
    if not isinstance(owner, str) or not UNIT_RE.fullmatch(owner):
        raise WakeError(f"compiled runtime owner unit for {service_id!r} is invalid")


def _is_on_demand(service: dict[str, Any]) -> bool:
    workload = service.get("workload")
    return (
        service.get("enabled") is True
        and service.get("managed") is True
        and isinstance(workload, dict)
        and workload.get("kind") == "daemon"
        and workload.get("activation") == "on-demand"
    )


def _wake_order(effective: dict[str, Any], service_id: str) -> list[str]:
    services = _service_map(effective)
    requested = services.get(service_id)
    if not isinstance(requested, dict):
        raise KeyError(service_id)
    if requested.get("enabled") is not True:
        raise WakeError("service is disabled")
    if requested.get("managed") is not True:
        raise WakeError("service lifecycle is not managed by V2")
    workload = requested.get("workload")
    if not isinstance(workload, dict) or workload.get("kind") != "daemon" or workload.get("activation") != "on-demand":
        raise WakeError("service is not an on-demand daemon")

    ordered: list[str] = []
    visited: set[str] = set()

    def visit(current_id: str) -> None:
        if current_id in visited:
            return
        visited.add(current_id)
        current = services.get(current_id)
        if not isinstance(current, dict):
            raise WakeError(f"compiled dependency {current_id!r} is missing")
        dependencies = current.get("dependencies", [])
        if not isinstance(dependencies, list):
            raise WakeError(f"compiled dependencies for {current_id!r} are invalid")
        for dependency in dependencies:
            target_id = dependency.get("service") if isinstance(dependency, dict) else None
            if not isinstance(target_id, str) or not SERVICE_ID_RE.fullmatch(target_id):
                raise WakeError(f"compiled dependency for {current_id!r} is invalid")
            target = services.get(target_id)
            if not isinstance(target, dict):
                raise WakeError(f"compiled dependency {target_id!r} is missing")
            if _is_on_demand(target):
                visit(target_id)
        if _is_on_demand(current):
            _validate_runtime_owner(effective, current_id)
            ordered.append(current_id)

    visit(service_id)
    if not ordered or ordered[-1] != service_id:
        raise WakeError("requested service has no managed on-demand lease")
    return ordered


def _systemctl(systemctl: str, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            [systemctl, *args],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=SYSTEMCTL_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise WakeError(f"native service activation failed: {exc}") from exc
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[:2000]
        raise WakeError(f"native service activation failed: {detail or f'exit {result.returncode}'}")
    return result


def wake_service(effective: dict[str, Any], service_id: str, *, systemctl: str) -> None:
    acquired: list[str] = []
    try:
        for current_id in _wake_order(effective, service_id):
            lease = _lease_unit(current_id)
            timer = _idle_timer(current_id)
            was_active = _systemctl(systemctl, "is-active", "--quiet", lease, check=False).returncode == 0
            _systemctl(systemctl, "start", lease)
            if not was_active:
                acquired.append(lease)
            _systemctl(systemctl, "restart", timer)
    except WakeError:
        for lease in reversed(acquired):
            _systemctl(systemctl, "stop", lease, check=False)
        raise


def _response(status: int, reason: str, body: str = "") -> bytes:
    payload = body.encode("utf-8")
    headers = [
        f"HTTP/1.1 {status} {reason}",
        "Content-Type: text/plain; charset=utf-8",
        f"Content-Length: {len(payload)}",
        "Connection: close",
        "Cache-Control: no-store",
        "",
        "",
    ]
    return "\r\n".join(headers).encode("ascii") + payload


def _read_request(connection: socket.socket) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while total <= MAX_REQUEST_BYTES:
        try:
            chunk = connection.recv(min(4096, MAX_REQUEST_BYTES + 1 - total))
        except socket.timeout as exc:
            raise WakeError("timed out reading wake request") from exc
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        data = b"".join(chunks)
        if b"\r\n\r\n" in data:
            return data
    if total > MAX_REQUEST_BYTES:
        raise WakeError("request is too large")
    raise WakeError("incomplete HTTP request")


def serve_connection(*, effective_path: pathlib.Path, systemctl: str, fd: int = 0) -> int:
    """Serve exactly one accepted AF_UNIX stream connection from systemd."""
    try:
        connection = socket.fromfd(fd, socket.AF_UNIX, socket.SOCK_STREAM)
    except OSError as exc:
        print(f"nas-v2-wake: invalid activated socket: {exc}", file=sys.stderr)
        return 2
    with connection:
        connection.settimeout(SOCKET_TIMEOUT_SECONDS)
        try:
            service_id = parse_request(_read_request(connection))
            effective = _load_effective(effective_path)
            wake_service(effective, service_id, systemctl=systemctl)
        except KeyError:
            response = _response(404, "Not Found", "unknown service\n")
        except WakeError as exc:
            message = str(exc)
            status = (
                400
                if message.startswith(("invalid ", "wake endpoint", "request ", "incomplete ", "HTTP ", "missing "))
                else 503
            )
            reason = "Bad Request" if status == 400 else "Service Unavailable"
            response = _response(status, reason, message + "\n")
        else:
            response = _response(204, "No Content")
        try:
            connection.sendall(response)
        except OSError as exc:
            print(f"nas-v2-wake: unable to send response: {exc}", file=sys.stderr)
            return 2
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Serve one Managed Services V2 wake request")
    parser.add_argument("--effective", type=pathlib.Path, default=pathlib.Path("/run/nas-control/effective.json"))
    parser.add_argument("--systemctl", default="systemctl")
    parser.add_argument("--fd", type=int, default=0, help=argparse.SUPPRESS)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return serve_connection(effective_path=args.effective, systemctl=args.systemctl, fd=args.fd)


if __name__ == "__main__":
    raise SystemExit(main())
