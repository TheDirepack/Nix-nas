#!/usr/bin/env python3
"""Small vmalert notifier and optional ntfy delivery adapter.

vmalert owns rule evaluation, VictoriaMetrics owns metric history, and this
service owns only bounded notification routing, deduplication, inhibition, and
status reporting. It accepts vmalert's notifier wire format without installing
or running a separate alert-management server.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
import re
import stat
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Mapping, Sequence

from nas_logging import log_event

LISTEN_ADDRESS = os.environ.get("NAS_ALERT_ROUTER_LISTEN", "127.0.0.1:9093")
NTFY_BASE_URL = os.environ.get("NAS_NTFY_URL", "http://127.0.0.1:2586").rstrip("/")
NTFY_TOPIC_FILE = pathlib.Path(os.environ.get("NAS_NTFY_TOPIC_FILE", "/run/nas-secrets/observability/ntfy-topic"))
NTFY_PASSWORD_FILE = pathlib.Path(
    os.environ.get("NAS_NTFY_PASSWORD_FILE", "/run/nas-secrets/observability/ntfy-admin-password")
)
NTFY_USERNAME = os.environ.get("NAS_NTFY_USERNAME", "admin")
NTFY_ENABLED = os.environ.get("NAS_ALERT_ROUTER_NTFY_ENABLED", "1") == "1"
STATE_PATH = pathlib.Path(os.environ.get("NAS_ALERT_ROUTER_STATE", "/var/lib/nas-alert-router/state.json"))
REPEAT_SECONDS = max(60, int(os.environ.get("NAS_ALERT_ROUTER_REPEAT_SECONDS", "14400")))
MAX_BODY_BYTES = max(4096, int(os.environ.get("NAS_ALERT_ROUTER_MAX_BODY_BYTES", str(1024 * 1024))))
MAX_ALERTS_PER_REQUEST = max(1, int(os.environ.get("NAS_ALERT_ROUTER_MAX_ALERTS", "256")))
MAX_STATE_ENTRIES = max(128, int(os.environ.get("NAS_ALERT_ROUTER_MAX_STATE_ENTRIES", "4096")))
REQUEST_TIMEOUT_SECONDS = max(1.0, float(os.environ.get("NAS_ALERT_ROUTER_REQUEST_TIMEOUT_SECONDS", "10")))
MAX_SECRET_BYTES = 4096

STATE_LOCK = threading.RLock()


class AlertRouterError(RuntimeError):
    """Expected malformed-input error."""


class AlertDeliveryError(RuntimeError):
    """Expected downstream delivery failure."""


@dataclass(frozen=True)
class RoutedAlert:
    fingerprint: str
    status: str
    severity: str
    title: str
    message: str
    labels: dict[str, str]


def _text(value: Any, *, limit: int = 1024) -> str:
    return str(value or "").strip()[:limit]


def _header_text(value: Any, *, limit: int = 1024) -> str:
    """Return bounded text that is safe to place in an HTTP header value."""

    normalized = re.sub(r"[\x00-\x1f\x7f]+", " ", str(value or "")).strip()
    return normalized[:limit]


def _mapping_strings(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    return {_header_text(key, limit=128): _header_text(item, limit=512) for key, item in value.items()}


def _parse_timestamp(value: Any) -> datetime | None:
    text = _text(value, limit=128)
    if not text or text.startswith("0001-01-01"):
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def alert_status(raw: Mapping[str, Any], *, now: datetime | None = None) -> str:
    explicit = _text(raw.get("status"), limit=32).lower()
    if explicit in {"firing", "resolved"}:
        return explicit
    ends_at = _parse_timestamp(raw.get("endsAt"))
    current = now or datetime.now(timezone.utc)
    return "resolved" if ends_at is not None and ends_at <= current else "firing"


def alert_fingerprint(labels: Mapping[str, str]) -> str:
    encoded = json.dumps(dict(sorted(labels.items())), separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def normalize_alert(raw: Any, *, now: datetime | None = None) -> RoutedAlert:
    if not isinstance(raw, Mapping):
        raise AlertRouterError("Each alert must be an object")
    labels = _mapping_strings(raw.get("labels"))
    if not labels:
        raise AlertRouterError("Alert labels must be a non-empty object")
    annotations = _mapping_strings(raw.get("annotations"))
    status = alert_status(raw, now=now)
    severity = labels.get("severity", "warning").lower()
    if severity not in {"critical", "warning", "info"}:
        severity = "warning"
    alert_name = labels.get("alertname", "NAS alert")
    instance = labels.get("instance") or labels.get("host") or ""
    summary = _header_text(annotations.get("summary") or alert_name, limit=220)
    description = _text(annotations.get("description") or annotations.get("message") or summary, limit=4000)
    title = _header_text(f"{summary} [{status}]", limit=256)
    message_lines = [description]
    if instance:
        message_lines.append(f"Instance: {instance}")
    message_lines.append(f"Severity: {severity}")
    return RoutedAlert(
        fingerprint=alert_fingerprint(labels),
        status=status,
        severity=severity,
        title=title[:256],
        message="\n".join(message_lines)[:4096],
        labels=labels,
    )


def inhibit_derivative_warnings(alerts: Sequence[RoutedAlert]) -> list[RoutedAlert]:
    critical_keys = {
        (alert.labels.get("alertname", ""), alert.labels.get("instance", ""))
        for alert in alerts
        if alert.status == "firing" and alert.severity == "critical"
    }
    return [
        alert
        for alert in alerts
        if not (
            alert.status == "firing"
            and alert.severity == "warning"
            and (alert.labels.get("alertname", ""), alert.labels.get("instance", "")) in critical_keys
        )
    ]


def _quarantine_corrupt_state(path: pathlib.Path, *, reason: str) -> pathlib.Path:
    quarantine = path.with_name(f"{path.name}.corrupt-{int(time.time())}-{uuid.uuid4().hex[:8]}")
    try:
        os.replace(path, quarantine)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as exc:
        raise AlertRouterError("Alert-router state is corrupt and could not be quarantined") from exc
    log_event(
        "alert_router_state_quarantined",
        workflow="alert-routing",
        phase="state-load",
        authority="nas-alert-router",
        result="degraded",
        error_class=reason,
        recovery_required=True,
        quarantine_path=str(quarantine),
    )
    return quarantine


def load_state(path: pathlib.Path | None = None) -> dict[str, dict[str, Any]]:
    path = STATE_PATH if path is None else path
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        _quarantine_corrupt_state(path, reason="JSONDecodeError")
        return {}
    except OSError as exc:
        raise AlertRouterError("Unable to read alert-router state") from exc
    if not isinstance(value, Mapping):
        _quarantine_corrupt_state(path, reason="InvalidStateShape")
        return {}
    return {str(key): dict(item) for key, item in value.items() if isinstance(key, str) and isinstance(item, Mapping)}


def atomic_write_state(value: Mapping[str, Mapping[str, Any]], path: pathlib.Path | None = None) -> None:
    path = STATE_PATH if path is None else path
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    replaced = False
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        replaced = True
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if not replaced:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def should_send(alert: RoutedAlert, state: Mapping[str, Mapping[str, Any]], *, now: float) -> bool:
    previous = state.get(alert.fingerprint)
    if not isinstance(previous, Mapping):
        return True
    if previous.get("status") != alert.status:
        return True
    last_sent = previous.get("lastSent")
    return not isinstance(last_sent, (int, float)) or now - float(last_sent) >= REPEAT_SECONDS


def read_secret(path: pathlib.Path) -> str:
    try:
        before = path.lstat()
    except OSError as exc:
        raise AlertDeliveryError(f"Unable to inspect secret file {path}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise AlertDeliveryError(f"Secret path is not a regular file: {path}")
    if before.st_mode & 0o077:
        raise AlertDeliveryError(f"Secret file permissions are too broad: {path}")
    if before.st_uid not in {0, os.geteuid()}:
        raise AlertDeliveryError(f"Secret file has an unexpected owner: {path}")

    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise AlertDeliveryError(f"Unable to open secret file {path}") from exc
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise AlertDeliveryError(f"Secret file changed while opening: {path}")
        if not stat.S_ISREG(opened.st_mode) or opened.st_mode & 0o077:
            raise AlertDeliveryError(f"Secret file metadata is unsafe: {path}")
        if opened.st_uid not in {0, os.geteuid()}:
            raise AlertDeliveryError(f"Secret file has an unexpected owner: {path}")
        chunks: list[bytes] = []
        remaining = MAX_SECRET_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
    finally:
        os.close(fd)
    if len(raw) > MAX_SECRET_BYTES:
        raise AlertDeliveryError(f"Secret file is too large: {path}")
    try:
        value = raw.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise AlertDeliveryError(f"Secret file is not valid UTF-8: {path}") from exc
    if not value or "\n" in value or "\r" in value:
        raise AlertDeliveryError(f"Invalid single-line secret in {path}")
    return value


def publish_ntfy(alert: RoutedAlert) -> None:
    if not NTFY_ENABLED:
        return
    topic = read_secret(NTFY_TOPIC_FILE)
    password = read_secret(NTFY_PASSWORD_FILE)
    auth = base64.b64encode(f"{NTFY_USERNAME}:{password}".encode("utf-8")).decode("ascii")
    tags = ["rotating_light" if alert.status == "firing" else "white_check_mark"]
    if alert.severity == "critical":
        tags.append("skull")
    request = urllib.request.Request(
        f"{NTFY_BASE_URL}/{urllib.parse.quote(topic, safe='')}",
        data=alert.message.encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Basic {auth}",
            "Content-Type": "text/plain; charset=utf-8",
            "Title": alert.title,
            "Priority": "5" if alert.severity == "critical" else "4" if alert.severity == "warning" else "3",
            "Tags": ",".join(tags),
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            if response.status < 200 or response.status >= 300:
                raise AlertDeliveryError(f"ntfy returned HTTP {response.status}")
    except (OSError, urllib.error.URLError) as exc:
        raise AlertDeliveryError(f"Unable to publish ntfy alert: {exc}") from exc


def _state_entry(alert: RoutedAlert, *, timestamp: float) -> dict[str, Any]:
    return {
        "status": alert.status,
        "severity": alert.severity,
        "lastSent": timestamp,
        "title": alert.title,
        "labels": dict(alert.labels),
    }


def _prune_state(state: dict[str, dict[str, Any]]) -> None:
    if len(state) <= MAX_STATE_ENTRIES:
        return
    ordered = sorted(
        state,
        key=lambda fingerprint: (
            float(state[fingerprint].get("lastSent", 0.0))
            if isinstance(state[fingerprint].get("lastSent"), (int, float))
            else 0.0
        ),
        reverse=True,
    )
    for fingerprint in ordered[MAX_STATE_ENTRIES:]:
        state.pop(fingerprint, None)


def _rfc3339_timestamp(value: Any) -> str:
    try:
        timestamp = float(value)
    except (TypeError, ValueError):
        timestamp = 0.0
    if timestamp < 0 or not __import__("math").isfinite(timestamp):
        timestamp = 0.0
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def public_alerts(state: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
    ordered = sorted(
        state.items(),
        key=lambda item: (
            float(item[1].get("lastSent", 0)) if isinstance(item[1].get("lastSent"), (int, float)) else 0.0
        ),
        reverse=True,
    )
    output: list[dict[str, Any]] = []
    for fingerprint, entry in ordered:
        labels = entry.get("labels")
        normalized_labels = _mapping_strings(labels)
        output.append(
            {
                "fingerprint": fingerprint,
                "labels": normalized_labels,
                "annotations": {"summary": _text(entry.get("title"), limit=256)},
                "status": {"state": _text(entry.get("status"), limit=32) or "unknown"},
                "updatedAt": _rfc3339_timestamp(entry.get("lastSent", 0)),
            }
        )
    return output


def process_alerts(
    raw_alerts: Any,
    *,
    now: float | None = None,
    operation_id: str = "",
) -> dict[str, int]:
    started = time.monotonic()
    if not isinstance(raw_alerts, list):
        raise AlertRouterError("Request body must be an array of alerts")
    if len(raw_alerts) > MAX_ALERTS_PER_REQUEST:
        raise AlertRouterError("Request contains too many alerts")
    normalized = inhibit_derivative_warnings([normalize_alert(item) for item in raw_alerts])
    timestamp = time.time() if now is None else now
    sent = 0
    suppressed = 0
    dirty = False
    try:
        with STATE_LOCK:
            state = load_state()
            try:
                for alert in normalized:
                    if should_send(alert, state, now=timestamp):
                        publish_ntfy(alert)
                        sent += 1
                        state[alert.fingerprint] = _state_entry(alert, timestamp=timestamp)
                        dirty = True
                    else:
                        suppressed += 1
            finally:
                if dirty:
                    _prune_state(state)
                    atomic_write_state(state)
    except AlertDeliveryError as exc:
        log_event(
            "alert_batch",
            operation_id=operation_id,
            workflow="alert-routing",
            phase="delivery",
            authority="nas-alert-router",
            result="failure",
            error_class=type(exc).__name__,
            duration_ms=(time.monotonic() - started) * 1000,
            received=len(raw_alerts),
            considered=len(normalized),
            sent=sent,
            suppressed=suppressed,
        )
        raise
    result = {"received": len(raw_alerts), "considered": len(normalized), "sent": sent, "suppressed": suppressed}
    log_event(
        "alert_batch",
        operation_id=operation_id,
        workflow="alert-routing",
        phase="delivery",
        authority="nas-alert-router",
        result="success",
        duration_ms=(time.monotonic() - started) * 1000,
        received=result["received"],
        considered=result["considered"],
        sent=result["sent"],
        suppressed=result["suppressed"],
    )
    return result


class Handler(BaseHTTPRequestHandler):
    server_version = "nas-alert-router/2"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _json(self, status: HTTPStatus, value: Any) -> None:
        payload = json.dumps(value, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        if self.path in {"/-/healthy", "/-/ready", "/health"}:
            self._json(HTTPStatus.OK, {"ok": True})
            return
        if self.path == "/api/v2/alerts":
            with STATE_LOCK:
                alerts = public_alerts(load_state())
            self._json(HTTPStatus.OK, alerts)
            return
        if self.path in {"/", "/alerts", "/alerts/"}:
            with STATE_LOCK:
                state = load_state()
            self._json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "trackedAlerts": len(state),
                    "backend": "victoriametrics-vmalert",
                    "ntfyEnabled": NTFY_ENABLED,
                },
            )
            return
        self._json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not found"})

    def do_POST(self) -> None:
        if self.path != "/api/v2/alerts":
            self._json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not found"})
            return
        operation_id = _header_text(self.headers.get("X-Request-ID"), limit=128) or uuid.uuid4().hex
        if self.headers.get("Transfer-Encoding") is not None:
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "transfer encoding is not supported"})
            return
        length_text = self.headers.get("Content-Length")
        if length_text is None:
            self._json(HTTPStatus.LENGTH_REQUIRED, {"ok": False, "error": "content length required"})
            return
        try:
            length = int(length_text)
        except ValueError:
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "invalid content length"})
            return
        if length < 0:
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "invalid content length"})
            return
        if length > MAX_BODY_BYTES:
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"ok": False, "error": "body too large"})
            return
        try:
            raw = json.loads(self.rfile.read(length))
            result = process_alerts(raw, operation_id=operation_id)
        except (AlertRouterError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            log_event(
                "alert_request",
                operation_id=operation_id,
                workflow="alert-routing",
                phase="validation",
                authority="nas-alert-router",
                result="failure",
                error_class=type(exc).__name__,
            )
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc), "operationId": operation_id})
            return
        except AlertDeliveryError as exc:
            self._json(HTTPStatus.BAD_GATEWAY, {"ok": False, "error": str(exc), "operationId": operation_id})
            return
        self._json(HTTPStatus.OK, {"ok": True, "operationId": operation_id, **result})


def main() -> int:
    host, separator, port_text = LISTEN_ADDRESS.rpartition(":")
    if not separator or not host:
        raise SystemExit(f"Invalid NAS_ALERT_ROUTER_LISTEN value: {LISTEN_ADDRESS}")
    try:
        port = int(port_text)
    except ValueError as exc:
        raise SystemExit(f"Invalid NAS_ALERT_ROUTER_LISTEN value: {LISTEN_ADDRESS}") from exc
    if port < 1 or port > 65535:
        raise SystemExit(f"Invalid NAS_ALERT_ROUTER_LISTEN value: {LISTEN_ADDRESS}")
    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    log_event(
        "service_start",
        workflow="alert-routing",
        phase="serve",
        authority="nas-alert-router",
        result="success",
        listen=LISTEN_ADDRESS,
        ntfy_enabled=NTFY_ENABLED,
    )
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
