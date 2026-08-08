"""Bounded structured logging for NAS control-plane services.

The helper emits one JSON object per line so journald can retain stable fields
without forcing diagnostics to parse free-form messages. Values are bounded and
secret-like fields are redacted before serialization.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from typing import Any, Mapping, TextIO

MAX_TEXT_LENGTH = 4096
MAX_COLLECTION_ITEMS = 64
MAX_DEPTH = 4
_SENSITIVE_KEYS = frozenset(
    {
        "authorization",
        "cookie",
        "cookies",
        "credential",
        "credentials",
        "password",
        "passwd",
        "token",
        "api_key",
        "apikey",
        "access_key",
        "secret",
        "secret_key",
        "private_key",
        "client_secret",
        "access_token",
        "refresh_token",
        "session_token",
    }
)
_SENSITIVE_SUFFIXES = (
    "_password",
    "_passwd",
    "_token",
    "_secret",
    "_api_key",
    "_access_key",
    "_private_key",
    "_cookie",
)


def _sensitive_key(key: str) -> bool:
    lowered = key.lower().replace("-", "_").replace(".", "_")
    return lowered in _SENSITIVE_KEYS or lowered.endswith(_SENSITIVE_SUFFIXES)


def _bounded_text(value: Any) -> str:
    text = str(value).replace("\x00", "")
    if len(text) <= MAX_TEXT_LENGTH:
        return text
    return f"{text[:MAX_TEXT_LENGTH]}[truncated]"


def sanitize(value: Any, *, key: str = "", depth: int = 0) -> Any:
    """Return a JSON-safe, bounded value with secret-like fields redacted."""

    if key and _sensitive_key(key):
        return "[redacted]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        # Process output is text-oriented. Decode invalid bytes deterministically
        # instead of leaking Python's implementation-specific b'...' repr.
        return _bounded_text(bytes(value).decode("utf-8", errors="replace"))
    if depth >= MAX_DEPTH:
        return "[depth-limit]"
    if isinstance(value, Mapping):
        output: dict[str, Any] = {}
        for index, (item_key, item_value) in enumerate(value.items()):
            if index >= MAX_COLLECTION_ITEMS:
                output["_truncated"] = True
                break
            normalized_key = _bounded_text(item_key)
            output[normalized_key] = sanitize(item_value, key=normalized_key, depth=depth + 1)
        return output
    if isinstance(value, (list, tuple, set, frozenset)):
        items = list(value)
        output = [sanitize(item, depth=depth + 1) for item in items[:MAX_COLLECTION_ITEMS]]
        if len(items) > MAX_COLLECTION_ITEMS:
            output.append("[truncated]")
        return output
    return _bounded_text(value)


def log_event(
    event: str,
    *,
    operation_id: str = "",
    workflow: str = "",
    phase: str = "",
    actor: str = "system",
    authority: str = "",
    result: str = "",
    error_class: str = "",
    duration_ms: int | float | None = None,
    retry_count: int = 0,
    affected_unit: str = "",
    recovery_required: bool = False,
    stream: TextIO | None = None,
    **fields: Any,
) -> dict[str, Any]:
    """Emit and return a stable structured operation record."""

    record: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": _bounded_text(event),
        "operationId": _bounded_text(operation_id),
        "workflow": _bounded_text(workflow),
        "phase": _bounded_text(phase),
        "actor": _bounded_text(actor),
        "authority": _bounded_text(authority),
        "result": _bounded_text(result),
        "errorClass": _bounded_text(error_class),
        "retryCount": max(0, int(retry_count)),
        "affectedUnit": _bounded_text(affected_unit),
        "recoveryRequired": bool(recovery_required),
    }
    if duration_ms is not None:
        record["durationMs"] = max(0, round(float(duration_ms), 3))
    for key, value in fields.items():
        record[_bounded_text(key)] = sanitize(value, key=key)
    target = sys.stderr if stream is None else stream
    print(json.dumps(record, sort_keys=True, separators=(",", ":")), file=target, flush=True)
    return record
