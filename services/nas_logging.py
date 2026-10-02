"""Bound and redact structured values retained by control-plane journals."""

from __future__ import annotations

import math
import re
from typing import Any, Mapping

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
# Compound structured-field names are common (providerAuthorization,
# upstream_token, peer.credentials). Every complete sensitive token is treated
# as sensitive at a normalized component boundary rather than maintaining a
# second, inevitably incomplete suffix allowlist. Names such as
# authorizationMethod remain visible because they do not end at that boundary.
_SENSITIVE_SUFFIXES = tuple(f"_{key}" for key in sorted(_SENSITIVE_KEYS))
_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def _normalized_key(key: str) -> str:
    # Structured APIs in this project use a mix of snake_case, kebab-case,
    # dotted names, and camelCase. Normalize all of those before applying the
    # exact/suffix sensitive-name policy so e.g. clientSecret and providerApiKey
    # cannot bypass redaction merely through naming style.
    with_boundaries = _CAMEL_BOUNDARY_RE.sub("_", key)
    return with_boundaries.lower().replace("-", "_").replace(".", "_")


def _sensitive_key(key: str) -> bool:
    lowered = _normalized_key(key)
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
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        # Strict JSON has no NaN/Infinity. Converting them to bounded strings
        # keeps journald output parseable by non-Python consumers.
        return value if math.isfinite(value) else _bounded_text(value)
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
            raw_key = str(item_key)
            display_key = _bounded_text(raw_key)
            # Classify the original key. Bounding is only a display/output
            # concern; truncating first could remove a trailing sensitive token.
            output[display_key] = sanitize(item_value, key=raw_key, depth=depth + 1)
        return output
    if isinstance(value, (list, tuple, set, frozenset)):
        items = list(value)
        list_output = [sanitize(item, depth=depth + 1) for item in items[:MAX_COLLECTION_ITEMS]]
        if len(items) > MAX_COLLECTION_ITEMS:
            list_output.append("[truncated]")
        return list_output
    return _bounded_text(value)
