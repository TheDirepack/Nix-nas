"""Authentik OAuth bearer authentication command for Cockpit."""

from __future__ import annotations

import json
import os
import time
from typing import Any

CLIENT_ID = "nas-cockpit"
ADMIN_GROUP = "nas_admin"
JWKS_URL = "http://127.0.0.1:9000/identity/application/o/nas-cockpit/jwks/"


class AuthenticationError(RuntimeError):
    pass


def validate_claims(claims: dict[str, Any]) -> str:
    audience = claims.get("aud")
    # Hostile aud shapes must fail closed as an auth rejection, never escape
    # as TypeError from set() over unhashable entries.
    if isinstance(audience, str):
        audiences = {audience}
    elif isinstance(audience, list):
        audiences = {item for item in audience if isinstance(item, str)}
    else:
        audiences = set()
    if CLIENT_ID not in audiences:
        raise AuthenticationError("token has the wrong audience")
    groups = claims.get("groups")
    if not isinstance(groups, list) or ADMIN_GROUP not in groups:
        raise AuthenticationError("token does not grant nas_admin")
    return "root"


def send_frame(value: dict[str, Any]) -> None:
    payload = json.dumps(value, separators=(",", ":")).encode("utf-8")
    os.write(1, f"{len(payload) + 1}\n\n".encode("ascii"))
    os.write(1, payload)


def read_frame() -> dict[str, Any]:
    size = 0
    digits = 0
    while True:
        byte = os.read(1, 1)
        if not byte:
            raise AuthenticationError("Cockpit closed the authentication channel")
        if byte == b"\n":
            break
        if byte < b"0" or byte > b"9" or digits == 7:
            raise AuthenticationError("invalid Cockpit protocol frame")
        size = size * 10 + int(byte)
        digits += 1
    data = b""
    while len(data) < size:
        chunk = os.read(1, size - len(data))
        if not chunk:
            raise AuthenticationError("truncated Cockpit protocol frame")
        data += chunk
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuthenticationError("invalid Cockpit authorization response") from exc
    if not isinstance(value, dict):
        raise AuthenticationError("invalid Cockpit authorization response")
    return value


def bearer_token() -> str:
    cookie = f"nas-cockpit-{os.getpid()}-{time.monotonic_ns()}"
    send_frame({"command": "authorize", "cookie": cookie, "challenge": "*"})
    response = read_frame()
    value = response.get("response")
    if response.get("command") != "authorize" or response.get("cookie") != cookie:
        raise AuthenticationError("unexpected Cockpit authorization response")
    if not isinstance(value, str) or not value.startswith("Bearer ") or len(value) <= len("Bearer "):
        raise AuthenticationError("Cockpit did not provide a bearer token")
    return value[len("Bearer ") :]


def verify(token: str) -> str:
    import jwt

    try:
        key = jwt.PyJWKClient(JWKS_URL).get_signing_key_from_jwt(token).key
        claims = jwt.decode(token, key, algorithms=["RS256"], audience=CLIENT_ID)
    except jwt.PyJWTError as exc:
        raise AuthenticationError("invalid Authentik bearer token") from exc
    return validate_claims(claims)


def main() -> int:
    try:
        verify(bearer_token())
    except AuthenticationError as exc:
        send_frame({"command": "init", "problem": "access-denied", "message": str(exc)})
        return 1
    os.execv("/run/current-system/sw/libexec/cockpit-bridge", ["cockpit-bridge"])


if __name__ == "__main__":
    raise SystemExit(main())
