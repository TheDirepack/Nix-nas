"""Pure validation of the first-start systemd job request and secret payload.

File ownership, size, permission, and deletion checks remain in the privileged
nas_setup job runner, before and after invoking these parsers respectively.
"""

from __future__ import annotations

import json
import pathlib
import re
from typing import Any

from nas_setup_config import SetupError, normalize_secret_line


_REQUEST_KEYS = {
    "schemaVersion",
    "jobId",
    "reservationToken",
    "config",
    "planDigest",
    "devices",
    "allowDestructiveStorage",
    "confirmPasswordReapply",
    "encryptStorage",
}


def parse_first_start_request(text: str) -> dict[str, Any]:
    try:
        request = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SetupError("First-start job request is invalid") from exc
    if not isinstance(request, dict) or set(request) != _REQUEST_KEYS or request.get("schemaVersion") != 1:
        raise SetupError("First-start job request contract is invalid")
    token = request.get("reservationToken")
    if not isinstance(token, str) or re.fullmatch(r"[0-9a-f]{32}", token) is None:
        raise SetupError("First-start reservation token is invalid")
    job_id = request.get("jobId")
    if not isinstance(job_id, str) or re.fullmatch(r"[0-9a-f]{24}", job_id) is None:
        raise SetupError("First-start job identifier is invalid")
    config = request.get("config")
    if not isinstance(config, str) or not pathlib.Path(config).is_absolute():
        raise SetupError("First-start job configuration path is invalid")
    digest = request.get("planDigest")
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise SetupError("First-start job plan digest is invalid")
    devices = request.get("devices")
    if (
        not isinstance(devices, list)
        or not all(isinstance(item, str) and item for item in devices)
        or len(devices) != len(set(devices))
    ):
        raise SetupError("First-start job devices are invalid")
    if not all(
        isinstance(request.get(field), bool)
        for field in ("allowDestructiveStorage", "confirmPasswordReapply", "encryptStorage")
    ):
        raise SetupError("First-start job confirmation flags are invalid")
    return request


def parse_first_start_secrets(text: str) -> tuple[str, dict[str, Any]]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SetupError("First-start secret payload is invalid") from exc
    if not isinstance(payload, dict) or set(payload) != {"keepass", "administrator"}:
        raise SetupError("First-start secret payload contract is invalid")
    password = payload["keepass"]
    if not isinstance(password, str):
        raise SetupError("First-start KeePass database password is invalid")
    password = normalize_secret_line(password, "KeePass database password")
    administrator = payload["administrator"]
    if not isinstance(administrator, dict) or set(administrator) != {"username", "name", "email", "password"}:
        raise SetupError("First-start administrator secret payload is invalid")
    return password, administrator
