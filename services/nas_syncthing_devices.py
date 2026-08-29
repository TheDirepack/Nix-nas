"""Validation helpers for Syncthing devices stored in Authentik user attributes.

Authentik is the only user-editable settings authority. The reconciler reads
``attributes.nasSyncthingDevices`` (or the legacy singular attribute) and
translates only the appliance-owned ``nas-*`` folders/devices into Syncthing.
Self-service devices use Syncthing discovery rather than administrator-selected
static connection targets, so ordinary profile data cannot become an outbound
connection primitive from the NAS host.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Iterable, Mapping

DEVICE_ID_RE = re.compile(r"^[A-Z2-7]{7}(?:-[A-Z2-7]{7}){7}$")
USERNAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$")
MAX_DEVICES_PER_USER = max(1, int(os.environ.get("NAS_MAX_SYNCTHING_DEVICES_PER_USER", "32")))
MAX_DEVICE_NAME = 128
SELF_SERVICE_ADDRESSES = ["dynamic"]


class DeviceError(ValueError):
    """A user-supplied Syncthing device record is invalid."""


def _text(value: Any, label: str, *, maximum: int) -> str:
    if not isinstance(value, str):
        raise DeviceError(f"{label} must be a string")
    result = value.strip()
    if not result or len(result) > maximum:
        raise DeviceError(f"{label} must be between 1 and {maximum} characters")
    if any(ord(character) < 32 or ord(character) == 127 for character in result):
        raise DeviceError(f"{label} contains control characters")
    return result


def validate_username(value: str) -> str:
    if not isinstance(value, str) or not USERNAME_RE.fullmatch(value):
        raise DeviceError("Invalid user identifier")
    return value


def normalize_device(raw: Mapping[str, Any] | str) -> dict[str, Any]:
    """Return the narrow Syncthing device object managed by this appliance."""
    if isinstance(raw, str):
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise DeviceError("Syncthing device attribute must contain JSON") from exc
        if isinstance(value, str):
            raise DeviceError(
                "Syncthing device is a JSON-encoded string; remove the extra quoting and store a JSON object"
            )
    else:
        value = raw
    if not isinstance(value, Mapping):
        raise DeviceError("Syncthing device must be a JSON object")

    if "deviceID" in value:
        raw_device_id = value.get("deviceID")
    elif "id" in value:
        raw_device_id = value.get("id")
    else:
        raise DeviceError("Device ID is required")
    device_id = _text(raw_device_id, "Device ID", maximum=128).upper()
    if not DEVICE_ID_RE.fullmatch(device_id):
        raise DeviceError("Device ID is not a valid Syncthing device ID")
    name = _text(value.get("name") or device_id[:7], "Device name", maximum=MAX_DEVICE_NAME)

    raw_addresses = value.get("addresses", SELF_SERVICE_ADDRESSES)
    if raw_addresses != SELF_SERVICE_ADDRESSES:
        raise DeviceError(
            "Self-service Syncthing devices must use the discovery address ['dynamic']; "
            "static connection targets require administrator-managed configuration"
        )

    return {
        "deviceID": device_id,
        "name": name,
        "addresses": list(SELF_SERVICE_ADDRESSES),
        "autoAcceptFolders": False,
    }


def expand_attribute_values(values: Iterable[Any]) -> list[Mapping[str, Any] | str]:
    """Expand Authentik prompt values into individual device definitions.

    A prompt can store a JSON array, one JSON object, or newline-delimited JSON
    objects. Invalid primitive values fail loudly so an Authentik editing error
    cannot silently disable a user's backup.
    """

    def append_item(item: Any, *, context: str) -> None:
        if isinstance(item, Mapping):
            expanded.append(item)
        elif isinstance(item, str):
            expanded.append(item)
        else:
            raise DeviceError(
                f"{context} must contain only JSON objects or JSON-object strings; got {type(item).__name__}"
            )

    expanded: list[Mapping[str, Any] | str] = []
    for index, value in enumerate(values):
        context = f"Syncthing device attribute value {index + 1}"
        if isinstance(value, Mapping):
            expanded.append(value)
            continue
        if isinstance(value, list):
            for item_index, item in enumerate(value):
                append_item(item, context=f"{context}, list item {item_index + 1}")
            continue
        if value is None:
            raise DeviceError(f"{context} cannot be null; use an empty list to remove all devices")
        if not isinstance(value, str):
            raise DeviceError(f"{context} must be a JSON object, array, or string; got {type(value).__name__}")
        if not value.strip():
            continue

        text = value.strip()
        try:
            decoded = json.loads(text)
        except json.JSONDecodeError:
            lines = [line.strip() for line in text.splitlines() if line.strip()]
            if len(lines) <= 1:
                expanded.append(text)
            else:
                expanded.extend(lines)
            continue

        if isinstance(decoded, Mapping):
            expanded.append(decoded)
        elif isinstance(decoded, list):
            for item_index, item in enumerate(decoded):
                append_item(item, context=f"{context}, JSON array item {item_index + 1}")
        elif isinstance(decoded, str):
            raise DeviceError(
                f"{context} is a JSON-encoded string; remove the extra quoting and store an object or array"
            )
        else:
            raise DeviceError(f"{context} decoded to {type(decoded).__name__}; expected a JSON object or array")
    return expanded


def normalize_devices(values: Iterable[Any]) -> list[dict[str, Any]]:
    values = expand_attribute_values(values)
    if len(values) > MAX_DEVICES_PER_USER:
        raise DeviceError(f"At most {MAX_DEVICES_PER_USER} devices may be configured per user")
    output: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in values:
        device = normalize_device(raw)
        device_id = device["deviceID"]
        if device_id in seen:
            raise DeviceError(f"Device {device_id} is listed more than once")
        seen.add(device_id)
        output.append(device)
    return sorted(output, key=lambda item: (item["name"].casefold(), item["deviceID"]))
