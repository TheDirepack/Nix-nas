from __future__ import annotations

import os
import pathlib
import stat
import sys
from typing import Any, Mapping

from nas_common import ADMIN_GROUP, CAPABILITY_GROUPS, DISABLED_GROUP, GUEST_GROUP, USER_GROUP
from nas_syncthing_devices import DeviceError, normalize_devices, validate_username

SCHEMA_VERSION = 1
RESERVED_GROUPS = {
    ADMIN_GROUP,
    USER_GROUP,
    GUEST_GROUP,
    DISABLED_GROUP,
    *(group for pair in CAPABILITY_GROUPS.values() for group in pair),
}
FEATURE_MODES = {"off", "on-demand", "always"}
ZFS_TOPOLOGIES = {"single", "stripe", "mirror", "raidz1", "raidz2", "raidz3"}


class SetupError(RuntimeError):
    """Expected setup/configuration failure."""


def _bool(value: Any, label: str, default: bool) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise SetupError(f"{label} must be true or false")
    return value


def _string(value: Any, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        raise SetupError(f"{label} must be a non-empty string")
    return value.strip()


def reject_unknown_fields(value: Mapping[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(str(key) for key in value if key not in allowed)
    if unknown:
        raise SetupError(f"{label} contains unknown field(s): {', '.join(unknown)}")


def normalize_account(raw: Any, index: int) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise SetupError(f"accounts[{index}] must be an object")
    if "password" in raw:
        raise SetupError(
            f"accounts[{index}] contains plaintext password; use passwordFile or the account --password-stdin command"
        )
    reject_unknown_fields(
        raw,
        {"username", "name", "email", "active", "groups", "passwordFile", "attributes"},
        f"accounts[{index}]",
    )
    username = _string(raw.get("username"), f"accounts[{index}].username")
    try:
        username = validate_username(username)
    except DeviceError as exc:
        raise SetupError(f"accounts[{index}].username is unsafe: {exc}") from exc
    if username == "akadmin":
        raise SetupError("akadmin is Authentik's bootstrap account and is not managed by setup accounts")

    active = _bool(raw.get("active"), f"accounts[{index}].active", True)
    name = _string(raw.get("name", username), f"accounts[{index}].name")
    email = _string(raw.get("email", f"{username}@invalid.local"), f"accounts[{index}].email")

    raw_groups = raw.get("groups", [USER_GROUP])
    if not isinstance(raw_groups, list) or not all(isinstance(item, str) for item in raw_groups):
        raise SetupError(f"accounts[{index}].groups must be a list of group names")
    groups = {item.strip() for item in raw_groups if item.strip()}
    unknown = sorted(groups - RESERVED_GROUPS)
    if unknown:
        raise SetupError(f"accounts[{index}] contains unknown reserved groups: {', '.join(unknown)}")
    if active:
        groups.discard(DISABLED_GROUP)
        if not ({ADMIN_GROUP, GUEST_GROUP} & groups):
            groups.add(USER_GROUP)
    else:
        if ADMIN_GROUP in groups:
            raise SetupError(f"accounts[{index}] cannot disable an account while granting {ADMIN_GROUP}")
        groups = {DISABLED_GROUP}

    password_file = raw.get("passwordFile")
    if password_file is not None:
        password_file = _string(password_file, f"accounts[{index}].passwordFile")
        if not pathlib.Path(password_file).is_absolute():
            raise SetupError(f"accounts[{index}].passwordFile must be an absolute path")
    attributes = raw.get("attributes", {})
    if not isinstance(attributes, Mapping):
        raise SetupError(f"accounts[{index}].attributes must be an object")
    attributes = dict(attributes)
    if "nasSyncthingDevices" in attributes and "nasSyncthingDevice" in attributes:
        raise SetupError(
            f"accounts[{index}].attributes must not define both nasSyncthingDevices and nasSyncthingDevice"
        )
    device_key = (
        "nasSyncthingDevices"
        if "nasSyncthingDevices" in attributes
        else "nasSyncthingDevice"
        if "nasSyncthingDevice" in attributes
        else None
    )
    if device_key is not None:
        raw_devices = attributes.pop(device_key)
        values = raw_devices if isinstance(raw_devices, list) else [raw_devices]
        try:
            attributes["nasSyncthingDevices"] = normalize_devices(values)
        except DeviceError as exc:
            raise SetupError(f"accounts[{index}] has invalid Syncthing devices: {exc}") from exc

    return {
        "username": username,
        "name": name,
        "email": email,
        "active": active,
        "groups": sorted(groups),
        "passwordFile": password_file,
        "attributes": attributes,
    }


def normalize_config(raw: Mapping[str, Any]) -> dict[str, Any]:
    reject_unknown_fields(
        raw,
        {
            "schemaVersion",
            "storage",
            "accounts",
            "features",
            "deactivateMissingManagedAccounts",
            "runPreflight",
        },
        "setup configuration",
    )
    schema = raw.get("schemaVersion", SCHEMA_VERSION)
    if schema != SCHEMA_VERSION:
        raise SetupError(f"Unsupported setup schemaVersion {schema!r}; expected {SCHEMA_VERSION}")

    raw_accounts = raw.get("accounts", [])
    if not isinstance(raw_accounts, list):
        raise SetupError("accounts must be a list")
    accounts = [normalize_account(item, index) for index, item in enumerate(raw_accounts)]
    usernames = [item["username"] for item in accounts]
    duplicates = sorted({name for name in usernames if usernames.count(name) > 1})
    if duplicates:
        raise SetupError(f"Duplicate setup accounts: {', '.join(duplicates)}")

    storage_raw = raw.get("storage", {})
    if not isinstance(storage_raw, Mapping):
        raise SetupError("storage must be an object")
    reject_unknown_fields(
        storage_raw,
        {"createPool", "device", "devices", "topology", "wipeDevice", "wipeDevices", "ashift"},
        "storage",
    )
    legacy_device = storage_raw.get("device")
    devices_value = storage_raw.get("devices")
    if legacy_device is not None and devices_value is not None:
        raise SetupError("Use only one of storage.device or storage.devices")
    if legacy_device is not None:
        devices_value = [legacy_device]
    if devices_value is None:
        devices_value = []
    if not isinstance(devices_value, list) or not all(isinstance(item, str) for item in devices_value):
        raise SetupError("storage.devices must be a list of absolute /dev paths")
    devices = [_string(item, f"storage.devices[{index}]") for index, item in enumerate(devices_value)]
    if any(not item.startswith("/dev/") for item in devices):
        raise SetupError("Every storage.devices entry must be an absolute /dev path")
    if any(".." in pathlib.PurePath(item).parts for item in devices):
        raise SetupError("storage.devices must not contain parent-directory traversal")
    duplicates = sorted({item for item in devices if devices.count(item) > 1})
    if duplicates:
        raise SetupError(f"Duplicate storage devices: {', '.join(duplicates)}")

    topology = _string(storage_raw.get("topology", "single"), "storage.topology")
    if topology not in ZFS_TOPOLOGIES:
        raise SetupError(f"storage.topology must be one of: {', '.join(sorted(ZFS_TOPOLOGIES))}")
    wipe_value = storage_raw.get("wipeDevices")
    if "wipeDevice" in storage_raw:
        if wipe_value is not None:
            raise SetupError("Use only one of storage.wipeDevice or storage.wipeDevices")
        wipe_value = storage_raw.get("wipeDevice")
    ashift = storage_raw.get("ashift", 12)
    if isinstance(ashift, bool) or not isinstance(ashift, int) or not 9 <= ashift <= 16:
        raise SetupError("storage.ashift must be an integer from 9 through 16")
    storage = {
        "createPool": _bool(storage_raw.get("createPool"), "storage.createPool", False),
        "devices": devices,
        "topology": topology,
        "wipeDevices": _bool(wipe_value, "storage.wipeDevices", False),
        "ashift": ashift,
    }
    if storage["createPool"]:
        minimums = {"single": 1, "stripe": 2, "mirror": 2, "raidz1": 3, "raidz2": 4, "raidz3": 5}
        required = minimums[topology]
        if len(devices) < required:
            raise SetupError(f"storage.topology={topology} requires at least {required} device(s)")
        if topology == "single" and len(devices) != 1:
            raise SetupError(
                "storage.topology=single requires exactly one device; use stripe for multiple unmirrored devices"
            )
    elif devices or storage["wipeDevices"]:
        raise SetupError("storage.devices/wipeDevices require storage.createPool=true")

    features_raw = raw.get("features", {})
    if not isinstance(features_raw, Mapping):
        raise SetupError("features must be an object")
    features: dict[str, str] = {}
    for feature, mode in features_raw.items():
        feature_name = _string(feature, "feature name")
        mode_name = _string(mode, f"features.{feature_name}")
        if mode_name not in FEATURE_MODES:
            raise SetupError(f"features.{feature_name} must be one of: {', '.join(sorted(FEATURE_MODES))}")
        features[feature_name] = mode_name

    return {
        "schemaVersion": SCHEMA_VERSION,
        "storage": storage,
        "accounts": accounts,
        "features": features,
        "deactivateMissingManagedAccounts": _bool(
            raw.get("deactivateMissingManagedAccounts"),
            "deactivateMissingManagedAccounts",
            False,
        ),
        "runPreflight": _bool(raw.get("runPreflight"), "runPreflight", True),
    }


def normalize_secret_line(raw: str, label: str) -> str:
    if len(raw) > 4098 or "\x00" in raw:
        raise SetupError(f"{label} is too long or malformed")
    if raw.endswith("\r\n"):
        value = raw[:-2]
    elif raw.endswith(("\n", "\r")):
        value = raw[:-1]
    else:
        value = raw
    if not value or len(value) > 4096 or any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise SetupError(f"{label} must contain exactly one non-empty line without control characters")
    return value


def read_secret_stdin(label: str) -> str:
    return normalize_secret_line(sys.stdin.read(4099), label)


def read_password_file(path_value: str, label: str) -> str:
    path = pathlib.Path(path_value)
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SetupError(f"Unable to open {label} password file {path} without following symlinks: {exc}") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise SetupError(f"{label} password file is not a regular file: {path}")
        if info.st_mode & 0o077:
            raise SetupError(f"{label} password file must not be readable or writable by group/other: {path}")
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            descriptor = -1
            raw = handle.read(4099)
    except UnicodeDecodeError as exc:
        raise SetupError(f"{label} password file is not valid UTF-8: {path}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return normalize_secret_line(raw, f"{label} password file {path}")
