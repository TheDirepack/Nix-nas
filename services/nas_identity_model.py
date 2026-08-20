from __future__ import annotations

import json
import os
import pathlib
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Mapping

from nas_common import (
    ADMIN_GROUP,
    DISABLED_GROUP,
    GUEST_GROUP,
    USER_GROUP,
    application_capability_allowed,
)
from nas_syncthing_devices import DeviceError, normalize_devices, validate_username

_SYNCTHING_SERVICE = os.environ.get("NAS_V2_SYNCTHING_SERVICE", "syncthing")
_SYNCTHING_CAPABILITY = os.environ.get("NAS_V2_SYNCTHING_CAPABILITY", "access")


def _resolve_syncthing_capability() -> tuple[str, str] | None:  # pragma: no cover - V2 integration
    service = os.environ.get("NAS_V2_SYNCTHING_SERVICE", _SYNCTHING_SERVICE)
    capability = os.environ.get("NAS_V2_SYNCTHING_CAPABILITY", _SYNCTHING_CAPABILITY)
    effective_path = os.environ.get("NAS_V2_EFFECTIVE", "/run/nas-control/effective.json")
    try:
        data = json.loads(pathlib.Path(effective_path).read_text(encoding="utf-8"))
        derived = data.get("derived", {}).get("authorization", {})
        if not isinstance(derived, dict):
            raise ValueError("derived.authorization is not a dict")
        caps = derived.get(service, {}).get("capabilities", {}) if isinstance(derived.get(service), dict) else {}
        if isinstance(caps, dict) and capability in caps:
            return service, capability
        if isinstance(derived, dict) and derived:
            return None
    except (OSError, ValueError, json.JSONDecodeError):
        pass
    return service, capability


RESERVED_GROUPS = (
    ADMIN_GROUP,
    USER_GROUP,
    GUEST_GROUP,
    DISABLED_GROUP,
)
APPLICATION_GROUP_PREFIX = "application."


class SyncError(RuntimeError):
    """Expected configuration or reconciliation failure."""


@dataclass(frozen=True)
class User:
    uid: str
    email: str
    display_name: str
    groups: frozenset[str]
    attrs: dict[str, list[Any]]

    @property
    def enabled(self) -> bool:
        return DISABLED_GROUP not in self.groups

    @property
    def personal_sync(self) -> bool:
        resolved = _resolve_syncthing_capability()
        if resolved is None:
            return False
        service, capability = resolved
        return application_capability_allowed(set(self.groups), service, capability)


@dataclass(frozen=True)
class Group:
    gid: str
    name: str
    members: tuple[str, ...]
    attrs: dict[str, list[Any]]


@dataclass(frozen=True)
class IdentityModel:
    users: tuple[User, ...]
    groups: tuple[Group, ...]
    administrators: tuple[str, ...]


def attrs_map(raw: Any) -> dict[str, list[Any]]:
    if not isinstance(raw, Mapping):
        return {}
    result: dict[str, list[Any]] = {}
    for name, value in raw.items():
        result[str(name)] = value if isinstance(value, list) else [value]
    return result


def validate_uid(uid: str) -> str:
    if not isinstance(uid, str):
        raise SyncError("Authentik username must be a string")
    try:
        return validate_username(uid)
    except DeviceError as exc:
        raise SyncError(f"Authentik username {uid!r} is not safe for a managed folder ID") from exc


def group_names(raw: Mapping[str, Any], groups_by_pk: Mapping[str, str]) -> set[str]:
    output: set[str] = set()
    groups = raw.get("groups_obj") if isinstance(raw.get("groups_obj"), list) else raw.get("groups")
    if not isinstance(groups, list):
        return output
    for group in groups:
        if isinstance(group, Mapping):
            if isinstance(group.get("name"), str):
                output.add(str(group["name"]))
                continue
            group_pk = group.get("pk", group.get("num_pk"))
            if group_pk is not None and str(group_pk) in groups_by_pk:
                output.add(groups_by_pk[str(group_pk)])
        elif str(group) in groups_by_pk:
            output.add(groups_by_pk[str(group)])
    return output


def build_model(data: Mapping[str, Any]) -> IdentityModel:
    raw_groups = [item for item in data.get("groups", []) if isinstance(item, Mapping)]
    raw_users = [item for item in data.get("users", []) if isinstance(item, Mapping)]
    groups_by_pk = {
        str(item.get("pk")): str(item.get("name"))
        for item in raw_groups
        if item.get("pk") is not None and isinstance(item.get("name"), str)
    }
    usernames_by_pk = {
        str(item.get("pk")): str(item.get("username"))
        for item in raw_users
        if item.get("pk") is not None and isinstance(item.get("username"), str)
    }

    explicit_groups_by_uid: dict[str, set[str]] = {}
    for raw_group in raw_groups:
        group_name = raw_group.get("name")
        if not isinstance(group_name, str):
            continue
        raw_members = (
            raw_group.get("users_obj") if isinstance(raw_group.get("users_obj"), list) else raw_group.get("users")
        )
        if not isinstance(raw_members, list):
            continue
        for member in raw_members:
            if isinstance(member, Mapping):
                username = member.get("username")
                if not isinstance(username, str):
                    member_pk = member.get("pk", member.get("num_pk"))
                    username = usernames_by_pk.get(str(member_pk))
            else:
                username = usernames_by_pk.get(str(member))
            if isinstance(username, str):
                explicit_groups_by_uid.setdefault(username, set()).add(group_name)

    users: list[User] = []
    for raw in raw_users:
        username = raw.get("username")
        if not isinstance(username, str):
            continue
        uid = validate_uid(username)
        user_groups = group_names(raw, groups_by_pk)
        user_groups.update(explicit_groups_by_uid.get(uid, set()))
        if raw.get("is_active") is not True:
            user_groups.add(DISABLED_GROUP)
        user = User(
            uid,
            str(raw.get("email") or f"{uid}@invalid.local"),
            str(raw.get("name") or uid),
            frozenset(user_groups),
            attrs_map(raw.get("attributes")),
        )
        if user.enabled:
            users.append(user)

    by_uid = {user.uid: user for user in users}
    inferred: dict[str, set[str]] = {name: set() for name in groups_by_pk.values()}
    for user in users:
        for name in user.groups:
            inferred.setdefault(name, set()).add(user.uid)

    groups: list[Group] = []
    for raw in raw_groups:
        name = str(raw.get("name") or "")
        if not name:
            continue
        members = set(inferred.get(name, set()))
        raw_members = raw.get("users_obj") if isinstance(raw.get("users_obj"), list) else raw.get("users")
        if isinstance(raw_members, list):
            for member in raw_members:
                if isinstance(member, Mapping):
                    username = member.get("username")
                    if not isinstance(username, str):
                        member_pk = member.get("pk", member.get("num_pk"))
                        username = usernames_by_pk.get(str(member_pk))
                else:
                    username = usernames_by_pk.get(str(member))
                if isinstance(username, str) and username in by_uid:
                    members.add(username)
        groups.append(
            Group(
                str(raw.get("pk") or name),
                name,
                tuple(sorted(members)),
                attrs_map(raw.get("attributes")),
            )
        )

    administrators = tuple(sorted(user.uid for user in users if ADMIN_GROUP in user.groups))
    if not administrators:
        raise SyncError(
            f"No enabled members of {ADMIN_GROUP} were found. Authentik superuser status "
            "alone is not sufficient: add at least one enabled user, normally akadmin, "
            f"explicitly to the {ADMIN_GROUP} group."
        )
    return IdentityModel(
        tuple(sorted(users, key=lambda item: item.uid)),
        tuple(sorted(groups, key=lambda item: item.name)),
        administrators,
    )


def capability_status(model: IdentityModel) -> dict[str, Any]:
    """Report Authentik-owned V2 application assignments without re-evaluating policy."""
    users: list[dict[str, Any]] = []
    for user in model.users:
        assigned = sorted(group for group in user.groups if group.startswith(APPLICATION_GROUP_PREFIX))
        users.append(
            {
                "id": user.uid,
                "displayName": user.display_name,
                "email": user.email,
                "administrator": ADMIN_GROUP in user.groups,
                "administratorBypass": ADMIN_GROUP in user.groups,
                "groups": sorted(user.groups),
                "capabilities": {group: {"allowed": True, "source": "authentik-assignment"} for group in assigned},
                "assignedApplicationCapabilities": assigned,
            }
        )
    return {
        "identityProvider": "Authentik",
        "capabilityModel": "managed-services-v2",
        "managementUrl": "/identity/if/user/",
        "users": users,
    }


def user_device_values(user: User) -> list[Any]:
    return user.attrs.get("nasSyncthingDevices", user.attrs.get("nasSyncthingDevice", []))


def desired_syncthing(
    model: IdentityModel, share_root: pathlib.Path
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    devices: dict[str, dict[str, Any]] = {}
    folders: dict[str, dict[str, Any]] = {}
    for user in model.users:
        if not user.personal_sync:
            continue
        try:
            user_devices = normalize_devices(user_device_values(user))
        except DeviceError as exc:
            raise SyncError(f"Invalid Syncthing devices for {user.uid}: {exc}") from exc
        if not user_devices:
            continue
        for device in user_devices:
            device = {**device, "numConnections": 1}
            existing = devices.get(device["deviceID"])
            if existing is not None and existing != device:
                raise SyncError(f"Syncthing device {device['deviceID']} has conflicting Authentik definitions")
            devices[device["deviceID"]] = device
        folder_id = f"nas-{user.uid}-backup"
        folders[folder_id] = {
            "id": folder_id,
            "label": f"{user.display_name} Backup",
            "path": str(share_root / "users" / user.uid / "syncthing"),
            "type": "receiveonly",
            "devices": [{"deviceID": device["deviceID"]} for device in user_devices],
            "ignorePerms": True,
            "fsWatcherEnabled": True,
            "rescanIntervalS": 3600,
            "pullerMaxPendingKiB": 16384,
            "scanProgressIntervalS": -1,
            "weakHashThresholdPct": 101,
            "versioning": {"type": "staggered", "params": {"cleanInterval": "3600", "maxAge": "31536000"}},
        }
    return folders, devices


def model_status(model: IdentityModel) -> dict[str, Any]:
    return {
        "identityProvider": "Authentik",
        "shareAuthority": "CopyParty",
        "capabilityModel": "managed-services-v2",
        "users": [user.uid for user in model.users],
        "groups": [group.name for group in model.groups],
        "administrators": list(model.administrators),
        "syncthingUsers": [user.uid for user in model.users if user.personal_sync and user_device_values(user)],
    }


def normalized_account_plan(raw: Any, index: int) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise SyncError(f"accounts[{index}] must be an object")
    unknown = sorted(
        str(key)
        for key in raw
        if key not in {"username", "name", "email", "active", "groups", "attributes", "password"}
    )
    if unknown:
        raise SyncError(f"accounts[{index}] contains unknown field(s): {', '.join(unknown)}")
    username_raw = raw.get("username")
    if not isinstance(username_raw, str):
        raise SyncError(f"accounts[{index}].username must be a string")
    username = validate_uid(username_raw)
    if username == "akadmin":
        raise SyncError("akadmin is the Authentik bootstrap account and cannot be managed by account plans")
    name = raw.get("name", username)
    email = raw.get("email", f"{username}@invalid.local")
    active = raw.get("active", True)
    if not isinstance(name, str) or not name.strip():
        raise SyncError(f"accounts[{index}].name must be a non-empty string")
    if not isinstance(email, str) or not email.strip():
        raise SyncError(f"accounts[{index}].email must be a non-empty string")
    if not isinstance(active, bool):
        raise SyncError(f"accounts[{index}].active must be true or false")
    groups_raw = raw.get("groups", [USER_GROUP])
    if not isinstance(groups_raw, list) or not all(isinstance(item, str) for item in groups_raw):
        raise SyncError(f"accounts[{index}].groups must be a list of base identity roles")
    groups = {item.strip() for item in groups_raw if item.strip()}
    unknown = sorted(groups - set(RESERVED_GROUPS))
    if unknown:
        raise SyncError(
            f"accounts[{index}] contains non-role group(s): {', '.join(unknown)}; "
            "application capability assignments are Authentik-owned"
        )
    if active:
        groups.discard(DISABLED_GROUP)
        if not ({ADMIN_GROUP, GUEST_GROUP} & groups):
            groups.add(USER_GROUP)
    else:
        if ADMIN_GROUP in groups:
            raise SyncError(f"accounts[{index}] cannot disable an account while granting {ADMIN_GROUP}")
        groups = {DISABLED_GROUP}
    attrs = raw.get("attributes", {})
    if not isinstance(attrs, Mapping):
        raise SyncError(f"accounts[{index}].attributes must be an object")
    password = raw.get("password")
    if password is not None and (
        not isinstance(password, str)
        or not password
        or len(password) > 4096
        or "\x00" in password
        or "\n" in password
        or "\r" in password
    ):
        raise SyncError(f"accounts[{index}].password must contain exactly one non-empty line")
    return {
        "username": username,
        "name": name.strip(),
        "email": email.strip(),
        "active": active,
        "groups": sorted(groups),
        "attributes": dict(attrs),
        "password": password,
    }


def raw_group_pks(raw_user: Mapping[str, Any]) -> set[str]:
    groups = raw_user.get("groups")
    if not isinstance(groups, list):
        return set()
    output: set[str] = set()
    for group in groups:
        if isinstance(group, Mapping):
            key = group.get("pk", group.get("num_pk"))
        else:
            key = group
        if key is not None:
            output.add(str(key))
    return output


def user_detail_pk(raw_user: Mapping[str, Any]) -> int:
    key = raw_user.get("num_pk", raw_user.get("pk"))
    if isinstance(key, int):
        return key
    if isinstance(key, str) and key.isdigit():
        return int(key)
    raise SyncError(f"Authentik user {raw_user.get('username')!r} has no numeric primary key")


def enabled_administrator_names(
    users: Sequence[Mapping[str, Any]],
    groups: Sequence[Mapping[str, Any]],
) -> set[str]:
    usernames_by_pk = {
        str(item.get("pk", item.get("num_pk"))): str(item.get("username"))
        for item in users
        if item.get("pk", item.get("num_pk")) is not None
        and isinstance(item.get("username"), str)
        and item.get("is_active") is True
    }
    active_names = set(usernames_by_pk.values())
    admin_group = next((item for item in groups if item.get("name") == ADMIN_GROUP), None)
    if not isinstance(admin_group, Mapping):
        return set()
    admin_pk = admin_group.get("pk")
    administrators: set[str] = set()
    if admin_pk is not None:
        key = str(admin_pk)
        for user in users:
            username = user.get("username")
            if user.get("is_active") is True and isinstance(username, str) and key in raw_group_pks(user):
                administrators.add(username)
    raw_members = (
        admin_group.get("users_obj") if isinstance(admin_group.get("users_obj"), list) else admin_group.get("users")
    )
    if isinstance(raw_members, list):
        for member in raw_members:
            if isinstance(member, Mapping):
                username = member.get("username")
                if not isinstance(username, str):
                    member_pk = member.get("pk", member.get("num_pk"))
                    username = usernames_by_pk.get(str(member_pk))
            else:
                username = usernames_by_pk.get(str(member))
            if isinstance(username, str) and username in active_names:
                administrators.add(username)
    return administrators
