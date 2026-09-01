#!/usr/bin/env python3
"""First-run and account provisioning CLI for the NixOS NAS appliance.

This is a finite setup/orchestration command. It does not own application
lifecycle or authorization:

* KeePassXC and ``nas-secrets`` own machine and service secrets.
* ZFS helpers own managed storage validation and encryption.
* Authentik and ``nas-identity-sync`` own human identities and assignments.
* CopyParty owns share ACLs; setup only creates required backing directories.
* Managed Services V2 ``services.yaml`` owns mutable service lifecycle policy.

The setup JSON therefore contains only base identity roles and optional V2
service lifecycle modes. Application capability groups are assigned in
Authentik after V2 has ensured the corresponding
``application.<service>.<capability>`` objects.
"""

from __future__ import annotations

import argparse
import contextlib
import getpass
import hashlib
import hmac
import json
import os
import pathlib
import pwd
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from nas_common import ADMIN_GROUP, DISABLED_GROUP, GUEST_GROUP, USER_GROUP, run_command
from nas_operation_journal import JournalError, OperationJournal, atomic_write_json, load_json
from nas_operation_lock import (
    COORDINATION_TOKEN_ENV,
    OperationBusyError,
    acquire_operation,
    cancel_reservation,
    current_coordination_token,
)
from nas_setup_config import (
    SCHEMA_VERSION,
    SetupError,
    normalize_account,
    normalize_config,
    normalize_secret_line,
    read_password_file,
    read_secret_stdin,
)
from nas_syncthing_devices import DeviceError, validate_username

# Explicit setup application for first run. The wizard is served at /setup
# behind Authentik forward-auth as an explicit Authentik Application
# (nas-setup) so it is discoverable in the launcher during first run. After a
# successful first run the setup transaction removes both its mutable blueprint
# and application before retiring the one-time Authentik authority.
SETUP_APPLICATION_SLUG = "nas-setup"

BOOTSTRAP_ADMIN_USER = "akadmin"
# Kept as the pre-completion administrator identity for command callers that
# run before the operator-selected account has been persisted.
ADMIN_USER = BOOTSTRAP_ADMIN_USER
ADMIN_STATE_PATH = pathlib.Path(os.environ.get("NAS_ADMIN_STATE", "/var/lib/nas-setup/local-administrator.json"))
BOOTSTRAP_RUNTIME_ROOT = pathlib.Path(os.environ.get("NAS_BOOTSTRAP_RUNTIME_ROOT", "/var/lib/nas-control-plane"))
BOOTSTRAP_AUTHENTIK_ENVIRONMENT = BOOTSTRAP_RUNTIME_ROOT / "authentik/environment"
BOOTSTRAP_AUTHENTIK_TOKEN = BOOTSTRAP_RUNTIME_ROOT / "authentik/api-token"
SETUP_BLUEPRINT_PATH = BOOTSTRAP_RUNTIME_ROOT / "authentik/blueprints/nas-setup.yaml"
KEEPASS_DATABASE = pathlib.Path(
    os.environ.get("NAS_KEEPASS_DATABASE", "/var/lib/nas-control-plane/nas-secrets/NAS.kdbx")
)
KEEPASS_KEY_FILE = os.environ.get("NAS_KEEPASS_KEY_FILE", "")
ZFS_POOL = os.environ.get("NAS_ZFS_POOL", "tank")
ZFS_DATASET = os.environ.get("NAS_ZFS_DATASET", "tank/nas")
ZFS_ROOT = pathlib.Path(os.environ.get("NAS_ZFS_ROOT", "/tank"))
LOCAL_HOME_ROOT = ZFS_ROOT / "homes"
ZFS_ENCRYPTION = os.environ.get("NAS_ZFS_ENCRYPTION_ENABLE", "0") == "1"
SHARE_ROOT = pathlib.Path(os.environ.get("NAS_SHARE_ROOT", str(ZFS_ROOT / "shares")))
SYNCTHING_ENABLED = os.environ.get("NAS_SYNCTHING_ENABLE", "0") == "1"
STATE_PATH = pathlib.Path(os.environ.get("NAS_SETUP_STATE", "/var/lib/nas-setup/state.json"))
JOURNAL_PATH = pathlib.Path(os.environ.get("NAS_SETUP_JOURNAL", "/var/lib/nas-setup/first-run-journal.json"))
FIRST_START_STATUS_PATH = pathlib.Path(os.environ.get("NAS_FIRST_START_STATUS", "/var/lib/nas-first-start/status.json"))
MANAGED_SERVICES_CONTROL = os.environ.get("NAS_MANAGED_SERVICES_CONTROL", "nas-managed-services-control")
MANAGED_SERVICES_DESIRED = pathlib.Path(os.environ.get("NAS_V2_DESIRED", "/var/lib/nas-control/services.yaml"))
SETUP_OPERATION_CLASSES = (
    "appliance",
    "first-start",
    "identity",
    "runtime",
    "secrets",
    "state",
    "storage",
    "update",
)
FIRST_START_JOB_RETAIN_COUNT = max(1, int(os.environ.get("NAS_FIRST_START_JOB_RETAIN_COUNT", "20")))
FIRST_START_JOB_RETAIN_SECONDS = max(
    0, int(os.environ.get("NAS_FIRST_START_JOB_RETAIN_SECONDS", str(7 * 24 * 60 * 60)))
)
COMMAND_TIMEOUT_SECONDS = max(1.0, float(os.environ.get("NAS_SETUP_COMMAND_TIMEOUT_SECONDS", "900")))
COMMAND_MAX_OUTPUT_BYTES = max(4096, int(os.environ.get("NAS_SETUP_COMMAND_MAX_OUTPUT_BYTES", str(256 * 1024))))
INSTALLED_PREFLIGHT_ENV = {
    "NAS_PREFLIGHT_REQUIRE_COMPLETE": "0",
    "NAS_PREFLIGHT_SKIP_COCKPIT_BUNDLE": "1",
    "NAS_PREFLIGHT_SKIP_FUZZ": "1",
    "NAS_PREFLIGHT_SKIP_NIX": "1",
    "NAS_PREFLIGHT_SKIP_TESTS": "1",
    "NAS_PREFLIGHT_SKIP_TOOLING": "1",
    "NAS_PREFLIGHT_VERIFY_MANIFEST": "0",
}


def progress(message: str) -> None:
    print(f"nas-setup: {message}", file=sys.stderr, flush=True)


@dataclass(frozen=True)
class Completed:
    command: tuple[str, ...]
    stdout: str
    stderr: str
    returncode: int = 0


def run(
    command: Sequence[str],
    *,
    input_text: str | None = None,
    check: bool = True,
    capture: bool = True,
    env: Mapping[str, str] | None = None,
    timeout_seconds: float = COMMAND_TIMEOUT_SECONDS,
) -> Completed:
    cmd = tuple(str(item) for item in command)
    result = run_command(
        cmd,
        input_text=input_text,
        env=env,
        timeout_seconds=timeout_seconds,
        max_output_bytes=COMMAND_MAX_OUTPUT_BYTES,
        capture=capture,
    )
    if result.returncode == 124:
        raise SetupError(f"Command timed out after {timeout_seconds:g} seconds: {' '.join(cmd)}")
    if check and result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit status {result.returncode}"
        raise SetupError(f"Command failed: {' '.join(cmd)}: {detail}")
    return Completed(cmd, result.stdout, result.stderr, result.returncode)


def current_username() -> str:
    return pwd.getpwuid(os.geteuid()).pw_name


def local_administrator_username() -> str:
    try:
        value = load_json(ADMIN_STATE_PATH)
    except JournalError:
        return BOOTSTRAP_ADMIN_USER
    username = value.get("username") if isinstance(value, Mapping) else None
    if not isinstance(username, str):
        return BOOTSTRAP_ADMIN_USER
    try:
        return validate_username(username)
    except DeviceError:
        return BOOTSTRAP_ADMIN_USER


def admin_command(command: Sequence[str]) -> list[str]:
    administrator = local_administrator_username()
    current = current_username()
    if current == administrator:
        return [str(item) for item in command]
    if os.geteuid() == 0:
        try:
            home = pathlib.Path(pwd.getpwnam(administrator).pw_dir)
        except KeyError as exc:
            raise SetupError(f"Configured local administrator does not exist: {administrator}") from exc
        return [
            "runuser",
            "-u",
            administrator,
            "--",
            "env",
            f"--chdir={home}",
            f"HOME={home}",
            f"PATH={os.environ.get('PATH', '')}",
            *map(str, command),
        ]
    raise SetupError(f"Run nas-setup as {administrator} or root, not {current}")


def run_admin(command: Sequence[str], **kwargs: Any) -> Completed:
    return run(admin_command(command), **kwargs)


def run_interactive_privileged(command: Sequence[str], **kwargs: Any) -> Completed:
    if os.geteuid() == 0 and os.environ.get("NAS_SETUP_ALLOW_ROOT") == "1":
        return run(["env", f"--chdir={STATE_PATH.parent}", *map(str, command)], **kwargs)
    return run_admin(command, **kwargs)


def coordinated_child(command: Sequence[str]) -> list[str]:
    try:
        token = current_coordination_token()
    except RuntimeError as exc:
        raise SetupError("Nested mutation requested without an active appliance operation lock") from exc
    return ["env", f"{COORDINATION_TOKEN_ENV}={token}", *map(str, command)]


def run_root(command: Sequence[str], **kwargs: Any) -> Completed:
    if os.geteuid() == 0:
        return run(command, **kwargs)
    refresh = run(["sudo", "-n", "-v"], check=False)
    if refresh.returncode != 0:
        detail = refresh.stderr.strip() or "cached sudo authorization is unavailable"
        raise SetupError(f"Privileged setup authorization expired: {detail}")
    return run(["sudo", "-n", "--", *map(str, command)], **kwargs)


def run_root_noninteractive(command: Sequence[str], **kwargs: Any) -> Completed:
    if os.geteuid() == 0:
        return run(command, **kwargs)
    if current_username() != local_administrator_username():
        return Completed(
            tuple(map(str, command)), "", "privileged status requires the configured local administrator", 1
        )
    return run(["sudo", "-n", "--", *map(str, command)], **kwargs)


def require_setup_operator() -> None:
    current = current_username()
    if os.geteuid() == 0 and os.environ.get("NAS_SETUP_ALLOW_ROOT") == "1":
        progress("using Cockpit-authorized root setup execution")
        return
    administrator = local_administrator_username()
    if current != administrator:
        raise SetupError(
            f"Run mutating nas-setup commands as the configured local administrator {administrator!r}, not {current!r}."
        )
    progress("validating local administrator sudo authorization")
    run(["sudo", "-v"], capture=False)


@contextlib.contextmanager
def maintained_sudo_authorization() -> Iterator[None]:
    require_setup_operator()
    if os.geteuid() == 0:
        yield
        return
    stop = threading.Event()

    def refresh() -> None:
        while not stop.wait(30):
            if run(["sudo", "-n", "-v"], check=False).returncode != 0:
                progress("warning: unable to refresh cached sudo authorization")
                return

    worker = threading.Thread(target=refresh, name="nas-setup-sudo-keepalive", daemon=True)
    worker.start()
    try:
        yield
    finally:
        stop.set()
        worker.join(timeout=2)


def read_json_source(source: str) -> dict[str, Any]:
    try:
        text = sys.stdin.read() if source == "-" else pathlib.Path(source).read_text(encoding="utf-8")
        value = json.loads(text)
    except (OSError, json.JSONDecodeError) as exc:
        raise SetupError(f"Unable to read setup JSON from {source}: {exc}") from exc
    if not isinstance(value, dict):
        raise SetupError("Setup JSON must contain one object")
    return value


def pool_exists() -> bool:
    return (
        subprocess.run(
            ["zpool", "list", "-H", ZFS_POOL],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=30,
        ).returncode
        == 0
    )


def dataset_exists() -> bool:
    return (
        subprocess.run(
            ["zfs", "list", "-H", ZFS_DATASET],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=30,
        ).returncode
        == 0
    )


def validate_storage_request(
    storage: Mapping[str, Any],
    confirmed_devices: Sequence[str] | None,
    allow_destructive: bool,
) -> None:
    if pool_exists():
        return
    if not storage.get("createPool"):
        raise SetupError(
            f"ZFS pool {ZFS_POOL} does not exist. Configure storage.createPool/devices or create/import it before setup."
        )
    devices = [str(item) for item in storage.get("devices", [])]
    confirmed = [str(item) for item in (confirmed_devices or [])]
    if sorted(confirmed) != sorted(devices) or len(confirmed) != len(devices):
        raise SetupError(
            "Refusing to create the pool: repeat --confirm-storage-device once for every configured storage.devices path"
        )
    if not allow_destructive:
        raise SetupError("Creating a new ZFS pool requires --allow-destructive-storage")
    missing: list[str] = []
    not_block: list[str] = []
    underlying: dict[int, str] = {}
    aliases: list[str] = []
    for device in devices:
        try:
            info = os.stat(device)
        except FileNotFoundError:
            missing.append(device)
            continue
        except OSError as exc:
            raise SetupError(f"Unable to inspect configured storage device {device}: {exc}") from exc
        if not stat.S_ISBLK(info.st_mode):
            not_block.append(device)
            continue
        previous = underlying.get(info.st_rdev)
        if previous is not None:
            aliases.append(f"{previous} and {device}")
        else:
            underlying[info.st_rdev] = device
    if missing:
        raise SetupError(f"Configured storage device(s) do not exist: {', '.join(missing)}")
    if not_block:
        raise SetupError(f"Configured storage path(s) are not block devices: {', '.join(not_block)}")
    if aliases:
        raise SetupError(f"Multiple configured paths refer to the same block device: {', '.join(aliases)}")


def _managed_services_status(*, noninteractive: bool = False) -> dict[str, Any]:
    runner = run_root_noninteractive if noninteractive else run_root
    completed = runner([MANAGED_SERVICES_CONTROL, "status"], check=False)
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or f"exit status {completed.returncode}"
        raise SetupError(f"Managed Services V2 status failed: {detail}")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise SetupError("Managed Services V2 status returned invalid JSON") from exc
    if not isinstance(value, dict) or not isinstance(value.get("services"), list):
        raise SetupError("Managed Services V2 status has no service catalog")
    return value


def validate_service_request(services: Mapping[str, str]) -> None:
    if not services:
        return
    status = _managed_services_status()
    rows = status["services"]
    by_id = {str(row.get("id")): row for row in rows if isinstance(row, Mapping) and isinstance(row.get("id"), str)}
    unknown = sorted(set(services) - set(by_id))
    if unknown:
        raise SetupError(f"Unknown configured Managed Services V2 service(s): {', '.join(unknown)}")
    for service_id, mode in services.items():
        row = by_id[service_id]
        allowed = row.get("allowedModes", [])
        if not isinstance(allowed, list) or mode not in allowed:
            raise SetupError(f"Managed Services V2 service {service_id} does not permit mode {mode}")
        if mode != "off" and row.get("available") is not True:
            raise SetupError(f"Managed Services V2 service {service_id} is unavailable on this host")


def identity_plan(config: Mapping[str, Any]) -> dict[str, Any]:
    accounts: list[dict[str, Any]] = []
    for account in config["accounts"]:
        item = {
            "username": account["username"],
            "name": account["name"],
            "email": account["email"],
            "active": account["active"],
            "groups": account["groups"],
            "attributes": account["attributes"],
        }
        if account.get("passwordFile"):
            item["password"] = read_password_file(account["passwordFile"], account["username"])
        accounts.append(item)
    return {
        "schemaVersion": 1,
        "accounts": accounts,
        "deactivateMissingManagedAccounts": config["deactivateMissingManagedAccounts"],
    }


def read_keepass_password(from_stdin: bool) -> str:
    if from_stdin:
        return read_secret_stdin("KeePass database password")
    return normalize_secret_line(getpass.getpass("KeePass database password: "), "KeePass database password")


def local_administrator_details(administrator: Mapping[str, Any]) -> dict[str, Any]:
    username = administrator.get("username")
    if not isinstance(username, str):
        raise SetupError("Administrator username is invalid")
    try:
        username = validate_username(username)
    except DeviceError as exc:
        raise SetupError(f"Administrator username is unsafe: {exc}") from exc
    if username == BOOTSTRAP_ADMIN_USER:
        raise SetupError("Administrator username is the reserved bootstrap identity")
    return {
        "username": username,
        "name": str(administrator.get("name", username)),
        "email": str(administrator.get("email", f"{username}@invalid.local")),
        "active": True,
        "groups": [ADMIN_GROUP],
        "attributes": {},
    }


def create_local_administrator(administrator: Mapping[str, Any], password: str) -> dict[str, Any]:
    details = local_administrator_details(administrator)
    username = details["username"]
    password = normalize_secret_line(password, "Administrator password")
    if ":" in password:
        raise SetupError("Administrator password must not contain a colon")

    expected_home = LOCAL_HOME_ROOT / username
    existing = run_root(["id", "--user", username], check=False)
    if existing.returncode != 0:
        run_root(
            [
                "useradd",
                "--home-dir",
                str(expected_home),
                "--no-create-home",
                "--shell",
                "/run/current-system/sw/bin/bash",
                username,
            ]
        )
    account = pwd.getpwnam(username)
    home = pathlib.Path(account.pw_dir)
    if home != expected_home:
        raise SetupError(f"Administrator home directory is not ZFS-backed: {home}")
    run_root(["install", "-d", "-m", "0711", "-o", "root", "-g", "root", str(LOCAL_HOME_ROOT)])
    run_root(
        [
            "install",
            "-d",
            "-m",
            "0700",
            "-o",
            str(account.pw_uid),
            "-g",
            str(account.pw_gid),
            str(home),
        ]
    )
    run_root(["chpasswd"], input_text=f"{username}:{password}\n")
    run_root(["usermod", "--append", "--groups", "wheel,nas-administrators,nas-operations", username])
    return details


def configured_administrator(account_plan: Mapping[str, Any]) -> Mapping[str, Any] | None:
    candidates = [
        account
        for account in account_plan.get("accounts", [])
        if isinstance(account, Mapping)
        and account.get("active") is True
        and ADMIN_GROUP in account.get("groups", [])
        and isinstance(account.get("password"), str)
    ]
    return candidates[0] if len(candidates) == 1 else None


def include_local_administrator(account_plan: dict[str, Any], administrator: Mapping[str, Any], password: str) -> None:
    local = {**administrator, "password": password}
    accounts = account_plan["accounts"]
    for index, account in enumerate(accounts):
        if account.get("username") == administrator["username"]:
            accounts[index] = local
            return
    accounts.append(local)


def finalize_local_administrator(administrator: Mapping[str, Any]) -> dict[str, str]:
    username = administrator.get("username")
    if not isinstance(username, str):
        raise SetupError("Administrator username is invalid")
    try:
        username = validate_username(username)
    except DeviceError as exc:
        raise SetupError(f"Administrator username is unsafe: {exc}") from exc
    value = {"username": username}
    run_root(["chown", f"{username}:users", str(KEEPASS_DATABASE.parent)])
    if KEEPASS_DATABASE.exists():
        run_root(["chown", f"{username}:users", str(KEEPASS_DATABASE)])
    atomic_write_json(ADMIN_STATE_PATH, value, mode=0o600)
    if username != BOOTSTRAP_ADMIN_USER:
        existing = run_root(["id", "--user", BOOTSTRAP_ADMIN_USER], check=False)
        if existing.returncode == 0:
            run_root(
                [
                    "systemd-run",
                    "--wait",
                    "--pipe",
                    "--collect",
                    "--quiet",
                    "--unit",
                    "nas-bootstrap-account-retirement.service",
                    "--property=Type=oneshot",
                    "--property=User=root",
                    "--property=Group=root",
                    "--property=UMask=0077",
                    "--property=NoNewPrivileges=yes",
                    "--property=PrivateTmp=yes",
                    "--property=ProtectSystem=yes",
                    "--property=ProtectHome=read-only",
                    "--",
                    "userdel",
                    BOOTSTRAP_ADMIN_USER,
                ]
            )
        run_root(
            [
                "systemd-run",
                "--wait",
                "--pipe",
                "--collect",
                "--quiet",
                "--unit",
                "nas-bootstrap-home-retirement.service",
                "--property=Type=oneshot",
                "--property=User=root",
                "--property=Group=root",
                "--property=UMask=0077",
                "--property=NoNewPrivileges=yes",
                "--property=PrivateTmp=yes",
                "--property=ProtectSystem=yes",
                "--property=ProtectHome=no",
                "--property=ReadWritePaths=/home",
                "--",
                "rm",
                "--recursive",
                "--force",
                "--one-file-system",
                "--",
                f"/home/{BOOTSTRAP_ADMIN_USER}",
            ]
        )
    return value


def provision_local_administrator(administrator: Mapping[str, Any], password: str) -> dict[str, Any]:
    return create_local_administrator(administrator, password)


def local_administrator_ready(administrator: Mapping[str, Any]) -> bool:
    username = administrator.get("username")
    if not isinstance(username, str) or local_administrator_username() != username:
        return False
    try:
        account = pwd.getpwnam(username)
    except KeyError:
        return False
    home = pathlib.Path(account.pw_dir)
    if home != LOCAL_HOME_ROOT / username or not home.is_dir():
        return False
    return True


def regenerate_boot_identity_databases(control_root: pathlib.Path) -> dict[str, bool]:
    """Replace all temporary identity state without touching KeePass or ZFS."""
    authentik_root = control_root / "authentik"
    postgresql_root = control_root / "postgresql"
    run_root(
        [
            "systemctl",
            "stop",
            "nas-authentik-proxy-outpost.service",
            "nas-identity-bootstrap.service",
            "authentik.service",
            "authentik-worker.service",
            "authentik-migrate.service",
            "postgresql.service",
            "nas-bootstrap-runtime-select.service",
            "nas-bootstrap-authentik-secrets.service",
        ]
    )
    for path in (authentik_root, postgresql_root):
        if path.is_dir() and not path.is_symlink():
            run_root(["find", str(path), "-mindepth", "1", "-delete"])
    run_root(
        [
            "systemctl",
            "reset-failed",
            "postgresql.service",
            "authentik-migrate.service",
            "authentik-worker.service",
            "authentik.service",
        ]
    )
    run_root(["systemctl", "start", "nas-bootstrap-authentik-secrets.service"])
    run_root(["systemctl", "start", "nas-bootstrap-runtime-select.service"])
    return {"regenerated": True, "bootSide": True}


def retire_bootstrap_runtime(
    bootstrap_root: pathlib.Path, administrator: str, keepass_password: str
) -> dict[str, bool]:
    run_root(coordinated_child(["nas-identity-sync", "retire-bootstrap", administrator]))
    run_admin(
        coordinated_child(["nas-secrets", "retire-authentik-bootstrap-stdin"]),
        input_text=keepass_password + "\n",
    )
    # Keep the boot-side control-plane databases intact. Only remove the
    # one-time Authentik environment values before activation can restart
    # Authentik and recreate akadmin from them.
    run_root(
        [
            "sed",
            "--in-place",
            "/^AUTHENTIK_BOOTSTRAP_/d",
            str(bootstrap_root / "authentik/environment"),
        ]
    )
    run_interactive_privileged(coordinated_child(["nas-secrets", "activate-stdin"]), input_text=keepass_password + "\n")
    return {"bootstrapRetired": True}


def verify_or_create_database(password: str, create: bool) -> str:
    key_args = ["--key-file", KEEPASS_KEY_FILE] if KEEPASS_KEY_FILE else []
    run_root(
        [
            "install",
            "-d",
            "-m",
            "0700",
            "-o",
            local_administrator_username(),
            "-g",
            "users",
            str(KEEPASS_DATABASE.parent),
        ]
    )
    if KEEPASS_DATABASE.exists():
        run_admin(
            ["keepassxc-cli", "db-info", "--quiet", "--pw-stdin", *key_args, str(KEEPASS_DATABASE)],
            input_text=password + "\n",
        )
        return "existing"
    if not create:
        raise SetupError(f"KeePass database does not exist: {KEEPASS_DATABASE}")
    create_args = ["keepassxc-cli", "db-create", "--quiet", "--set-password"]
    if KEEPASS_KEY_FILE:
        create_args.extend(["--set-key-file", KEEPASS_KEY_FILE])
    create_args.append(str(KEEPASS_DATABASE))
    run_admin(create_args, input_text=f"{password}\n{password}\n")
    if not KEEPASS_DATABASE.exists():
        raise SetupError(f"KeePassXC did not create {KEEPASS_DATABASE}")
    return "created"


def setup_storage(
    storage: Mapping[str, Any],
    *,
    keepass_password: str,
    confirmed_devices: Sequence[str] | None,
    allow_destructive: bool,
    encrypt_storage: bool | None = None,
) -> dict[str, Any]:
    if encrypt_storage is None:
        encrypt_storage = ZFS_ENCRYPTION
    created_pool = False
    created_dataset = False
    devices = [str(item) for item in storage.get("devices", [])]
    topology = str(storage.get("topology", "single"))
    ashift = int(storage.get("ashift", 12))
    if not pool_exists():
        validate_storage_request(storage, confirmed_devices, allow_destructive)
        if storage.get("wipeDevices"):
            for device in devices:
                run_root(["wipefs", "--all", "--force", device])
        vdev = devices if topology in {"single", "stripe"} else [topology, *devices]
        zpool_create = [
            "zpool",
            "create",
            "-f",
            "-o",
            f"ashift={ashift}",
            "-O",
            "compression=zstd",
            "-O",
            "atime=off",
            "-O",
            "xattr=sa",
            "-O",
            "acltype=posixacl",
            "-O",
            "mountpoint=none",
            "-m",
            "none",
            ZFS_POOL,
            *vdev,
        ]
        run_storage_host(zpool_create)
        run_root(["zpool", "set", "autotrim=on", ZFS_POOL])
        created_pool = True
    if not dataset_exists():
        if encrypt_storage:
            run_storage_host(["nas-zfs-create-encrypted-dataset"], input_text=keepass_password + "\n")
        else:
            run_storage_host(["zfs", "create", "-o", f"mountpoint={ZFS_ROOT}", ZFS_DATASET])
        created_dataset = True
    else:
        encryption = run_storage_host(["zfs", "get", "-H", "-o", "value", "encryption", ZFS_DATASET]).stdout.strip()
        existing_encrypted = encryption != "off"
        if existing_encrypted != encrypt_storage:
            raise SetupError("The existing managed ZFS dataset does not match the encryption choice reviewed in setup")
    if not encrypt_storage:
        run_storage_host(["zfs", "mount", ZFS_DATASET], check=False)
        run_storage_host(["nas-zfs-mount-check"])
    creation_request = None
    if storage.get("createPool"):
        creation_request = {
            "topology": topology,
            "devices": devices,
            "ashift": ashift,
            "wipeDevices": bool(storage.get("wipeDevices")),
        }
    return {
        "pool": ZFS_POOL,
        "dataset": ZFS_DATASET,
        "root": str(ZFS_ROOT),
        "creationRequest": creation_request,
        "createdPool": created_pool,
        "createdDataset": created_dataset,
        "encrypted": encrypt_storage,
    }


def prepare_storage_runtime(keepass_password: str, encrypt_storage: bool | None = None) -> dict[str, bool]:
    if encrypt_storage is None:
        encrypt_storage = ZFS_ENCRYPTION
    if encrypt_storage:
        run_interactive_privileged(
            coordinated_child(["nas-secrets", "activate-stdin"]),
            input_text=keepass_password + "\n",
        )
    run_storage_host(["nas-zfs-mount-check"])
    run_storage_host(["systemd-tmpfiles", "--create", "--graceful"])
    # The initial seed runs before the new ZFS mount exists and is hidden by
    # that mount. Re-run it against the permanent data root before any managed
    # service reconciliation can observe a missing desired-state authority.
    run_root(["systemctl", "restart", "nas-managed-services-seed.service"])
    return {"mounted": True, "runtimeDirectoriesPrepared": True}


def storage_runtime_ready(_result: Any = None) -> bool:
    return storage_ready() and (ZFS_ROOT / "nas-control").is_dir() and MANAGED_SERVICES_DESIRED.is_file()


def run_storage_host(
    command: Sequence[str],
    *,
    input_text: str | None = None,
    check: bool = True,
) -> Completed:
    return run_root(
        [
            "systemd-run",
            "--quiet",
            "--wait",
            "--collect",
            "--pipe",
            "--unit",
            f"nas-storage-host-{secrets.token_hex(8)}.service",
            "--property=Type=exec",
            "--property=User=root",
            "--property=Group=root",
            "--property=UMask=0077",
            "--property=NoNewPrivileges=yes",
            "--property=PrivateDevices=no",
            "--property=DevicePolicy=auto",
            "--setenv=NAS_SETUP_ALLOW_ROOT=1",
            "--",
            *command,
        ],
        input_text=input_text,
        check=check,
    )


def apply_accounts(plan: Mapping[str, Any], *, confirm_password_reapply: bool = False) -> dict[str, Any]:
    command = coordinated_child(["nas-identity-sync", "apply-accounts", "-"])
    if confirm_password_reapply:
        command.append("--confirm-password-reapply")
    result = run_root(command, input_text=json.dumps(plan) + "\n")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise SetupError("nas-identity-sync returned invalid account JSON") from exc
    if not isinstance(value, dict):
        raise SetupError("nas-identity-sync returned an invalid account result")
    return value


def provision_share_directories(accounts: Sequence[Mapping[str, Any]]) -> list[str]:
    """Prepare backing directories independently of Authentik app assignments."""
    run_root(["install", "-d", "-m", "2770", "-o", "copyparty", "-g", "copyparty", str(SHARE_ROOT)])
    users_root = SHARE_ROOT / "users"
    run_root(["install", "-d", "-m", "2770", "-o", "copyparty", "-g", "copyparty", str(users_root)])
    created: list[str] = []
    for account in accounts:
        groups = set(account.get("groups", []))
        if account.get("active") is True and GUEST_GROUP not in groups:
            path = users_root / str(account["username"])
            run_root(["install", "-d", "-m", "2770", "-o", "copyparty", "-g", "copyparty", str(path)])
            created.append(str(path))
    return created


def apply_services(services: Mapping[str, str]) -> dict[str, str]:
    if services:
        run_root(
            coordinated_child([MANAGED_SERVICES_CONTROL, "set-many", "-"]),
            input_text=json.dumps(dict(services), sort_keys=True) + "\n",
        )
    return dict(services)


def write_state(report: Mapping[str, Any]) -> None:
    safe_report = json.loads(json.dumps(report))
    safe_report.pop("password", None)
    payload = json.dumps(safe_report, indent=2, sort_keys=True) + "\n"
    # The administrator-owned setup process must be able to resume and finish
    # its journal after this state write. Keep the directory's wheel-group
    # write bit aligned with the declared first-run authority policy.
    run_root(["install", "-d", "-m", "0770", "-o", "root", "-g", "wheel", str(STATE_PATH.parent)])
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
        handle.write(payload)
        temp_path = pathlib.Path(handle.name)
    try:
        run_root(["install", "-m", "0640", "-o", "root", "-g", "wheel", str(temp_path), str(STATE_PATH)])
    finally:
        temp_path.unlink(missing_ok=True)


def password_input_authenticators(account_plan: Mapping[str, Any], keepass_password: str) -> dict[str, str]:
    key = hashlib.sha256(b"nixos-nas/setup-password-fingerprint/v2\0" + keepass_password.encode("utf-8")).digest()
    authenticators: dict[str, str] = {}
    accounts = account_plan.get("accounts", [])
    if not isinstance(accounts, Sequence):
        raise SetupError("Account plan is invalid")
    for account in accounts:
        if not isinstance(account, Mapping):
            raise SetupError("Account plan is invalid")
        password = account.get("password")
        if not isinstance(password, str):
            continue
        username = str(account.get("username", ""))
        payload = username.encode("utf-8") + b"\0" + password.encode("utf-8")
        authenticators[username] = hmac.new(key, payload, hashlib.sha256).hexdigest()
    return authenticators


def canonical_setup_plan(config: Mapping[str, Any]) -> dict[str, Any]:
    accounts = []
    for account in config.get("accounts", []):
        if not isinstance(account, Mapping):
            continue
        accounts.append(
            {
                "username": account.get("username"),
                "name": account.get("name"),
                "email": account.get("email"),
                "active": account.get("active"),
                "groups": list(account.get("groups", [])),
                "attributes": dict(account.get("attributes", {})),
                "passwordInput": bool(account.get("passwordFile")),
            }
        )
    return {
        "schemaVersion": SCHEMA_VERSION,
        "storage": {
            "pool": ZFS_POOL,
            "dataset": ZFS_DATASET,
            "root": str(ZFS_ROOT),
            "encryption": ZFS_ENCRYPTION,
            **dict(config.get("storage", {})),
        },
        "accounts": accounts,
        "deactivateMissingManagedAccounts": bool(config.get("deactivateMissingManagedAccounts")),
        "services": dict(config.get("services", {})),
        "runPreflight": bool(config.get("runPreflight")),
    }


def setup_plan_digest(config: Mapping[str, Any]) -> str:
    payload = json.dumps(canonical_setup_plan(config), sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def require_confirmed_plan(config: Mapping[str, Any], supplied: str | None) -> str:
    expected = setup_plan_digest(config)
    if not supplied or not secrets.compare_digest(supplied, expected):
        raise SetupError(
            "The confirmed first-start plan digest no longer matches the normalized configuration; refresh Cockpit and review it again"
        )
    return expected


def setup_fingerprint(
    config: Mapping[str, Any],
    args: argparse.Namespace,
    account_plan: Mapping[str, Any],
    keepass_password: str,
) -> str:
    value = {
        "schemaVersion": SCHEMA_VERSION,
        "config": config,
        "planDigest": setup_plan_digest(config),
        "passwordInputAuthenticators": password_input_authenticators(account_plan, keepass_password),
        "createDatabase": bool(args.create_database),
        "confirmedStorageDevices": sorted(str(item) for item in args.confirm_storage_device),
        "allowDestructiveStorage": bool(args.allow_destructive_storage),
        "encryptStorage": bool(getattr(args, "encrypt_storage", ZFS_ENCRYPTION)),
        "skipPreflight": bool(args.skip_preflight),
    }
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _remove_setup_application() -> dict[str, Any]:
    """Remove the one-time setup application before bootstrap authority retirement."""
    try:
        SETUP_BLUEPRINT_PATH.unlink(missing_ok=True)
    except OSError as exc:
        raise SetupError("Unable to remove the mutable Authentik setup blueprint") from exc
    token_path = pathlib.Path(
        os.environ.get("NAS_AUTHENTIK_BOOTSTRAP_TOKEN_FILE", "/run/nas-secrets/authentik/bootstrap-token")
    )
    try:
        token = token_path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise SetupError("Authentik bootstrap token is unavailable for setup application retirement") from exc
    if not token:
        raise SetupError("Authentik bootstrap token is empty during setup application retirement")

    # Authentik listens on 127.0.0.1:9000 with the configured path prefix.
    # Try both the canonical and the bare API path for robustness across
    # generations.
    import urllib.error
    import urllib.request

    bases = [
        "http://127.0.0.1:9000/identity/api/v3",
        "http://127.0.0.1:9000/api/v3",
    ]
    last_error: str | None = None
    for base in bases:
        url = f"{base}/core/applications/{SETUP_APPLICATION_SLUG}/"
        request = urllib.request.Request(url, method="DELETE", headers={"Authorization": f"Bearer {token}"})
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                # 204 No Content on successful deletion, 200 is also treated as success.
                if response.status in (200, 201, 202, 204):
                    return {"removed": True, "slug": SETUP_APPLICATION_SLUG}
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return {"removed": False, "reason": "not-found"}
            last_error = f"HTTP {exc.code}"
            continue
        except OSError as exc:
            last_error = str(exc)
            continue
    raise SetupError(f"Unable to retire the Authentik setup application: {last_error or 'unknown error'}")


def install_runtime_identity_token(keepass_password: str) -> dict[str, Any]:
    completed = run_root(coordinated_child(["nas-identity-sync", "bootstrap-runtime-token"]))
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise SetupError("nas-identity-sync returned invalid runtime-token JSON") from exc
    if not isinstance(value, dict) or not isinstance(value.get("token"), str):
        raise SetupError("nas-identity-sync did not return a runtime identity token")
    token = value.pop("token")
    try:
        run_admin(
            coordinated_child(["nas-secrets", "set-authentik-token-stdin"]),
            input_text=f"{keepass_password}\n{token}\n",
        )
        run_root(
            ["install", "-m", "0400", "-o", "root", "-g", "root", "/dev/stdin", str(BOOTSTRAP_AUTHENTIK_TOKEN)],
            input_text=token,
        )
        run_interactive_privileged(
            coordinated_child(["nas-secrets", "activate-stdin"]), input_text=f"{keepass_password}\n"
        )
        return value
    finally:
        token = ""


def adopt_bootstrap_authentik_authority(keepass_password: str) -> dict[str, bool]:
    try:
        environment = BOOTSTRAP_AUTHENTIK_ENVIRONMENT.read_text(encoding="utf-8")
        token = BOOTSTRAP_AUTHENTIK_TOKEN.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise SetupError("The running first-boot Authentik authority is unavailable") from exc
    secret_key = ""
    for line in environment.splitlines():
        if line.startswith("AUTHENTIK_SECRET_KEY="):
            secret_key = line.partition("=")[2].strip()
            break
    if re.fullmatch(r"[0-9A-Fa-f]{128}", secret_key) is None:
        raise SetupError("The first-boot Authentik secret key is malformed")
    if re.fullmatch(r"[0-9A-Fa-f]{64}", token) is None:
        raise SetupError("The first-boot Authentik token is malformed")
    try:
        run_admin(
            coordinated_child(["nas-secrets", "adopt-authentik-bootstrap-stdin"]),
            input_text=f"{keepass_password}\n{secret_key}\n{token}\n",
        )
        if pathlib.Path("/run/nas-secrets/ready").is_file():
            run_interactive_privileged(
                coordinated_child(["nas-secrets", "activate-stdin"]), input_text=f"{keepass_password}\n"
            )
        return {"adopted": True}
    finally:
        secret_key = ""
        token = ""


def run_setup_stage(
    journal: OperationJournal,
    step: str,
    action: Any,
    *,
    manual_recovery_on_failure: bool = False,
    postcondition: Any | None = None,
) -> Any:
    if journal.step_complete(step):
        previous_result = journal.result(step)
        if postcondition is None or bool(postcondition(previous_result)):
            return previous_result
        journal.fail_step(
            step, "The completed step no longer satisfies its appliance postcondition", manual_recovery=True
        )
        raise SetupError(f"Completed setup step {step} no longer matches the appliance; explicit recovery is required")
    journal.start_step(step)
    try:
        result = action()
    except Exception as exc:
        journal.fail_step(step, str(exc), manual_recovery=manual_recovery_on_failure)
        raise
    journal.complete_step(step, result)
    return result


def keepass_database_ready(_result: Any = None) -> bool:
    try:
        mode = KEEPASS_DATABASE.lstat().st_mode
    except FileNotFoundError:
        return False
    return stat.S_ISREG(mode) and not stat.S_ISLNK(mode)


def storage_ready(_result: Any = None) -> bool:
    if not pool_exists() or not dataset_exists():
        return False
    try:
        return run_storage_host(["nas-zfs-mount-check"], check=False).returncode == 0
    except SetupError:
        return False


def reconcile_verified_storage_retry(
    fingerprints: Sequence[str], storage: Mapping[str, Any], encrypt_storage: bool | None = None
) -> str | None:
    if encrypt_storage is None:
        encrypt_storage = ZFS_ENCRYPTION
    if not storage_ready():
        return None
    existing = load_json(JOURNAL_PATH)
    if existing is None or not fingerprints:
        return None
    fingerprint = existing.get("fingerprint")
    if not isinstance(fingerprint, str) or not any(
        secrets.compare_digest(fingerprint, candidate) for candidate in fingerprints
    ):
        raise JournalError(f"A different first-run-v2 operation is incomplete; reconcile or clear {JOURNAL_PATH}")
    creation_request = None
    if storage.get("createPool"):
        creation_request = {
            "topology": str(storage.get("topology", "single")),
            "devices": [str(item) for item in storage.get("devices", [])],
            "ashift": int(storage.get("ashift", 12)),
            "wipeDevices": bool(storage.get("wipeDevices")),
        }
    result = {
        "pool": ZFS_POOL,
        "dataset": ZFS_DATASET,
        "root": str(ZFS_ROOT),
        "creationRequest": creation_request,
        "createdPool": bool(storage.get("createPool")),
        "createdDataset": True,
        "encrypted": encrypt_storage,
        "recoveredAfterVerification": True,
    }
    primary_fingerprint = fingerprints[0]
    if existing.get("status") == "manual-recovery-required" and existing.get("currentStep") == "storage":
        OperationJournal.complete_verified_recovery_step(
            JOURNAL_PATH,
            workflow="first-run-v2",
            fingerprint=fingerprint,
            step="storage",
            result=result,
            replacement_fingerprint=primary_fingerprint,
        )
        progress("verified the completed storage side effects and resumed the existing setup transaction")
        return primary_fingerprint
    storage_record = existing.get("steps", {}).get("storage")
    storage_result = storage_record.get("result") if isinstance(storage_record, Mapping) else None
    if (
        not secrets.compare_digest(fingerprint, primary_fingerprint)
        and isinstance(storage_record, Mapping)
        and storage_record.get("status") == "complete"
        and isinstance(storage_result, Mapping)
        and storage_result.get("createdPool") is True
    ):
        existing["fingerprint"] = primary_fingerprint
        journal = OperationJournal(JOURNAL_PATH, existing)
        journal.save()
        progress("updated the completed storage transaction for non-destructive retry")
        return primary_fingerprint
    return None


def protected_stack_ready(_result: Any = None) -> bool:
    if not pathlib.Path("/run/nas-secrets/ready").is_file():
        return False
    return (
        run_root_noninteractive(
            ["systemctl", "is-active", "--quiet", "nas-protected-services.target"], check=False
        ).returncode
        == 0
    )


def identity_command_ready(command: Sequence[str]) -> bool:
    completed = run_root_noninteractive(command, check=False)
    if completed.returncode != 0:
        return False
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return False
    return isinstance(value, Mapping) and not value.get("error")


def account_plan_ready(plan: Mapping[str, Any]) -> bool:
    for desired in plan.get("accounts", []):
        if not isinstance(desired, Mapping):
            return False
        completed = run_root_noninteractive(
            ["nas-identity-sync", "export-account", str(desired.get("username", ""))], check=False
        )
        if completed.returncode != 0:
            return False
        try:
            current = json.loads(completed.stdout)
        except json.JSONDecodeError:
            return False
        if not isinstance(current, Mapping):
            return False
        for field in ("username", "name", "email", "active"):
            if current.get(field) != desired.get(field):
                return False
        if sorted(current.get("groups", [])) != sorted(desired.get("groups", [])):
            return False
        current_attributes = current.get("attributes", {})
        desired_attributes = desired.get("attributes", {})
        if not isinstance(current_attributes, Mapping) or not isinstance(desired_attributes, Mapping):
            return False
        if any(current_attributes.get(key) != value for key, value in desired_attributes.items()):
            return False
    return True


def verification_ready(_result: Any = None) -> bool:
    storage = run_root_noninteractive(["nas-zfs-mount-check"], check=False)
    return storage.returncode == 0 and identity_command_ready(["nas-identity-sync", "status"])


def preflight_ready(_result: Any = None) -> bool:
    return run(["nas-preflight"], env=INSTALLED_PREFLIGHT_ENV, check=False).returncode == 0


def service_policy_ready(services: Mapping[str, str]) -> bool:
    try:
        status = _managed_services_status(noninteractive=True)
    except SetupError:
        return False
    rows = status.get("services", [])
    by_id = {row.get("id"): row for row in rows if isinstance(row, Mapping)}
    return all(by_id.get(service_id, {}).get("requestedMode") == mode for service_id, mode in services.items())


def share_directories_ready(accounts: Sequence[Mapping[str, Any]]) -> bool:
    def directory_is_safe(path: pathlib.Path) -> bool:
        if os.geteuid() == 0:
            try:
                mode = path.lstat().st_mode
            except FileNotFoundError:
                return False
            return stat.S_ISDIR(mode) and not stat.S_ISLNK(mode)
        completed = run_root_noninteractive(["stat", "-c", "%F", str(path)], check=False)
        return completed.returncode == 0 and completed.stdout.strip() == "directory"

    for account in accounts:
        groups = set(account.get("groups", []))
        if account.get("active") is not True or GUEST_GROUP in groups:
            continue
        path = SHARE_ROOT / "users" / str(account["username"])
        if not directory_is_safe(path):
            return False
    return True


def setup_state_matches(report: Mapping[str, Any]) -> bool:
    try:
        current = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return current == report


def _first_run_locked(args: argparse.Namespace) -> dict[str, Any]:
    args.encrypt_storage = bool(getattr(args, "encrypt_storage", ZFS_ENCRYPTION))
    if args.encrypt_storage and not ZFS_ENCRYPTION:
        raise SetupError("This system build does not include KeePassXC-backed ZFS encryption support")
    config = normalize_config(read_json_source(args.config))
    confirmed_plan_digest = require_confirmed_plan(config, getattr(args, "confirm_plan_digest", None))
    with maintained_sudo_authorization():
        validate_storage_request(config["storage"], args.confirm_storage_device, args.allow_destructive_storage)
        validate_service_request(config["services"])
        account_plan = identity_plan(config)
        password = ""
        started = int(time.time())
        try:
            password_override = getattr(args, "keepass_password_value", None)
            password = (
                password_override
                if isinstance(password_override, str) and password_override
                else read_keepass_password(args.keepass_password_stdin)
            )
            administrator = getattr(args, "administrator", None) or configured_administrator(account_plan)
            if not isinstance(administrator, Mapping):
                raise SetupError("First-run administrator details are missing")
            administrator_password_value = administrator.get("password")
            if not isinstance(administrator_password_value, str):
                raise SetupError("First-run administrator password is missing")
            administrator_password = str(administrator_password_value)
            local_administrator = local_administrator_details(administrator)
            include_local_administrator(account_plan, local_administrator, administrator_password)
            fingerprint = setup_fingerprint(config, args, account_plan, password)
            retry_args = argparse.Namespace(**vars(args))
            retry_args.allow_destructive_storage = not bool(args.allow_destructive_storage)
            compatible_fingerprints = (fingerprint, setup_fingerprint(config, retry_args, account_plan, password))
            fingerprint = (
                reconcile_verified_storage_retry(compatible_fingerprints, config["storage"], args.encrypt_storage)
                or fingerprint
            )
            journal = OperationJournal.open(
                JOURNAL_PATH,
                workflow="first-run-v2",
                fingerprint=fingerprint,
                metadata={
                    "configPath": str(pathlib.Path(args.config).resolve()),
                    "storagePool": ZFS_POOL,
                    "storageDataset": ZFS_DATASET,
                    "planDigest": confirmed_plan_digest,
                },
            )
            progress("verifying or creating the KeePassXC database")
            database_result = run_setup_stage(
                journal,
                "keepass-database",
                lambda: verify_or_create_database(password, args.create_database),
                postcondition=keepass_database_ready,
            )
            progress("initializing machine and service secrets")
            run_setup_stage(
                journal,
                "bootstrap-authentik-authority",
                lambda: adopt_bootstrap_authentik_authority(password),
            )
            run_setup_stage(
                journal,
                "secret-initialization",
                lambda: (
                    run_admin(coordinated_child(["nas-secrets", "init"]), input_text=password + "\n")
                    and {"initialized": True}
                ),
            )
            progress("creating or validating managed ZFS storage")
            pool_was_missing = not pool_exists()
            storage_result = run_setup_stage(
                journal,
                "storage",
                lambda: setup_storage(
                    config["storage"],
                    keepass_password=password,
                    confirmed_devices=args.confirm_storage_device,
                    allow_destructive=args.allow_destructive_storage,
                    encrypt_storage=args.encrypt_storage,
                ),
                manual_recovery_on_failure=pool_was_missing and args.allow_destructive_storage,
                postcondition=storage_ready,
            )
            run_setup_stage(
                journal,
                "storage-runtime-preparation",
                lambda: prepare_storage_runtime(password, args.encrypt_storage),
                postcondition=storage_runtime_ready,
            )
            progress("creating the permanent ZFS-backed recovery administrator")
            local_administrator = run_setup_stage(
                journal,
                "local-administrator",
                lambda: provision_local_administrator(administrator, administrator_password),
                postcondition=lambda result: isinstance(result, Mapping) and local_administrator_ready(result),
            )
            progress("rebuilding permanent boot-side Authentik and PostgreSQL databases")
            run_setup_stage(
                journal,
                "identity-database-regeneration",
                lambda: regenerate_boot_identity_databases(BOOTSTRAP_RUNTIME_ROOT),
                manual_recovery_on_failure=True,
                postcondition=lambda result: (
                    isinstance(result, Mapping)
                    and result.get("regenerated") is True
                    and BOOTSTRAP_AUTHENTIK_ENVIRONMENT.is_file()
                    and (BOOTSTRAP_RUNTIME_ROOT / "postgresql").is_dir()
                ),
            )
            run_setup_stage(
                journal,
                "permanent-authentik-authority",
                lambda: adopt_bootstrap_authentik_authority(password),
            )
            progress("activating protected services")
            run_setup_stage(
                journal,
                "protected-service-activation",
                lambda: (
                    run_interactive_privileged(
                        coordinated_child(["nas-secrets", "activate-stdin"]), input_text=password + "\n"
                    )
                    and {"active": True}
                ),
                postcondition=protected_stack_ready,
            )
            progress("bootstrapping Authentik base identity roles")
            bootstrap_result = run_setup_stage(
                journal,
                "identity-bootstrap",
                lambda: json.loads(run_root(coordinated_child(["nas-identity-sync", "bootstrap"])).stdout),
                postcondition=lambda _result: identity_command_ready(["nas-identity-sync", "status"]),
            )
            progress("creating the chosen Authentik administrator")
            runtime_token_result = run_setup_stage(
                journal,
                "identity-runtime-token",
                lambda: install_runtime_identity_token(password),
                postcondition=lambda _result: identity_command_ready(["nas-identity-sync", "verify-token"]),
            )
            account_result = run_setup_stage(
                journal,
                "identity-accounts",
                lambda: apply_accounts(
                    account_plan,
                    confirm_password_reapply=getattr(args, "confirm_password_reapply", False),
                ),
                postcondition=lambda _result: account_plan_ready(account_plan),
            )
            run_setup_stage(
                journal,
                "setup-application-retirement",
                _remove_setup_application,
                postcondition=lambda result: (
                    isinstance(result, Mapping)
                    and (result.get("removed") is True or result.get("reason") == "not-found")
                ),
            )
            run_setup_stage(
                journal,
                "bootstrap-authority-retirement",
                lambda: retire_bootstrap_runtime(BOOTSTRAP_RUNTIME_ROOT, local_administrator["username"], password),
                manual_recovery_on_failure=True,
                postcondition=lambda result: isinstance(result, Mapping) and result.get("bootstrapRetired") is True,
            )
            run_setup_stage(
                journal,
                "bootstrap-linux-retirement",
                lambda: finalize_local_administrator(local_administrator),
                manual_recovery_on_failure=True,
                postcondition=lambda result: (
                    isinstance(result, Mapping)
                    and local_administrator_username() == local_administrator["username"]
                    and run_root(["id", "--user", BOOTSTRAP_ADMIN_USER], check=False).returncode != 0
                ),
            )
            progress("provisioning CopyParty-backed personal directories")
            share_directories = run_setup_stage(
                journal,
                "share-directories",
                lambda: provision_share_directories(config["accounts"]),
                postcondition=lambda _result: share_directories_ready(config["accounts"]),
            )
            syncthing_result: dict[str, Any] | None = None
            if SYNCTHING_ENABLED:
                progress("reconciling Authentik-owned Syncthing folders and devices")
                syncthing_result = run_setup_stage(
                    journal,
                    "syncthing",
                    lambda: json.loads(run_root(coordinated_child(["nas-identity-sync", "sync-syncthing"])).stdout),
                )
            progress("applying Managed Services V2 lifecycle modes")
            service_result = run_setup_stage(
                journal,
                "managed-services-policy",
                lambda: apply_services(config["services"]),
                postcondition=lambda _result: service_policy_ready(config["services"]),
            )
            progress("verifying storage and identity state")
            verification = run_setup_stage(
                journal,
                "verification",
                lambda: (
                    run_root(["nas-zfs-mount-check"]),
                    json.loads(run_root(["nas-identity-sync", "status"]).stdout),
                )[1],
                postcondition=verification_ready,
            )
            preflight_ran = bool(config["runPreflight"] and not args.skip_preflight)
            if preflight_ran:
                progress("running repository and host preflight validation")
                run_setup_stage(
                    journal,
                    "preflight",
                    lambda: run(["nas-preflight"], env=INSTALLED_PREFLIGHT_ENV) and {"passed": True},
                    postcondition=preflight_ready,
                )
            report_status = "complete" if preflight_ran else "complete-unverified"
            report = {
                "schemaVersion": SCHEMA_VERSION,
                "status": report_status,
                "planDigest": confirmed_plan_digest,
                "completedAt": int(time.time()),
                "durationSeconds": int(time.time()) - started,
                "database": {"path": str(KEEPASS_DATABASE), "result": database_result},
                "localAdministrator": {key: local_administrator[key] for key in ("username", "name", "email")},
                "storage": storage_result,
                "identityBootstrap": bootstrap_result,
                "identityRuntimeToken": runtime_token_result,
                "accounts": account_result,
                "shareDirectories": share_directories,
                "syncthing": syncthing_result,
                "services": service_result,
                "identity": verification,
                "preflight": preflight_ran,
                "journal": str(JOURNAL_PATH),
            }
            run_setup_stage(
                journal,
                "final-state",
                lambda: (write_state(report), report)[1],
                postcondition=lambda _result: setup_state_matches(report),
            )
            if not setup_state_matches(report):
                journal.fail("Final setup state could not be verified", manual_recovery=True)
                raise SetupError("Final setup state could not be verified")
            journal.complete(report)
            publish_first_start_status(
                {
                    "schemaVersion": SCHEMA_VERSION,
                    "status": report_status,
                    "planDigest": confirmed_plan_digest,
                    "configPath": str(pathlib.Path(args.config).resolve()),
                    "completedAt": report["completedAt"],
                    "message": "Initial appliance setup is complete."
                    if preflight_ran
                    else "Initial setup completed without final preflight verification.",
                }
            )
            return report
        except JournalError as exc:
            raise SetupError(str(exc)) from exc
        finally:
            password = ""
            if "administrator_password" in locals():
                administrator_password = ""
            for account in account_plan.get("accounts", []):
                if isinstance(account, dict):
                    account.pop("password", None)


def existing_account(username: str) -> dict[str, Any] | None:
    completed = run_root(["nas-identity-sync", "export-account", username], check=False)
    if completed.returncode == 0:
        try:
            value = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise SetupError("nas-identity-sync returned invalid exported account JSON") from exc
        if not isinstance(value, dict):
            raise SetupError("nas-identity-sync returned an invalid exported account")
        return value
    if "does not exist" in completed.stderr:
        return None
    detail = completed.stderr.strip() or completed.stdout.strip() or f"exit status {completed.returncode}"
    raise SetupError(f"Unable to inspect existing Authentik account {username}: {detail}")


def one_account(args: argparse.Namespace) -> dict[str, Any]:
    try:
        username = validate_username(args.username)
    except DeviceError as exc:
        raise SetupError(f"Account username is unsafe: {exc}") from exc
    if username == "akadmin":
        raise SetupError("akadmin is Authentik's bootstrap account and is not managed by nas-setup")
    with maintained_sudo_authorization():
        current = existing_account(username)
        explicit_groups = list(args.group or [])
        if explicit_groups:
            groups = explicit_groups
        elif current is not None:
            groups = list(current.get("groups", []))
        else:
            groups = [USER_GROUP]
        if args.active is False:
            if explicit_groups or args.administrator:
                raise SetupError("Do not combine --disabled with --group or --administrator")
            groups = [DISABLED_GROUP]
        elif args.administrator and ADMIN_GROUP not in groups:
            groups.append(ADMIN_GROUP)
        raw: dict[str, Any] = {
            "username": username,
            "name": args.name or (current.get("name") if current else username),
            "email": args.email or (current.get("email") if current else f"{username}@invalid.local"),
            "active": args.active if args.active is not None else (current.get("active", True) if current else True),
            "groups": groups,
            "attributes": current.get("attributes", {}) if current else {},
        }
        account = normalize_account(raw, 0)
        password = None
        if args.password_stdin:
            password = read_secret_stdin(f"Password for {account['username']}")
        elif args.set_password:
            password = normalize_secret_line(
                getpass.getpass(f"Password for {account['username']}: "), f"Password for {account['username']}"
            )
        item = {
            "username": account["username"],
            "name": account["name"],
            "email": account["email"],
            "active": account["active"],
            "groups": account["groups"],
            "attributes": account["attributes"],
        }
        if password is not None:
            item["password"] = password
        try:
            result = apply_accounts({"schemaVersion": 1, "accounts": [item], "deactivateMissingManagedAccounts": False})
            shares = provision_share_directories([account])
            if SYNCTHING_ENABLED:
                run_root(coordinated_child(["nas-identity-sync", "sync-syncthing"]))
            return {"account": result, "shareDirectories": shares}
        finally:
            password = None
            item.pop("password", None)


def disable_account(args: argparse.Namespace) -> dict[str, Any]:
    try:
        username = validate_username(args.username)
    except DeviceError as exc:
        raise SetupError(f"Account username is unsafe: {exc}") from exc
    with maintained_sudo_authorization():
        existing = json.loads(run_root(["nas-identity-sync", "export-account", username]).stdout)
        existing["active"] = False
        existing["groups"] = [DISABLED_GROUP]
        result = apply_accounts({"schemaVersion": 1, "accounts": [existing], "deactivateMissingManagedAccounts": False})
        if SYNCTHING_ENABLED:
            run_root(coordinated_child(["nas-identity-sync", "sync-syncthing"]))
        return result


def setup_authority_health(config: Mapping[str, Any]) -> dict[str, Any]:
    checks: dict[str, bool | None] = {
        "keepassDatabase": keepass_database_ready(),
        "pool": pool_exists(),
        "dataset": dataset_exists(),
        "identity": None,
        "managedServices": None,
        "shares": share_directories_ready(config.get("accounts", [])),
    }
    if pathlib.Path("/run/nas-secrets/ready").is_file():
        checks["identity"] = identity_command_ready(["nas-identity-sync", "status"])
        checks["managedServices"] = service_policy_ready(config.get("services", {}))
    required = [checks["keepassDatabase"], checks["pool"], checks["dataset"], checks["shares"]]
    if checks["identity"] is not None:
        required.append(checks["identity"])
    if checks["managedServices"] is not None:
        required.append(checks["managedServices"])
    return {"ok": all(value is True for value in required), "checks": checks}


def first_start_status(config_source: str) -> dict[str, Any]:
    try:
        state = load_json(STATE_PATH)
    except JournalError as exc:
        return {
            "schemaVersion": SCHEMA_VERSION,
            "status": "state-invalid",
            "configPath": config_source,
            "message": str(exc),
        }
    config_path = pathlib.Path(config_source)
    if not config_path.exists():
        return {
            "schemaVersion": SCHEMA_VERSION,
            "status": "configuration-missing",
            "configPath": config_source,
            "message": "Create the first-run JSON file, then recheck configuration.",
        }
    try:
        config = normalize_config(read_json_source(config_source))
        validate_service_request(config["services"])
        plan_digest = setup_plan_digest(config)
    except (SetupError, OSError, ValueError, json.JSONDecodeError) as exc:
        return {
            "schemaVersion": SCHEMA_VERSION,
            "status": "configuration-invalid",
            "configPath": config_source,
            "message": str(exc),
        }
    if isinstance(state, dict) and state.get("status") in {"complete", "complete-unverified"}:
        if state.get("planDigest") != plan_digest:
            return {
                "schemaVersion": SCHEMA_VERSION,
                "status": "configuration-changed",
                "configPath": config_source,
                "planDigest": plan_digest,
                "previousPlanDigest": state.get("planDigest"),
                "message": "The normalized first-start configuration changed after setup; review and reconcile the new plan.",
            }
        health = setup_authority_health(config)
        if not health["ok"]:
            return {
                "schemaVersion": SCHEMA_VERSION,
                "status": "state-drift",
                "configPath": config_source,
                "planDigest": plan_digest,
                "completedAt": state.get("completedAt"),
                "authorityHealth": health,
                "message": "Setup state exists, but one or more appliance authorities no longer satisfy it.",
            }
        status = str(state.get("status"))
        return {
            "schemaVersion": SCHEMA_VERSION,
            "status": status,
            "configPath": config_source,
            "planDigest": plan_digest,
            "completedAt": state.get("completedAt"),
            "authorityHealth": health,
            "message": "Initial appliance setup is complete."
            if status == "complete"
            else "Initial setup completed without final preflight verification.",
        }
    storage = config["storage"]
    devices = [str(item) for item in storage.get("devices", [])]
    pool_present = pool_exists()
    destructive = bool(not pool_present and storage.get("createPool"))
    return {
        "schemaVersion": SCHEMA_VERSION,
        "status": "ready",
        "configPath": config_source,
        "message": "Enter the KeePassXC database password in Cockpit to continue setup.",
        "planDigest": plan_digest,
        "requiresPassword": True,
        "requiresDestructiveConfirmation": destructive,
        "storage": {
            "pool": ZFS_POOL,
            "dataset": ZFS_DATASET,
            "poolPresent": pool_present,
            "createPool": bool(storage.get("createPool")),
            "topology": str(storage.get("topology", "single")),
            "devices": devices,
            "wipeDevices": bool(storage.get("wipeDevices")),
            "ashift": int(storage.get("ashift", 12)),
        },
        "accountCount": len(config["accounts"]),
        "serviceCount": len(config["services"]),
        "runPreflight": bool(config["runPreflight"]),
    }


def publish_first_start_status(status: Mapping[str, Any]) -> None:
    if os.geteuid() == 0:
        atomic_write_json(FIRST_START_STATUS_PATH, status, mode=0o644)
        return
    payload = json.dumps(dict(status), indent=2, sort_keys=True) + "\n"
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
        handle.write(payload)
        temporary = pathlib.Path(handle.name)
    try:
        run_root(["install", "-d", "-m", "0755", str(FIRST_START_STATUS_PATH.parent)])
        run_root(["install", "-m", "0644", "-o", "root", "-g", "root", str(temporary), str(FIRST_START_STATUS_PATH)])
    finally:
        temporary.unlink(missing_ok=True)


def prepare_first_start(config_source: str) -> dict[str, Any]:
    status = first_start_status(config_source)
    publish_first_start_status(status)
    return status


def reconcile_first_run(note: str) -> dict[str, Any]:
    journal = OperationJournal.acknowledge_manual_recovery(JOURNAL_PATH, workflow="first-run-v2", note=note)
    return {
        "ok": True,
        "journal": str(JOURNAL_PATH),
        "status": journal.value["status"],
        "message": "Manual recovery was acknowledged. Re-run first-run with the original inputs to resume.",
    }


def status_report() -> dict[str, Any]:
    report: dict[str, Any] = {
        "schemaVersion": SCHEMA_VERSION,
        "keepassDatabase": {"path": str(KEEPASS_DATABASE), "exists": KEEPASS_DATABASE.exists()},
        "runtimeSecretsActive": pathlib.Path("/run/nas-secrets/ready").exists(),
        "poolPresent": pool_exists(),
        "datasetPresent": dataset_exists(),
        "setupState": None,
        "setupJournal": None,
        "firstStart": None,
    }
    try:
        report["firstStart"] = load_json(FIRST_START_STATUS_PATH)
    except JournalError as exc:
        report["firstStart"] = {"status": "invalid", "error": str(exc)}
    try:
        report["setupState"] = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        pass
    try:
        report["setupJournal"] = load_json(JOURNAL_PATH)
    except JournalError as exc:
        report["setupJournal"] = {"status": "invalid", "error": str(exc)}
    if report["runtimeSecretsActive"]:
        for key, command in {
            "identity": ["nas-identity-sync", "status"],
            "managedServices": [MANAGED_SERVICES_CONTROL, "status"],
        }.items():
            completed = run_root_noninteractive(command, check=False)
            if completed.returncode != 0:
                report[key] = {"error": completed.stderr.strip() or f"command exited {completed.returncode}"}
            elif completed.stdout.strip():
                try:
                    report[key] = json.loads(completed.stdout)
                except json.JSONDecodeError:
                    report[key] = {"error": "invalid JSON"}
            else:
                report[key] = {"error": "command returned no JSON"}
    return report


def _read_secure_job_file(path: pathlib.Path, label: str, *, max_bytes: int) -> str:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SetupError(f"Unable to open {label} without following symlinks") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise SetupError(f"{label} must be a private regular file")
        if os.geteuid() == 0 and metadata.st_uid != 0:
            raise SetupError(f"{label} must be root-owned")
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            descriptor = -1
            value = handle.read(max_bytes + 1)
    except UnicodeDecodeError as exc:
        raise SetupError(f"{label} must be valid UTF-8") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(value.encode("utf-8")) > max_bytes:
        raise SetupError(f"{label} exceeds its size limit")
    return value


def prune_first_start_job_results(root: pathlib.Path, *, keep: pathlib.Path | None = None) -> None:
    now = time.time()
    candidates = sorted(
        (item for item in root.glob("*.json") if item != keep and item.is_file()),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )
    retained_slots = max(0, FIRST_START_JOB_RETAIN_COUNT - (1 if keep is not None and keep.exists() else 0))
    for index, item in enumerate(candidates):
        too_old = FIRST_START_JOB_RETAIN_SECONDS and now - item.stat().st_mtime > FIRST_START_JOB_RETAIN_SECONDS
        if index >= retained_slots or too_old:
            item.unlink(missing_ok=True)


def run_first_start_job(request_file: pathlib.Path, password_file: pathlib.Path) -> dict[str, Any]:
    reservation_token: str | None = None
    password = ""
    result_path: pathlib.Path | None = None
    job_id: str | None = None
    try:
        request_text = _read_secure_job_file(request_file, "First-start job request", max_bytes=64 * 1024)
        try:
            request = json.loads(request_text)
        except json.JSONDecodeError as exc:
            raise SetupError("First-start job request is invalid") from exc
        required = {
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
        if not isinstance(request, dict) or set(request) != required or request.get("schemaVersion") != 1:
            raise SetupError("First-start job request contract is invalid")
        candidate = request.get("reservationToken")
        if isinstance(candidate, str) and re.fullmatch(r"[0-9a-f]{32}", candidate):
            reservation_token = candidate
        if reservation_token is None:
            raise SetupError("First-start reservation token is invalid")
        job_id = request.get("jobId")
        if not isinstance(job_id, str) or not re.fullmatch(r"[0-9a-f]{24}", job_id):
            raise SetupError("First-start job identifier is invalid")
        result_root = STATE_PATH.parent / "jobs"
        result_path = result_root / f"{job_id}.json"
        result_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(result_root, 0o700)
        prune_first_start_job_results(result_root, keep=result_path)
        config = request.get("config")
        plan_digest = request.get("planDigest")
        devices = request.get("devices")
        if not isinstance(config, str) or not pathlib.Path(config).is_absolute():
            raise SetupError("First-start job configuration path is invalid")
        if not isinstance(plan_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", plan_digest):
            raise SetupError("First-start job plan digest is invalid")
        if (
            not isinstance(devices, list)
            or not all(isinstance(item, str) and item for item in devices)
            or len(devices) != len(set(devices))
        ):
            raise SetupError("First-start job devices are invalid")
        if (
            not isinstance(request.get("allowDestructiveStorage"), bool)
            or not isinstance(request.get("confirmPasswordReapply"), bool)
            or not isinstance(request.get("encryptStorage"), bool)
        ):
            raise SetupError("First-start job confirmation flags are invalid")
        try:
            secrets_payload = json.loads(
                _read_secure_job_file(password_file, "First-start password file", max_bytes=8192)
            )
        except json.JSONDecodeError as exc:
            raise SetupError("First-start secret payload is invalid") from exc
        if not isinstance(secrets_payload, dict) or set(secrets_payload) != {"keepass", "administrator"}:
            raise SetupError("First-start secret payload contract is invalid")
        raw_password = secrets_payload.get("keepass")
        if not isinstance(raw_password, str):
            raise SetupError("First-start KeePass database password is invalid")
        password = normalize_secret_line(raw_password, "KeePass database password")
        administrator = secrets_payload.get("administrator")
        if not isinstance(administrator, dict) or set(administrator) != {"username", "name", "email", "password"}:
            raise SetupError("First-start administrator secret payload is invalid")
        password_file.unlink(missing_ok=True)
        request_file.unlink(missing_ok=True)
        args = argparse.Namespace(
            config=config,
            keepass_password_stdin=False,
            keepass_password_value=password,
            administrator=administrator,
            create_database=True,
            confirm_storage_device=list(devices),
            allow_destructive_storage=request["allowDestructiveStorage"],
            encrypt_storage=request["encryptStorage"],
            confirm_plan_digest=plan_digest,
            skip_preflight=False,
            confirm_password_reapply=request["confirmPasswordReapply"],
            reservation_token=reservation_token,
        )
        atomic_write_json(
            result_path, {"schemaVersion": 1, "jobId": job_id, "status": "running", "startedAt": int(time.time())}
        )
        result = first_run(args)
        atomic_write_json(
            result_path,
            {
                "schemaVersion": 1,
                "jobId": job_id,
                "status": "complete",
                "completedAt": int(time.time()),
                "result": result,
            },
        )
        prune_first_start_job_results(result_root, keep=result_path)
        return result
    except Exception as exc:
        if result_path is not None and job_id is not None:
            atomic_write_json(
                result_path,
                {
                    "schemaVersion": 1,
                    "jobId": job_id,
                    "status": "failed",
                    "completedAt": int(time.time()),
                    "error": str(exc),
                },
            )
        raise
    finally:
        password = ""
        password_file.unlink(missing_ok=True)
        request_file.unlink(missing_ok=True)
        if reservation_token is not None:
            cancel_reservation(reservation_token)


def first_run(args: argparse.Namespace) -> dict[str, Any]:
    reservation_token = getattr(args, "reservation_token", None)
    if not isinstance(reservation_token, str):
        reservation_token = None
    try:
        with acquire_operation("first-start-v2", SETUP_OPERATION_CLASSES, reservation_token=reservation_token):
            return _first_run_locked(args)
    except OperationBusyError as exc:
        raise SetupError(str(exc)) from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate-config", help="Validate and normalize a first-run JSON file")
    validate.add_argument("config")

    prepare = sub.add_parser("prepare-first-start", help="Publish non-secret first-start state for Cockpit and systemd")
    prepare.add_argument("--config", required=True, help="Setup JSON file")

    first = sub.add_parser("first-run", help="Perform idempotent first-time appliance setup")
    first.add_argument("--config", required=True, help="Setup JSON file")
    first.add_argument(
        "--keepass-password-stdin", action="store_true", help="Read one KeePass password line from stdin"
    )
    first.add_argument("--create-database", action=argparse.BooleanOptionalAction, default=True)
    first.add_argument(
        "--encrypt-storage",
        action=argparse.BooleanOptionalAction,
        default=ZFS_ENCRYPTION,
        help="Create the managed ZFS dataset with KeePassXC-backed native encryption",
    )
    first.add_argument(
        "--confirm-storage-device",
        action="append",
        default=[],
        help="Exact configured device path; repeat once per device before creating a new pool",
    )
    first.add_argument(
        "--allow-destructive-storage",
        action="store_true",
        help="Permit creation of a new pool after every configured device is confirmed",
    )
    first.add_argument(
        "--confirm-plan-digest",
        required=True,
        help="SHA-256 digest returned by prepare-first-start for the complete normalized plan",
    )
    first.add_argument("--skip-preflight", action="store_true")
    first.add_argument(
        "--confirm-password-reapply",
        action="store_true",
        help="Permit repeating account password mutations while resuming an incomplete identity stage",
    )

    job = sub.add_parser("run-first-start-job", help=argparse.SUPPRESS)
    job.add_argument("--request-file", required=True, type=pathlib.Path)
    job.add_argument("--password-file", required=True, type=pathlib.Path)

    reconcile = sub.add_parser(
        "reconcile-first-run", help="Acknowledge a manually repaired first-run journal before resuming"
    )
    reconcile.add_argument("--note", required=True, help="Operator recovery note recorded in the journal")

    account = sub.add_parser("account", help="Create or update one Authentik account")
    account_sub = account.add_subparsers(dest="account_command", required=True)
    add = account_sub.add_parser("apply", help="Create or update one Authentik account")
    add.add_argument("--username", required=True)
    add.add_argument("--name")
    add.add_argument("--email")
    add.add_argument(
        "--group",
        action="append",
        default=[],
        help="Base identity role; application capability groups are assigned directly in Authentik",
    )
    add.add_argument("--administrator", action="store_true", help=f"Add {ADMIN_GROUP} without dropping existing roles")
    state = add.add_mutually_exclusive_group()
    state.add_argument("--enabled", dest="active", action="store_true")
    state.add_argument("--disabled", dest="active", action="store_false")
    add.set_defaults(active=None)
    add.add_argument("--set-password", action="store_true", help="Prompt for a password")
    add.add_argument("--password-stdin", action="store_true", help="Read one account password line from stdin")
    disable = account_sub.add_parser("disable", help="Disable one managed account without deleting it")
    disable.add_argument("username")

    sub.add_parser("status", help="Report first-run, storage, identity, and Managed Services V2 status")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "validate-config":
            result = normalize_config(read_json_source(args.config))
        elif args.command == "prepare-first-start":
            result = prepare_first_start(args.config)
        elif args.command == "first-run":
            result = first_run(args)
        elif args.command == "run-first-start-job":
            result = run_first_start_job(args.request_file, args.password_file)
        elif args.command == "reconcile-first-run":
            with acquire_operation("reconcile-first-run", ("first-start", "state")):
                result = reconcile_first_run(args.note)
        elif args.command == "account" and args.account_command == "apply":
            if args.password_stdin and args.set_password:
                raise SetupError("Choose only one of --set-password or --password-stdin")
            with acquire_operation("account-apply", ("identity", "runtime"), blocking=True):
                result = one_account(args)
        elif args.command == "account" and args.account_command == "disable":
            with acquire_operation("account-disable", ("identity", "runtime"), blocking=True):
                result = disable_account(args)
        else:
            result = status_report()
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (SetupError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"nas-setup: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
