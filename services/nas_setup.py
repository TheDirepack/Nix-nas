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

ADMIN_USER = os.environ.get("NAS_ADMIN_USER", "admin")
KEEPASS_DATABASE = pathlib.Path(os.environ.get("NAS_KEEPASS_DATABASE", "/var/lib/nas-secrets/NAS.kdbx"))
KEEPASS_KEY_FILE = os.environ.get("NAS_KEEPASS_KEY_FILE", "")
ZFS_POOL = os.environ.get("NAS_ZFS_POOL", "tank")
ZFS_DATASET = os.environ.get("NAS_ZFS_DATASET", "tank/nas")
ZFS_ROOT = pathlib.Path(os.environ.get("NAS_ZFS_ROOT", "/tank"))
ZFS_ENCRYPTION = os.environ.get("NAS_ZFS_ENCRYPTION_ENABLE", "0") == "1"
SHARE_ROOT = pathlib.Path(os.environ.get("NAS_SHARE_ROOT", str(ZFS_ROOT / "shares")))
SYNCTHING_ENABLED = os.environ.get("NAS_SYNCTHING_ENABLE", "0") == "1"
STATE_PATH = pathlib.Path(os.environ.get("NAS_SETUP_STATE", "/var/lib/nas-setup/state.json"))
JOURNAL_PATH = pathlib.Path(os.environ.get("NAS_SETUP_JOURNAL", "/var/lib/nas-setup/first-run-journal.json"))
FIRST_START_STATUS_PATH = pathlib.Path(os.environ.get("NAS_FIRST_START_STATUS", "/var/lib/nas-first-start/status.json"))
MANAGED_SERVICES_CONTROL = os.environ.get("NAS_MANAGED_SERVICES_CONTROL", "nas-managed-services-control")
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


def admin_command(command: Sequence[str]) -> list[str]:
    current = current_username()
    if current == ADMIN_USER:
        return [str(item) for item in command]
    if os.geteuid() == 0:
        return [
            "runuser",
            "-u",
            ADMIN_USER,
            "--",
            "env",
            f"HOME=/home/{ADMIN_USER}",
            f"PATH={os.environ.get('PATH', '')}",
            *map(str, command),
        ]
    raise SetupError(f"Run nas-setup as {ADMIN_USER} or root, not {current}")


def run_admin(command: Sequence[str], **kwargs: Any) -> Completed:
    return run(admin_command(command), **kwargs)


def run_interactive_privileged(command: Sequence[str], **kwargs: Any) -> Completed:
    if os.geteuid() == 0 and os.environ.get("NAS_SETUP_ALLOW_ROOT") == "1":
        return run(command, **kwargs)
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
    if current_username() != ADMIN_USER:
        return Completed(
            tuple(map(str, command)), "", "privileged status requires the configured local administrator", 1
        )
    return run(["sudo", "-n", "--", *map(str, command)], **kwargs)


def require_setup_operator() -> None:
    current = current_username()
    if os.geteuid() == 0 and os.environ.get("NAS_SETUP_ALLOW_ROOT") == "1":
        progress("using Cockpit-authorized root setup execution")
        return
    if current != ADMIN_USER:
        raise SetupError(
            f"Run mutating nas-setup commands as the configured local administrator {ADMIN_USER!r}, not {current!r}."
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


def verify_or_create_database(password: str, create: bool) -> str:
    key_args = ["--key-file", KEEPASS_KEY_FILE] if KEEPASS_KEY_FILE else []
    if KEEPASS_DATABASE.exists():
        run_admin(
            ["keepassxc-cli", "db-info", "--quiet", "--pw-stdin", *key_args, str(KEEPASS_DATABASE)],
            input_text=password + "\n",
        )
        return "existing"
    if not create:
        raise SetupError(f"KeePass database does not exist: {KEEPASS_DATABASE}")
    run_root(["install", "-d", "-m", "0700", "-o", ADMIN_USER, "-g", "users", str(KEEPASS_DATABASE.parent)])
    create_args = ["keepassxc-cli", "db-create", "--quiet", "-p"]
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
) -> dict[str, Any]:
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
        run_root(
            [
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
        )
        run_root(["zpool", "set", "autotrim=on", ZFS_POOL])
        created_pool = True
    if not dataset_exists():
        if ZFS_ENCRYPTION:
            run_interactive_privileged(["nas-zfs-create-encrypted-dataset"], input_text=keepass_password + "\n")
        else:
            run_root(["zfs", "create", "-o", f"mountpoint={ZFS_ROOT}", ZFS_DATASET])
        created_dataset = True
    if not ZFS_ENCRYPTION:
        run_root(["zfs", "mount", ZFS_DATASET], check=False)
        run_root(["nas-zfs-mount-check"])
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
        "encrypted": ZFS_ENCRYPTION,
    }


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
    run_root(["install", "-d", "-m", "0750", "-o", "root", "-g", "wheel", str(STATE_PATH.parent)])
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
        "skipPreflight": bool(args.skip_preflight),
    }
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


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
        run_interactive_privileged(
            coordinated_child(["nas-secrets", "activate-stdin"]), input_text=f"{keepass_password}\n"
        )
        return value
    finally:
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
    return pool_exists() and dataset_exists()


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
    return run(["nas-preflight"], env={"NAS_PREFLIGHT_VERIFY_MANIFEST": "0"}, check=False).returncode == 0


def service_policy_ready(services: Mapping[str, str]) -> bool:
    try:
        status = _managed_services_status(noninteractive=True)
    except SetupError:
        return False
    rows = status.get("services", [])
    by_id = {row.get("id"): row for row in rows if isinstance(row, Mapping)}
    return all(by_id.get(service_id, {}).get("requestedMode") == mode for service_id, mode in services.items())


def share_directories_ready(accounts: Sequence[Mapping[str, Any]]) -> bool:
    for account in accounts:
        groups = set(account.get("groups", []))
        if account.get("active") is not True or GUEST_GROUP in groups:
            continue
        path = SHARE_ROOT / "users" / str(account["username"])
        try:
            mode = path.lstat().st_mode
        except FileNotFoundError:
            return False
        if not stat.S_ISDIR(mode) or stat.S_ISLNK(mode):
            return False
    return True


def setup_state_matches(report: Mapping[str, Any]) -> bool:
    try:
        current = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return current == report


def _first_run_locked(args: argparse.Namespace) -> dict[str, Any]:
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
            fingerprint = setup_fingerprint(config, args, account_plan, password)
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
                ),
                manual_recovery_on_failure=pool_was_missing and args.allow_destructive_storage,
                postcondition=storage_ready,
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
            progress("installing the scoped Authentik runtime token")
            runtime_token_result = run_setup_stage(
                journal,
                "identity-runtime-token",
                lambda: install_runtime_identity_token(password),
                postcondition=lambda _result: identity_command_ready(["nas-identity-sync", "verify-token"]),
            )
            progress("applying Authentik accounts")
            account_result = run_setup_stage(
                journal,
                "identity-accounts",
                lambda: apply_accounts(
                    account_plan,
                    confirm_password_reapply=getattr(args, "confirm_password_reapply", False),
                ),
                postcondition=lambda _result: account_plan_ready(account_plan),
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
                    lambda: run(["nas-preflight"], env={"NAS_PREFLIGHT_VERIFY_MANIFEST": "0"}) and {"passed": True},
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
        if not isinstance(request.get("allowDestructiveStorage"), bool) or not isinstance(
            request.get("confirmPasswordReapply"), bool
        ):
            raise SetupError("First-start job confirmation flags are invalid")
        password = normalize_secret_line(
            _read_secure_job_file(password_file, "First-start password file", max_bytes=4098),
            "KeePass database password",
        )
        password_file.unlink(missing_ok=True)
        request_file.unlink(missing_ok=True)
        args = argparse.Namespace(
            config=config,
            keepass_password_stdin=False,
            keepass_password_value=password,
            create_database=True,
            confirm_storage_device=list(devices),
            allow_destructive_storage=request["allowDestructiveStorage"],
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
            with acquire_operation("account-apply", ("identity", "runtime")):
                result = one_account(args)
        elif args.command == "account" and args.account_command == "disable":
            with acquire_operation("account-disable", ("identity", "runtime")):
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
