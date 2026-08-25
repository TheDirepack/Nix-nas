#!/usr/bin/env python3
"""Hardened first-run job orchestration.

The HTTP setup service is authenticated by the already-running disposable
bootstrap Authentik/KDBX trust domain. This module deliberately does not unlock,
copy, promote, or otherwise consume bootstrap KDBX entries. Its first mutation
is the switch to a fresh root-hosted permanent runtime; all permanent secrets
are then generated in the new user-password-protected NAS.kdbx.

``nas_setup`` remains the library of finite setup primitives. The dedicated
standalone wizard uses this single security-focused orchestration path.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import stat
import time
from collections.abc import Mapping
from typing import Any

import nas_setup as setup

LOCAL_ADMIN_PENDING_PATH = setup.ADMIN_STATE_PATH.with_name("local-administrator-pending.json")
_REQUIRED_ADMIN_GROUPS = frozenset({"wheel", "nas-administrators", "nas-operations"})


def _regular_root_file(path: pathlib.Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISREG(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and info.st_uid == 0
        and not (stat.S_IMODE(info.st_mode) & 0o022)
    )


def _read_private_root_json(path: pathlib.Path) -> dict[str, Any]:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise setup.SetupError(f"Unable to open setup transaction marker safely: {path}") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or metadata.st_size > 16 * 1024
        ):
            raise setup.SetupError(f"Setup transaction marker has unsafe ownership or mode: {path}")
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            descriptor = -1
            value = json.load(handle)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise setup.SetupError(f"Setup transaction marker contains invalid JSON: {path}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not isinstance(value, dict):
        raise setup.SetupError(f"Setup transaction marker is not a JSON object: {path}")
    return value


def bootstrap_authority_ready() -> dict[str, Any]:
    """Verify that authenticated bootstrap infrastructure exists without opening its KDBX."""
    root = setup.BOOTSTRAP_RUNTIME_ROOT
    database = root / "nas-secrets" / "NAS.kdbx"
    password_file = root / "kdbx-password"
    token_file = pathlib.Path("/run/nas-authentik/api-token")
    if not _regular_root_file(database):
        raise setup.SetupError("Disposable bootstrap KDBX is missing or unsafe")
    if not _regular_root_file(password_file):
        raise setup.SetupError("Disposable bootstrap KDBX unlock material is missing or unsafe")
    if not _regular_root_file(token_file):
        raise setup.SetupError("Bootstrap Authentik API token staging is missing or unsafe")
    active = setup.run_root_noninteractive(["systemctl", "is-active", "--quiet", "authentik.service"], check=False)
    if active.returncode != 0:
        raise setup.SetupError("Bootstrap Authentik is not active")
    return {"verified": True, "database": str(database), "runtime": str(root)}


def permanent_runtime_ready(_result: Any = None) -> bool:
    marker = setup.OPERATIONAL_RUNTIME_SELECT_PATH
    if not _regular_root_file(marker):
        return False
    for name in ("authentik", "postgresql", "nas-secrets"):
        stable = pathlib.Path("/var/lib") / name
        expected = (setup.PERMANENT_RUNTIME_ROOT / name).resolve(strict=False)
        if not stable.is_symlink() or stable.resolve(strict=False) != expected:
            return False
    return True


def select_permanent_runtime() -> dict[str, Any]:
    """Select the fresh permanent root runtime, safely resuming after selection."""
    if setup.OPERATIONAL_RUNTIME_SELECT_PATH.exists():
        if not permanent_runtime_ready():
            raise setup.SetupError("Permanent runtime marker exists but stable authority links are inconsistent")
        return {"permanentRuntimeSelected": True, "resumed": True}
    return setup.select_fresh_permanent_runtime()


def _local_admin_marker(username: str, fingerprint: str) -> dict[str, Any]:
    return {"schemaVersion": 1, "username": username, "fingerprint": fingerprint}


def _load_matching_local_admin_marker(username: str, fingerprint: str) -> dict[str, Any] | None:
    try:
        marker = _read_private_root_json(LOCAL_ADMIN_PENDING_PATH)
    except setup.SetupError:
        if not LOCAL_ADMIN_PENDING_PATH.exists() and not LOCAL_ADMIN_PENDING_PATH.is_symlink():
            return None
        raise
    expected = _local_admin_marker(username, fingerprint)
    if marker != expected:
        raise setup.SetupError("Pending local-administrator transaction does not match this setup request")
    return marker


def _local_administrator_ready(result: Any) -> bool:
    if not isinstance(result, Mapping):
        return False
    username = result.get("username")
    if not isinstance(username, str) or not username:
        return False
    identity = setup.run_root_noninteractive(["id", "--user", username], check=False)
    if identity.returncode != 0:
        return False
    groups = setup.run_root_noninteractive(["id", "--name", "--groups", username], check=False)
    if groups.returncode != 0:
        return False
    return _REQUIRED_ADMIN_GROUPS.issubset(set(groups.stdout.split()))


def create_or_resume_local_administrator(
    administrator: Mapping[str, Any], password: str, fingerprint: str
) -> dict[str, Any]:
    """Create the chosen account, or finish only a transaction this setup owns.

    The marker is written before ``useradd``. A hard crash after account creation
    therefore cannot make the next run adopt an arbitrary pre-existing account:
    only the exact username/fingerprint transaction may be resumed. Reapplying
    the supplied password and groups is safe and finishes partial useradd work.
    """
    desired = setup._validated_administrator(administrator)
    username = desired["username"]
    marker = _load_matching_local_admin_marker(username, fingerprint)
    exists = setup.run_root_noninteractive(["id", "--user", username], check=False).returncode == 0

    if marker is None:
        if exists:
            raise setup.SetupError(f"Administrator username already exists locally: {username}")
        setup.atomic_write_json(LOCAL_ADMIN_PENDING_PATH, _local_admin_marker(username, fingerprint), mode=0o600)
        return setup.create_local_administrator(administrator, password)

    if not exists:
        return setup.create_local_administrator(administrator, password)

    normalized_password = setup.normalize_secret_line(password, "Administrator password")
    if ":" in normalized_password:
        raise setup.SetupError("Administrator password must not contain a colon")
    setup.run_root(["chpasswd"], input_text=f"{username}:{normalized_password}\n")
    setup.run_root(
        [
            "usermod",
            "--shell",
            "/run/current-system/sw/bin/bash",
            "--append",
            "--groups",
            "wheel,nas-administrators,nas-operations",
            username,
        ]
    )
    if not _local_administrator_ready(desired):
        raise setup.SetupError("Resumed local-administrator transaction did not reach the required account state")
    return {**desired, "resumed": True}


def commit_local_administrator_transaction(username: str, fingerprint: str) -> None:
    marker = _load_matching_local_admin_marker(username, fingerprint)
    if marker is None:
        return
    try:
        LOCAL_ADMIN_PENDING_PATH.unlink()
    except OSError as exc:
        raise setup.SetupError("Unable to remove completed local-administrator transaction marker") from exc
    if LOCAL_ADMIN_PENDING_PATH.exists() or LOCAL_ADMIN_PENDING_PATH.is_symlink():
        raise setup.SetupError("Completed local-administrator transaction marker still exists")


def remove_setup_application() -> dict[str, Any]:
    """Remove the temporary setup launcher and verify that it is gone.

    The operation is intentionally idempotent so a crash after Authentik accepts
    the DELETE but before the journal records the stage can resume safely. Any
    API failure remains fatal: first-run must never be marked complete while the
    setup application may still be reachable.
    """
    import nas_identity_sync as identity

    try:
        token = identity.authentik_token(bootstrap=True)
        applications = identity.authentik_list(token, "core/applications/?slug=nas-setup")
        matches = [item for item in applications if item.get("slug") == "nas-setup"]
        if not matches:
            return {"removed": True, "resumed": True}
        identity.authentik_request(token, "core/applications/nas-setup/", method="DELETE")
        remaining = identity.authentik_list(token, "core/applications/?slug=nas-setup")
        if any(item.get("slug") == "nas-setup" for item in remaining):
            raise setup.SetupError("Authentik NAS Setup application still exists after retirement")
        return {"removed": True, "resumed": False}
    except setup.SetupError:
        raise
    except Exception as exc:
        raise setup.SetupError("Unable to retire the temporary Authentik NAS Setup application") from exc


def secure_first_run_locked(args: argparse.Namespace) -> dict[str, Any]:
    config = setup.normalize_config(setup.read_json_source(args.config))
    confirmed_plan_digest = setup.require_confirmed_plan(config, getattr(args, "confirm_plan_digest", None))
    with setup.maintained_sudo_authorization():
        setup.validate_storage_request(config["storage"], args.confirm_storage_device, args.allow_destructive_storage)
        setup.validate_service_request(config["services"])
        account_plan = setup.identity_plan(config)
        password = ""
        administrator_password = ""
        authentik_administrator_password = ""
        started = int(time.time())
        try:
            password_override = getattr(args, "keepass_password_value", None)
            password = (
                password_override
                if isinstance(password_override, str) and password_override
                else setup.read_keepass_password(args.keepass_password_stdin)
            )
            administrator = getattr(args, "administrator", None)
            if not isinstance(administrator, Mapping):
                raise setup.SetupError("First-run administrator details are missing")
            administrator_password_raw = administrator.get("password")
            if not isinstance(administrator_password_raw, str):
                raise setup.SetupError("First-run Linux administrator password is missing")
            administrator_password = setup.normalize_secret_line(
                administrator_password_raw, "Linux administrator password"
            )
            authentik_password_raw = getattr(args, "authentik_administrator_password", None)
            if not isinstance(authentik_password_raw, str):
                raise setup.SetupError("First-run Authentik administrator password is missing")
            authentik_administrator_password = setup.normalize_secret_line(
                authentik_password_raw, "Authentik administrator password"
            )
            desired_administrator = setup._validated_administrator(administrator)
            fingerprint = setup.setup_fingerprint(config, args, administrator)
            journal = setup.OperationJournal.open(
                setup.JOURNAL_PATH,
                workflow="first-run-v3",
                fingerprint=fingerprint,
                metadata={
                    "configPath": str(pathlib.Path(args.config).resolve()),
                    "storagePool": setup.ZFS_POOL,
                    "storageDataset": setup.ZFS_DATASET,
                    "planDigest": confirmed_plan_digest,
                },
            )

            # Authentication has already happened at Caddy/AuthentiK. Verify
            # bootstrap infrastructure without asking for, deriving, or storing
            # its KDBX password in the permanent setup request.
            bootstrap_result = setup.run_setup_stage(
                journal,
                "bootstrap-authority-ready",
                bootstrap_authority_ready,
            )

            setup.progress("selecting a fresh root-hosted permanent trust domain")
            setup.run_setup_stage(
                journal,
                "permanent-runtime-selection",
                select_permanent_runtime,
                manual_recovery_on_failure=True,
                postcondition=permanent_runtime_ready,
            )

            setup.progress("creating the permanent KeePassXC database with the operator-supplied password")
            database_result = setup.run_setup_stage(
                journal,
                "permanent-keepass-database",
                lambda: setup.verify_or_create_database(password, True),
                postcondition=setup.keepass_database_ready,
            )
            setup.progress("generating a completely new set of permanent machine secrets")
            setup.run_setup_stage(
                journal,
                "permanent-secret-initialization",
                lambda: (
                    setup.run_admin(setup.coordinated_child(["nas-secrets", "init"]), input_text=password + "\n")
                    and {"initialized": True}
                ),
            )

            setup.progress("creating the permanent Linux administrator")
            local_administrator = setup.run_setup_stage(
                journal,
                "local-administrator",
                lambda: create_or_resume_local_administrator(administrator, administrator_password, fingerprint),
                manual_recovery_on_failure=True,
                postcondition=_local_administrator_ready,
            )
            commit_local_administrator_transaction(local_administrator["username"], fingerprint)
            account_plan["accounts"].append(
                {**desired_administrator, "password": authentik_administrator_password}
            )

            setup.progress("creating or validating managed ZFS storage using the permanent KDBX key")
            pool_was_missing = not setup.pool_exists()
            storage_result = setup.run_setup_stage(
                journal,
                "storage",
                lambda: setup.setup_storage(
                    config["storage"],
                    keepass_password=password,
                    confirmed_devices=args.confirm_storage_device,
                    allow_destructive=args.allow_destructive_storage,
                ),
                manual_recovery_on_failure=pool_was_missing and args.allow_destructive_storage,
                postcondition=setup.storage_ready,
            )

            setup.progress("activating permanent protected services")
            setup.run_setup_stage(
                journal,
                "permanent-protected-service-activation",
                lambda: (
                    setup.run_interactive_privileged(
                        setup.coordinated_child(["nas-secrets", "activate-stdin"]), input_text=password + "\n"
                    )
                    and {"active": True}
                ),
                postcondition=setup.protected_stack_ready,
            )

            setup.progress("bootstrapping permanent Authentik")
            operational_bootstrap_result = setup.run_setup_stage(
                journal,
                "permanent-identity-bootstrap",
                lambda: json.loads(setup.run_root(setup.coordinated_child(["nas-identity-sync", "bootstrap"])).stdout),
                postcondition=lambda _result: setup.identity_command_ready(["nas-identity-sync", "status"]),
            )
            runtime_token_result = setup.run_setup_stage(
                journal,
                "identity-runtime-token",
                lambda: setup.install_runtime_identity_token(password),
                postcondition=lambda _result: setup.identity_command_ready(["nas-identity-sync", "verify-token"]),
            )
            account_result = setup.run_setup_stage(
                journal,
                "identity-accounts",
                lambda: setup.apply_accounts(
                    account_plan,
                    confirm_password_reapply=getattr(args, "confirm_password_reapply", False),
                ),
                postcondition=lambda _result: setup.account_plan_ready(account_plan),
            )

            # Remove the launcher object while a privileged permanent bootstrap
            # token still exists, then retire both permanent-bootstrap authority
            # and the completely separate root-side bootstrap trust directory.
            setup_application = setup.run_setup_stage(
                journal,
                "setup-application-retirement",
                remove_setup_application,
                manual_recovery_on_failure=True,
                postcondition=lambda result: isinstance(result, Mapping) and result.get("removed") is True,
            )
            setup.run_setup_stage(
                journal,
                "bootstrap-authority-retirement",
                lambda: setup.retire_bootstrap_runtime(
                    setup.BOOTSTRAP_RUNTIME_ROOT, local_administrator["username"], password
                ),
                manual_recovery_on_failure=True,
                postcondition=lambda result: isinstance(result, Mapping) and result.get("bootstrapRetired") is True,
            )

            setup.progress("provisioning CopyParty-backed personal directories")
            share_directories = setup.run_setup_stage(
                journal,
                "share-directories",
                lambda: setup.provision_share_directories(config["accounts"]),
                postcondition=lambda _result: setup.share_directories_ready(config["accounts"]),
            )
            syncthing_result: dict[str, Any] | None = None
            if setup.SYNCTHING_ENABLED:
                setup.progress("reconciling Authentik-owned Syncthing folders and devices")
                syncthing_result = setup.run_setup_stage(
                    journal,
                    "syncthing",
                    lambda: json.loads(
                        setup.run_root(setup.coordinated_child(["nas-identity-sync", "sync-syncthing"])).stdout
                    ),
                )

            setup.progress("applying Managed Services V2 lifecycle modes")
            service_result = setup.run_setup_stage(
                journal,
                "managed-services-policy",
                lambda: setup.apply_services(config["services"]),
                postcondition=lambda _result: setup.service_policy_ready(config["services"]),
            )
            setup.progress("verifying storage and identity state")
            verification = setup.run_setup_stage(
                journal,
                "verification",
                lambda: (
                    setup.run_root(["nas-zfs-mount-check"]),
                    json.loads(setup.run_root(["nas-identity-sync", "status"]).stdout),
                )[1],
                postcondition=setup.verification_ready,
            )

            preflight_ran = bool(config["runPreflight"] and not args.skip_preflight)
            if preflight_ran:
                setup.progress("running repository and host preflight validation")
                setup.run_setup_stage(
                    journal,
                    "preflight",
                    lambda: setup.run(["nas-preflight"], env={"NAS_PREFLIGHT_VERIFY_MANIFEST": "0"})
                    and {"passed": True},
                    postcondition=setup.preflight_ready,
                )

            # Bootstrap account retirement is security-critical. It happens
            # before state.json exists so a failure cannot hide the setup UI or
            # make the runtime selector treat an incomplete install as complete.
            setup.run_setup_stage(
                journal,
                "bootstrap-account-retirement",
                lambda: setup.finalize_local_administrator(local_administrator),
                manual_recovery_on_failure=True,
                postcondition=lambda result: (
                    isinstance(result, Mapping)
                    and result.get("username") == local_administrator["username"]
                    and setup.local_administrator_username() == local_administrator["username"]
                    and setup.run_root_noninteractive(
                        ["id", "--user", setup.BOOTSTRAP_ADMIN_USER], check=False
                    ).returncode
                    != 0
                ),
            )

            report_status = "complete" if preflight_ran else "complete-unverified"
            report = {
                "schemaVersion": setup.SCHEMA_VERSION,
                "status": report_status,
                "planDigest": confirmed_plan_digest,
                "completedAt": int(time.time()),
                "durationSeconds": int(time.time()) - started,
                "bootstrapAuthority": bootstrap_result,
                "database": {"path": str(setup.KEEPASS_DATABASE), "result": database_result},
                "localAdministrator": {
                    key: local_administrator[key] for key in ("username", "name", "email")
                },
                "storage": storage_result,
                "operationalIdentityBootstrap": operational_bootstrap_result,
                "identityRuntimeToken": runtime_token_result,
                "accounts": account_result,
                "setupApplication": setup_application,
                "shareDirectories": share_directories,
                "syncthing": syncthing_result,
                "services": service_result,
                "identity": verification,
                "preflight": preflight_ran,
                "journal": str(setup.JOURNAL_PATH),
            }
            setup.run_setup_stage(
                journal,
                "final-state",
                lambda: (setup.write_state(report), report)[1],
                postcondition=lambda _result: setup.setup_state_matches(report),
            )
            if not setup.setup_state_matches(report):
                journal.fail("Final setup state could not be verified", manual_recovery=True)
                raise setup.SetupError("Final setup state could not be verified")
            journal.complete(report)
            setup.publish_first_start_status(
                {
                    "schemaVersion": setup.SCHEMA_VERSION,
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
        except setup.JournalError as exc:
            raise setup.SetupError(str(exc)) from exc
        finally:
            password = ""
            administrator_password = ""
            authentik_administrator_password = ""
            for account in account_plan.get("accounts", []):
                if isinstance(account, dict):
                    account.pop("password", None)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request-file", required=True, type=pathlib.Path)
    parser.add_argument("--password-file", required=True, type=pathlib.Path)
    args = parser.parse_args()

    # Reuse the hardened request-file parser/cleanup and operation reservation
    # code while keeping the standalone first-run job as the sole web setup
    # orchestration entrypoint.
    original = setup._first_run_locked
    setup._first_run_locked = secure_first_run_locked
    try:
        result = setup.run_first_start_job(args.request_file, args.password_file)
    finally:
        setup._first_run_locked = original
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
