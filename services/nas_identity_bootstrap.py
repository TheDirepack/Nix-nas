#!/usr/bin/env python3
"""Setup-only Authentik mutations performed with temporary bootstrap authority.

Steady-state ``nas-identity-sync`` uses the scoped read-only automation token.
This executable exists only for the finite first-run transaction so account
creation, runtime-token issuance, and bootstrap retirement do not accidentally
expand the runtime service account's permissions.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Mapping
from typing import Any

import nas_identity_sync as identity
from nas_identity_model import SyncError, user_detail_pk


def _bootstrap_token() -> str:
    return identity.authentik_token(bootstrap=True)


def _runtime_token() -> str:
    return identity.authentik_token()


def _load_plan() -> dict[str, Any]:
    try:
        value = json.load(sys.stdin)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SyncError("Bootstrap account plan is invalid JSON") from exc
    if not isinstance(value, dict):
        raise SyncError("Bootstrap account plan must be a JSON object")
    return value


def apply_accounts(*, confirm_password_reapply: bool) -> dict[str, Any]:
    return identity.apply_account_plan(
        _bootstrap_token(),
        _load_plan(),
        confirm_password_reapply=confirm_password_reapply,
    )


def provision_runtime_token() -> dict[str, Any]:
    return identity.provision_runtime_token(_bootstrap_token())


def _expect_forbidden(action: str, callback: Any) -> None:
    try:
        callback()
    except SyncError as exc:
        if "HTTP 403" in str(exc):
            return
        raise SyncError(f"Runtime token {action} probe was not permission-denied: {exc}") from exc
    raise SyncError(f"Runtime token unexpectedly authorized {action}")


def verify_runtime_read_only(administrator: str) -> dict[str, Any]:
    runtime = _runtime_token()
    read_result = identity.verify_token(runtime)
    if read_result.get("ok") is not True:
        raise SyncError("Runtime token cannot read required identity projections")

    # Invalid bodies make these probes mutation-free. A 400 would prove the
    # token reached validation with excessive privilege; only 403 is accepted.
    _expect_forbidden(
        "user creation",
        lambda: identity.authentik_request(runtime, "core/users/", method="POST", body={}),
    )

    users = identity.authentik_list(_bootstrap_token(), "core/users/?include_groups=true")
    replacement = next((item for item in users if item.get("username") == administrator), None)
    if not isinstance(replacement, Mapping):
        raise SyncError(f"Permanent Authentik administrator does not exist: {administrator}")
    pk = user_detail_pk(replacement)
    _expect_forbidden(
        "password reset",
        lambda: identity.authentik_request(runtime, f"core/users/{pk}/set_password/", method="POST", body={}),
    )
    return {
        "ok": True,
        "administrator": administrator,
        "allowed": ["authentik_core.view_user", "authentik_core.view_group"],
        "denied": ["authentik_core.add_user", "authentik_core.reset_user_password"],
    }


def _runtime_confirms_bootstrap_absent(administrator: str) -> bool:
    users = identity.authentik_list(_runtime_token(), "core/users/?include_groups=true")
    replacement = next((item for item in users if item.get("username") == administrator), None)
    bootstrap = next((item for item in users if item.get("username") == "akadmin"), None)
    return isinstance(replacement, Mapping) and replacement.get("is_active") is True and bootstrap is None


def retire_bootstrap(administrator: str) -> dict[str, Any]:
    # If power failed after akadmin deletion but before the outer journal write,
    # the bootstrap token is already invalid. The runtime token is sufficient to
    # verify that the permanent administrator exists and akadmin is gone.
    try:
        token = _bootstrap_token()
    except SyncError:
        if _runtime_confirms_bootstrap_absent(administrator):
            return {
                "retiredBootstrapAdministrator": "akadmin",
                "verifiedAdministrator": administrator,
                "bootstrapTokenRejected": True,
                "resumed": True,
            }
        raise

    try:
        result = identity.retire_bootstrap_administrator(token, administrator)
    except SyncError as exc:
        if ("HTTP 401" in str(exc) or "HTTP 403" in str(exc)) and _runtime_confirms_bootstrap_absent(administrator):
            return {
                "retiredBootstrapAdministrator": "akadmin",
                "verifiedAdministrator": administrator,
                "bootstrapTokenRejected": True,
                "resumed": True,
            }
        raise

    deadline = time.monotonic() + 15.0
    while True:
        try:
            identity.authentik_list(token, "core/users/?page_size=1")
        except SyncError as exc:
            if "HTTP 401" in str(exc) or "HTTP 403" in str(exc):
                return {**result, "bootstrapTokenRejected": True, "resumed": False}
            raise
        if time.monotonic() >= deadline:
            raise SyncError("Authentik bootstrap token remains authorized after deleting akadmin")
        time.sleep(0.5)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    apply_parser = subparsers.add_parser("apply-accounts")
    apply_parser.add_argument("--confirm-password-reapply", action="store_true")
    subparsers.add_parser("provision-runtime-token")
    verify_parser = subparsers.add_parser("verify-runtime-read-only")
    verify_parser.add_argument("administrator")
    retire_parser = subparsers.add_parser("retire-bootstrap")
    retire_parser.add_argument("administrator")
    args = parser.parse_args()

    try:
        operation = identity.identity_mutation_operation(f"identity-bootstrap-{args.command}")
        lock_command = "apply-accounts" if args.command == "apply-accounts" else args.command
        with operation, identity.identity_command_lock(lock_command):
            if args.command == "apply-accounts":
                result = apply_accounts(confirm_password_reapply=args.confirm_password_reapply)
            elif args.command == "provision-runtime-token":
                result = provision_runtime_token()
            elif args.command == "verify-runtime-read-only":
                result = verify_runtime_read_only(args.administrator)
            elif args.command == "retire-bootstrap":
                result = retire_bootstrap(args.administrator)
            else:  # pragma: no cover
                raise AssertionError(args.command)
    except (SyncError, OSError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 1

    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
