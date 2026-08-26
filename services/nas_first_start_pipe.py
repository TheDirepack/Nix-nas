#!/usr/bin/env python3
"""Pipe-only secret ingress for the hardened first-start worker.

The authenticated setup API persists only the non-secret job request and the
per-job capability. Human passwords are delivered exactly once on this
process's standard input by ``systemd-run --pipe`` and are never named in the
filesystem, environment, or command line.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys
import time
from typing import Any

import nas_first_start as first_start
import nas_setup as setup
from nas_operation_lock import cancel_reservation

_MAX_SECRET_BYTES = 16 * 1024


def _read_secret_payload() -> dict[str, Any]:
    raw = sys.stdin.buffer.read(_MAX_SECRET_BYTES + 1)
    if len(raw) > _MAX_SECRET_BYTES:
        raise setup.SetupError("First-start secret payload exceeds its size limit")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise setup.SetupError("First-start secret payload is invalid") from exc
    if not isinstance(value, dict) or set(value) != {
        "keepass",
        "administrator",
        "authentikAdministratorPassword",
    }:
        raise setup.SetupError("First-start secret payload contract is invalid")
    return value


def run_first_start_job(request_file: pathlib.Path) -> dict[str, Any]:
    reservation_token: str | None = None
    password = ""
    administrator_password = ""
    authentik_administrator_password = ""
    result_path: pathlib.Path | None = None
    job_id: str | None = None
    secrets_payload: dict[str, Any] = {}
    try:
        request_text = setup._read_secure_job_file(request_file, "First-start job request", max_bytes=64 * 1024)
        try:
            request = json.loads(request_text)
        except json.JSONDecodeError as exc:
            raise setup.SetupError("First-start job request is invalid") from exc
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
            raise setup.SetupError("First-start job request contract is invalid")
        candidate = request.get("reservationToken")
        if isinstance(candidate, str) and re.fullmatch(r"[0-9a-f]{32}", candidate):
            reservation_token = candidate
        if reservation_token is None:
            raise setup.SetupError("First-start reservation token is invalid")
        job_id = request.get("jobId")
        if not isinstance(job_id, str) or not re.fullmatch(r"[0-9a-f]{24}", job_id):
            raise setup.SetupError("First-start job identifier is invalid")

        result_root = setup.STATE_PATH.parent / "jobs"
        result_path = result_root / f"{job_id}.json"
        result_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(result_root, 0o700)
        setup.prune_first_start_job_results(result_root, keep=result_path)

        config = request.get("config")
        plan_digest = request.get("planDigest")
        devices = request.get("devices")
        if not isinstance(config, str) or not pathlib.Path(config).is_absolute():
            raise setup.SetupError("First-start job configuration path is invalid")
        if not isinstance(plan_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", plan_digest):
            raise setup.SetupError("First-start job plan digest is invalid")
        if (
            not isinstance(devices, list)
            or not all(isinstance(item, str) and item for item in devices)
            or len(devices) != len(set(devices))
        ):
            raise setup.SetupError("First-start job devices are invalid")
        if not isinstance(request.get("allowDestructiveStorage"), bool) or not isinstance(
            request.get("confirmPasswordReapply"), bool
        ):
            raise setup.SetupError("First-start job confirmation flags are invalid")

        secrets_payload = _read_secret_payload()
        raw_password = secrets_payload.get("keepass")
        if not isinstance(raw_password, str):
            raise setup.SetupError("First-start KeePass database password is invalid")
        password = setup.normalize_secret_line(raw_password, "KeePass database password")
        administrator = secrets_payload.get("administrator")
        if not isinstance(administrator, dict) or set(administrator) != {"username", "name", "email", "password"}:
            raise setup.SetupError("First-start administrator secret payload is invalid")
        raw_linux_password = administrator.get("password")
        if not isinstance(raw_linux_password, str):
            raise setup.SetupError("First-start Linux administrator password is invalid")
        administrator_password = setup.normalize_secret_line(raw_linux_password, "Linux administrator password")
        normalized_administrator = {**administrator, "password": administrator_password}
        raw_authentik_password = secrets_payload.get("authentikAdministratorPassword")
        if not isinstance(raw_authentik_password, str):
            raise setup.SetupError("First-start Authentik administrator password is invalid")
        authentik_administrator_password = setup.normalize_secret_line(
            raw_authentik_password, "Authentik administrator password"
        )

        # The request is a one-shot capability to begin this exact transaction.
        # Delete it before mutation starts so a resumed operation cannot be
        # launched by replaying stale API state.
        request_file.unlink(missing_ok=True)
        args = argparse.Namespace(
            config=config,
            keepass_password_stdin=False,
            keepass_password_value=password,
            administrator=normalized_administrator,
            authentik_administrator_password=authentik_administrator_password,
            create_database=True,
            confirm_storage_device=list(devices),
            allow_destructive_storage=request["allowDestructiveStorage"],
            confirm_plan_digest=plan_digest,
            skip_preflight=False,
            confirm_password_reapply=request["confirmPasswordReapply"],
            reservation_token=reservation_token,
        )
        setup.atomic_write_json(
            result_path,
            {"schemaVersion": 1, "jobId": job_id, "status": "running", "startedAt": int(time.time())},
        )
        result = first_start.secure_first_run(args)
        setup.atomic_write_json(
            result_path,
            {
                "schemaVersion": 1,
                "jobId": job_id,
                "status": "complete",
                "completedAt": int(time.time()),
                "result": result,
            },
        )
        setup.prune_first_start_job_results(result_root, keep=result_path)
        return result
    except Exception as exc:
        if result_path is not None and job_id is not None:
            setup.atomic_write_json(
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
        password = administrator_password = authentik_administrator_password = ""
        secrets_payload.clear()
        request_file.unlink(missing_ok=True)
        if reservation_token is not None:
            cancel_reservation(reservation_token)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request-file", required=True, type=pathlib.Path)
    args = parser.parse_args()
    try:
        result = run_first_start_job(args.request_file)
    except (setup.SetupError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"nas-first-start: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
