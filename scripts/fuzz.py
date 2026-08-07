#!/usr/bin/env python3
"""Deterministic fuzz harness for NAS-owned parsers and privileged request boundaries."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import pathlib
import random
import string
import sys
import tempfile
import traceback
from collections.abc import Callable
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))

import nas_alert_router
import nas_common
import nas_cockpit_api
import nas_doctor
import nas_feature_control
import nas_feature_model
import nas_identity_model
import nas_identity_sync
import nas_logging
import nas_migrate_state
import nas_operation_journal
import nas_operation_lock
import nas_state
import nas_setup_config
import nas_syncthing_devices

ALPHABET = string.ascii_letters + string.digits + string.punctuation + " \t\r\n\x00éΩ中\u2028\u202e"


class ExpectedReject(Exception):
    pass


def text(rng: random.Random, maximum: int) -> str:
    return "".join(rng.choice(ALPHABET) for _ in range(rng.randrange(maximum + 1)))


def target_groups(rng: random.Random) -> None:
    with contextlib.redirect_stderr(io.StringIO()):
        result = nas_common.split_groups(text(rng, 9000))
    if len(result) > nas_common.MAX_GROUPS:
        raise AssertionError("group count exceeded bound")
    for group in result:
        if len(group) > nas_common.MAX_GROUP_NAME_LENGTH:
            raise AssertionError("group length exceeded bound")
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in group):
            raise AssertionError("control character survived group parsing")


def target_secret(rng: random.Random) -> None:
    value = text(rng, 4200)
    try:
        result = nas_setup_config.normalize_secret_line(value, "fuzz-secret")
    except nas_setup_config.SetupError:
        return
    if not result or len(result) > 4096 or any(ch in result for ch in "\r\n\x00"):
        raise AssertionError("secret normalizer returned unsafe value")


def target_username(rng: random.Random) -> None:
    value = text(rng, 300)
    try:
        result = nas_syncthing_devices.validate_username(value)
    except nas_syncthing_devices.DeviceError:
        return
    if result != value or "/" in result or "\\" in result:
        raise AssertionError("username normalization changed or accepted a path separator")


def target_alert(rng: random.Random) -> None:
    value = text(rng, 7000)
    alert = nas_alert_router.normalize_alert(
        {
            "labels": {"alertname": value, "instance": value, "severity": value},
            "annotations": {"description": value},
        }
    )
    if len(alert.title) > 256 or len(alert.message) > 4096:
        raise AssertionError("alert output exceeded bound")


def target_feature_catalog(rng: random.Random) -> None:
    scalar: Any = rng.choice([None, True, False, 0, 1, "", "always", [], {}])
    candidate: Any = scalar
    if rng.randrange(2):
        candidate = {text(rng, 30): rng.choice([None, True, False, 0, "off", [], {}]) for _ in range(rng.randrange(5))}
    try:
        nas_feature_control.normalize_catalog(candidate)
    except (nas_feature_control.FeatureError, ValueError, TypeError, KeyError):
        return


def target_setup_json(rng: random.Random) -> None:
    candidate = {
        "schemaVersion": rng.choice([1, 2, text(rng, 12)]),
        "accounts": rng.choice([[], {}, text(rng, 80)]),
        "features": rng.choice([{}, [], text(rng, 80)]),
    }
    candidate = json.loads(json.dumps(candidate))
    try:
        nas_setup_config.normalize_config(candidate)
    except nas_setup_config.SetupError:
        return


def target_feature_identifier(rng: random.Random) -> None:
    value = text(rng, 512)
    try:
        accepted = nas_cockpit_api.validate_argument(value, nas_cockpit_api.FEATURE_RE, "feature identifier")
    except nas_cockpit_api.ApiError:
        return
    if accepted != value or nas_cockpit_api.FEATURE_RE.fullmatch(accepted) is None:
        raise AssertionError("feature identifier validator returned an unsafe value")


def target_state_member(rng: random.Random) -> None:
    value = text(rng, 2048)
    try:
        accepted = nas_state.safe_member_name(value)
    except nas_state.StateError:
        return
    if accepted.is_absolute() or ".." in accepted.parts or "" in accepted.parts:
        raise AssertionError("state bundle member escaped the archive root")
    if any(ord(character) < 32 or ord(character) == 127 for character in accepted.as_posix()):
        raise AssertionError("state bundle member retained control characters")
    if len(accepted.as_posix().encode("utf-8")) > nas_state.MAX_ARCHIVE_MEMBER_NAME_BYTES:
        raise AssertionError("state bundle member exceeded name bound")


def target_identity_model(rng: random.Random) -> None:
    username = text(rng, 256)
    data = {"groups": [], "users": [{"pk": "1", "username": username, "is_active": True}]}
    try:
        model = nas_identity_model.build_model(data)
    except nas_identity_model.SyncError:
        return
    for user in model.users:
        if user.uid != username:
            raise AssertionError("identity model unexpectedly rewrote a username")


def target_structured_logging(rng: random.Random) -> None:
    value = text(rng, 12000)
    sanitized = nas_logging.sanitize({"token": value, "message": value, "nested": {"password": value}})
    if sanitized.get("token") != "[redacted]" or sanitized["nested"].get("password") != "[redacted]":
        raise AssertionError("logging sanitizer leaked a sensitive field")
    if len(sanitized.get("message", "")) > nas_logging.MAX_TEXT_LENGTH + len("[truncated]"):
        raise AssertionError("logging sanitizer returned unbounded text")


def target_doctor_json(rng: random.Random) -> None:
    value = text(rng, 3000)
    with tempfile.TemporaryDirectory() as temporary:
        path = pathlib.Path(temporary) / "state.json"
        path.write_text(value, encoding="utf-8")
        try:
            parsed = nas_doctor._read_json(path)
        except ValueError:
            return
        if not isinstance(parsed, dict):
            raise AssertionError("doctor accepted a non-object JSON state")


def target_migration_schema(rng: random.Random) -> None:
    values: list[Any] = [None, True, False, text(rng, 80), rng.randrange(-100, 100), [], {}]
    candidate = {"schemaVersion": rng.choice(values)}
    try:
        result = nas_migrate_state._schema(candidate)
    except nas_migrate_state.MigrationError:
        return
    if result is not None and (isinstance(result, bool) or not isinstance(result, int)):
        raise AssertionError("migration schema accepted a non-integer")


def target_identity_error(rng: random.Random) -> None:
    raw = text(rng, 8000).encode("utf-8", "replace")
    result = nas_identity_sync.sanitize_error_payload(raw)
    if not isinstance(result, str) or len(result) > 500:
        raise AssertionError("identity error sanitizer returned an invalid or unbounded result")
    lowered = result.lower()
    # JSON key redaction must win whenever the generated input happens to parse.
    for key in ("password", "secret", "token"):
        if f'"{key}":' in lowered and "[redacted]" not in lowered:
            raise AssertionError("identity error sanitizer exposed a sensitive field")


def target_operation_classes(rng: random.Random) -> None:
    values = [text(rng, 80) for _ in range(rng.randrange(0, 12))]
    try:
        normalized = nas_operation_lock._normalize_classes(values)
    except ValueError:
        return
    if not normalized or tuple(sorted(set(normalized))) != normalized:
        raise AssertionError("operation classes were not canonicalized")
    if any(item not in nas_operation_lock.KNOWN_CLASSES for item in normalized):
        raise AssertionError("unknown operation class survived validation")


def target_operation_journal(rng: random.Random) -> None:
    raw = text(rng, 3000)
    with tempfile.TemporaryDirectory() as temporary:
        path = pathlib.Path(temporary) / "journal.json"
        path.write_text(raw, encoding="utf-8")
        try:
            value = nas_operation_journal.load_json(path)
        except nas_operation_journal.JournalError:
            return
        if value is not None and not isinstance(value, dict):
            raise AssertionError("journal parser accepted a non-object")


def target_authorization(rng: random.Random) -> None:
    access = rng.choice(["network", "authenticated", "admin", "files", "ai", text(rng, 40)])
    headers = {"Remote-User": text(rng, 80), "Remote-Groups": text(rng, 9000)}
    with contextlib.redirect_stderr(io.StringIO()):
        result = nas_feature_control.authorize(
            {"access": access}, headers, scope=rng.choice(["", "files", "ai", "admin"])
        )
    if not isinstance(result, bool):
        raise AssertionError("authorization boundary returned a non-boolean")


def target_endpoint_label(rng: random.Random) -> None:
    value = text(rng, 2000)
    try:
        result = nas_identity_sync.endpoint_label(value)
    except ValueError:
        return
    if "?" in result or "#" in result:
        raise AssertionError("diagnostic endpoint label retained query or fragment data")


def target_loopback_http_url(rng: random.Random) -> None:
    value: Any = rng.choice([text(rng, 4096), None, True, False, rng.randrange(-100000, 100000), [], {}])
    accepted = nas_feature_model.valid_loopback_http_url(value)
    if not isinstance(accepted, bool):
        raise AssertionError("loopback URL validator returned a non-boolean")
    if not accepted:
        return
    assert isinstance(value, str)
    import urllib.parse

    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise AssertionError("loopback URL validator accepted a non-loopback target")
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise AssertionError("loopback URL validator accepted credentials or a fragment")
    if parsed.port is not None and not 0 < parsed.port < 65536:
        raise AssertionError("loopback URL validator accepted an invalid port")


TARGETS: dict[str, Callable[[random.Random], None]] = {
    "groups": target_groups,
    "secret": target_secret,
    "username": target_username,
    "alert": target_alert,
    "feature-catalog": target_feature_catalog,
    "setup-json": target_setup_json,
    "feature-identifier": target_feature_identifier,
    "state-member": target_state_member,
    "identity-model": target_identity_model,
    "structured-logging": target_structured_logging,
    "doctor-json": target_doctor_json,
    "migration-schema": target_migration_schema,
    "identity-error": target_identity_error,
    "operation-classes": target_operation_classes,
    "operation-journal": target_operation_journal,
    "authorization": target_authorization,
    "endpoint-label": target_endpoint_label,
    "loopback-http-url": target_loopback_http_url,
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=["all", *TARGETS], default="all")
    parser.add_argument("--cases", type=int, default=2000)
    parser.add_argument("--seed", type=lambda value: int(value, 0), default=0x4E41533232)
    parser.add_argument("--crash-dir", type=pathlib.Path, default=ROOT / ".fuzz-crashes")
    args = parser.parse_args()
    if args.cases < 1 or args.cases > 1_000_000:
        parser.error("--cases must be from 1 through 1000000")

    targets = TARGETS if args.target == "all" else {args.target: TARGETS[args.target]}
    total = 0
    for target_name, target in targets.items():
        rng = random.Random(args.seed ^ sum(map(ord, target_name)))
        for index in range(args.cases):
            try:
                target(rng)
            except Exception as exc:
                args.crash_dir.mkdir(parents=True, exist_ok=True)
                crash = args.crash_dir / f"{target_name}-{args.seed:x}-{index}.txt"
                crash.write_text(
                    f"target={target_name}\nseed={args.seed}\ncase={index}\nerror={exc!r}\n\n{traceback.format_exc()}",
                    encoding="utf-8",
                )
                print(f"fuzz failure: {target_name} case {index}; replay seed {args.seed:#x}; {crash}", file=sys.stderr)
                return 1
            total += 1
        print(f"fuzz ok: {target_name}: {args.cases} cases")
    print(f"fuzz complete: {total} cases, seed={args.seed:#x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
