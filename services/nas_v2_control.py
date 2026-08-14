#!/usr/bin/env python3
"""Finite operator CLI for Managed Services V2 desired-state editing.

This command is not a controller or supervisor. It edits only ``services.yaml``,
starts the finite reconcile transaction, and reports live native systemd state.
Request-time authorization remains Caddy + Authentik and idle expiry remains
native systemd lease/timer behavior.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import sys
from typing import Any

from nas_common import parse_systemd_show, run_command
from nas_v2_editor import (
    ManagedServicesEditorError,
    read_document,
    replace_document,
    replace_document_value,
    set_service_mode,
    set_service_modes,
    status as desired_status,
)
from nas_v2_wake import WakeError, wake_service

DESIRED_PATH = pathlib.Path(
    os.environ.get("NAS_V2_DESIRED", os.environ.get("NAS_V2_SPEC", "/var/lib/nas-control/services.yaml"))
)
EFFECTIVE_PATH = pathlib.Path(os.environ.get("NAS_V2_EFFECTIVE", "/run/nas-control/effective.json"))
SCHEMA_PATH = pathlib.Path(os.environ.get("NAS_V2_SCHEMA", "/etc/nas-control/managed-services-v3.schema.json"))
RECONCILE_UNIT = os.environ.get("NAS_V2_RECONCILE_UNIT", "nas-managed-services-reconcile.service")
SYSTEMCTL = os.environ.get("NAS_V2_SYSTEMCTL", "systemctl")


def _is_directory_authority(path: pathlib.Path) -> bool:
    try:
        return path.is_dir()
    except OSError:
        return False


def _yaml_files(directory: pathlib.Path) -> list[pathlib.Path]:
    try:
        entries = list(directory.iterdir())
    except OSError:
        return []
    files = [p for p in entries if p.is_file() and p.suffix.lower() in {".yaml", ".yml"}]
    return sorted(files, key=lambda p: p.name)


def _read_authority_text(path: pathlib.Path) -> str:
    if _is_directory_authority(path):
        try:
            from nas_v2_spec import parse_yaml as _parse
            from nas_v2_editor import _render as _ed_render  # type: ignore

            doc = _parse(path)
            return _ed_render(doc)
        except Exception:
            files = _yaml_files(path)
            parts: list[str] = []
            for f in files:
                try:
                    parts.append(f.read_text(encoding="utf-8"))
                except OSError:
                    continue
            return "\n---\n".join(parts)
    return path.read_text(encoding="utf-8")


def _revision_for_path(path: pathlib.Path) -> str:
    if _is_directory_authority(path):
        files = _yaml_files(path)
        h = hashlib.sha256()
        for f in files:
            try:
                h.update(f.read_bytes())
            except OSError:
                continue
        return h.hexdigest()
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise ControlError(str(exc)) from exc


class ControlError(RuntimeError):
    """Raised when a finite V2 operator action fails."""


def _systemctl(*args: str, check: bool = True) -> None:
    result = run_command([SYSTEMCTL, *args], timeout_seconds=180)
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[:2000]
        raise ControlError(detail or f"systemctl {' '.join(args)} failed with exit {result.returncode}")


def _unit_snapshot(units: list[str]) -> dict[str, dict[str, str]]:
    if not units:
        return {}
    result = run_command(
        [
            SYSTEMCTL,
            "show",
            "--property=Id,LoadState,ActiveState,SubState,MemoryCurrent",
            *units,
        ],
        timeout_seconds=30,
    )
    if result.returncode != 0:
        return {}
    return parse_systemd_show(result.stdout)


def status() -> dict[str, Any]:
    try:
        value = desired_status(desired_path=DESIRED_PATH, effective_path=EFFECTIVE_PATH)
    except ManagedServicesEditorError as exc:
        raise ControlError(str(exc)) from exc

    rows = value.get("services")
    service_rows = rows if isinstance(rows, list) else []
    units = [
        unit["unit"]
        for row in service_rows
        if isinstance(row, dict)
        for unit in row.get("units", [])
        if isinstance(unit, dict) and isinstance(unit.get("unit"), str)
    ]
    snapshot = _unit_snapshot(list(dict.fromkeys(units)))
    for row in service_rows:
        if not isinstance(row, dict):
            continue
        unit_rows = row.get("units")
        if not isinstance(unit_rows, list):
            unit_rows = []
        running = False
        for unit_row in unit_rows:
            if not isinstance(unit_row, dict):
                continue
            unit = unit_row.get("unit")
            state = snapshot.get(unit, {}) if isinstance(unit, str) else {}
            active = state.get("ActiveState") == "active"
            running = running or active
            memory_raw = state.get("MemoryCurrent")
            try:
                memory = int(memory_raw) if memory_raw and memory_raw != "[not set]" else None
            except ValueError:
                memory = None
            unit_row.update(
                {
                    "active": active,
                    "activeState": state.get("ActiveState", "unknown"),
                    "subState": state.get("SubState", "unknown"),
                    "memoryBytes": memory,
                }
            )
        row["running"] = running
        row["resident"] = row.get("effectiveMode") == "always"
        row["healthState"] = "healthy" if row.get("effective") and running else "inactive"
        if row.get("effectiveMode") == "on-demand" and not running:
            row["healthState"] = "inactive"
        row["healthy"] = row["healthState"] == "healthy"
    value["services"] = service_rows
    value["schemaVersion"] = 3
    value["controller"] = "managed-services-v2"
    return value


def _read_mode_document(source: str) -> dict[str, str]:
    try:
        text = sys.stdin.read() if source == "-" else pathlib.Path(source).read_text(encoding="utf-8")
        value = json.loads(text)
    except (OSError, json.JSONDecodeError) as exc:
        raise ControlError(f"Unable to read service mode document from {source}: {exc}") from exc
    if not isinstance(value, dict) or any(
        not isinstance(key, str) or not isinstance(mode, str) for key, mode in value.items()
    ):
        raise ControlError("Service mode document must map service identifiers to string modes")
    return value


def _read_json_document(source: str) -> dict[str, Any]:
    try:
        text = sys.stdin.read() if source == "-" else pathlib.Path(source).read_text(encoding="utf-8")
        value = json.loads(text)
    except (OSError, json.JSONDecodeError) as exc:
        raise ControlError(f"Unable to read Managed Services V2 JSON document from {source}: {exc}") from exc
    if not isinstance(value, dict):
        raise ControlError("Managed Services V2 JSON document must contain an object")
    return value


def _reconcile() -> None:
    _systemctl("start", RECONCILE_UNIT)


def _rollback(previous: str, attempted: str | None, original: Exception) -> None:
    try:
        if attempted is not None:
            expected_revision = hashlib.sha256(attempted.encode("utf-8")).hexdigest()
            try:
                replace_document(
                    previous,
                    desired_path=DESIRED_PATH,
                    schema_path=SCHEMA_PATH,
                    expected_revision=expected_revision,
                )
            except ManagedServicesEditorError as exc:
                if "revision conflict" in str(exc).lower() or "expected" in str(exc).lower():
                    raise ControlError(
                        f"Managed Services V2 update failed but authority was already superseded; original={original}"
                    ) from original
                raise
        else:
            replace_document(previous, desired_path=DESIRED_PATH, schema_path=SCHEMA_PATH)
        _reconcile()
    except ControlError:
        raise
    except Exception as rollback_error:  # noqa: BLE001
        raise ControlError(
            "Managed Services V2 update failed and rollback was incomplete; "
            f"original={original}; rollback={rollback_error}"
        ) from original


def set_mode(service_id: str, mode: str) -> dict[str, Any]:
    try:
        previous = _read_authority_text(DESIRED_PATH)
        result = set_service_mode(
            service_id,
            mode,
            desired_path=DESIRED_PATH,
            schema_path=SCHEMA_PATH,
        )
        attempted = _read_authority_text(DESIRED_PATH)
        try:
            _reconcile()
        except Exception as exc:
            _rollback(previous, attempted, exc)
            raise
    except (OSError, ManagedServicesEditorError) as exc:
        raise ControlError(str(exc)) from exc
    result["status"] = status()
    return result


def set_modes(modes: dict[str, str]) -> dict[str, Any]:
    try:
        previous = _read_authority_text(DESIRED_PATH)
        result = set_service_modes(
            modes,
            desired_path=DESIRED_PATH,
            schema_path=SCHEMA_PATH,
        )
        attempted = _read_authority_text(DESIRED_PATH)
        try:
            _reconcile()
        except Exception as exc:
            _rollback(previous, attempted, exc)
            raise
    except (OSError, ManagedServicesEditorError) as exc:
        raise ControlError(str(exc)) from exc
    result["status"] = status()
    return result


def replace_from_source(source: str) -> dict[str, Any]:
    try:
        text = sys.stdin.read() if source == "-" else pathlib.Path(source).read_text(encoding="utf-8")
        previous = _read_authority_text(DESIRED_PATH)
        result = replace_document(text, desired_path=DESIRED_PATH, schema_path=SCHEMA_PATH)
        try:
            _reconcile()
        except Exception as exc:
            _rollback(previous, text, exc)
            raise
        return result
    except (OSError, ManagedServicesEditorError, ControlError) as exc:
        raise ControlError(str(exc)) from exc


def replace_json_from_source(source: str) -> dict[str, Any]:
    try:
        value = _read_json_document(source)
        previous = _read_authority_text(DESIRED_PATH)
        result = replace_document_value(value, desired_path=DESIRED_PATH, schema_path=SCHEMA_PATH)
        attempted = _read_authority_text(DESIRED_PATH)
        try:
            _reconcile()
        except Exception as exc:
            _rollback(previous, attempted, exc)
            raise
        return result
    except (OSError, ManagedServicesEditorError, ControlError) as exc:
        raise ControlError(str(exc)) from exc


def document() -> dict[str, Any]:
    try:
        return read_document(desired_path=DESIRED_PATH, schema_path=SCHEMA_PATH)
    except ManagedServicesEditorError as exc:
        raise ControlError(str(exc)) from exc


def reconcile() -> dict[str, Any]:
    _reconcile()
    return {"ok": True, "status": status()}


def wake(service_id: str) -> dict[str, Any]:
    try:
        effective = json.loads(EFFECTIVE_PATH.read_text(encoding="utf-8"))
        if not isinstance(effective, dict):
            raise ControlError("Managed Services V2 effective state is invalid")
        wake_service(effective, service_id, systemctl=SYSTEMCTL)
    except (OSError, json.JSONDecodeError, WakeError) as exc:
        raise ControlError(str(exc)) from exc
    return {"ok": True, "service": service_id, "status": status()}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status", help="Report policy and live native systemd state")
    sub.add_parser("reconcile", aliases=["apply"], help="Run the finite V2 reconcile transaction")
    sub.add_parser("document", help="Return editable YAML, parsed state, and JSON Schema")

    set_parser = sub.add_parser("set", help="Set one V2 service to off, on-demand, or always")
    set_parser.add_argument("service", help="Managed Services V2 service identifier")
    set_parser.add_argument("mode", choices=["off", "on-demand", "always"])

    set_many_parser = sub.add_parser("set-many", help="Apply service modes in one desired-state transaction")
    set_many_parser.add_argument("source", help="JSON object file or - for standard input")

    replace_parser = sub.add_parser("replace-document", help="Validate, replace, and reconcile the desired YAML")
    replace_parser.add_argument("source", help="YAML file or - for standard input")

    replace_json_parser = sub.add_parser(
        "replace-json-document",
        help="Validate a schema-editor JSON value, render YAML, replace authority, and reconcile",
    )
    replace_json_parser.add_argument("source", help="JSON object file or - for standard input")

    wake_parser = sub.add_parser("wake", help="Acquire the native V2 on-demand lease for one service")
    wake_parser.add_argument("service", help="Managed Services V2 service identifier")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "status":
            result = status()
        elif args.command in {"reconcile", "apply"}:
            result = reconcile()
        elif args.command == "document":
            result = document()
        elif args.command == "set":
            result = set_mode(args.service, args.mode)
        elif args.command == "set-many":
            result = set_modes(_read_mode_document(args.source))
        elif args.command == "replace-document":
            result = replace_from_source(args.source)
        elif args.command == "replace-json-document":
            result = replace_json_from_source(args.source)
        elif args.command == "wake":
            result = wake(args.service)
        else:
            raise AssertionError(f"Unhandled command {args.command!r}")
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except ControlError as exc:
        print(f"nas-managed-services-control: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
