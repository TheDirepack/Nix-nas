#!/usr/bin/env python3
"""Thin offline/debug frontend for the Managed Services V2 compiler."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys


def _path_defaults() -> tuple[pathlib.Path, pathlib.Path, pathlib.Path | None]:
    spec = pathlib.Path(
        os.environ.get("NAS_V2_DESIRED") or os.environ.get("NAS_V2_SPEC") or "/var/lib/nas-control/services.yaml"
    )
    schema = pathlib.Path(os.environ.get("NAS_V2_SCHEMA", "/etc/nas-control/managed-services-v3.schema.json"))
    raw_platform = os.environ.get("NAS_V2_PLATFORM", "/etc/nas-control/platform-capabilities.json")
    platform = pathlib.Path(raw_platform) if raw_platform else None
    return spec, schema, platform if platform is not None and platform.exists() else None


def _add_common_options(parser: argparse.ArgumentParser) -> None:
    default_spec, default_schema, default_platform = _path_defaults()
    parser.add_argument("--spec", type=pathlib.Path, default=default_spec, help="desired services.yaml path")
    parser.add_argument("--schema", type=pathlib.Path, default=default_schema, help="V3 JSON Schema path")
    parser.add_argument(
        "--platform",
        type=pathlib.Path,
        default=default_platform,
        help="platform capability inventory (omit to compile without host capabilities)",
    )
    parser.add_argument("--no-platform", action="store_true", help="do not use a platform capability inventory")
    parser.add_argument("--output", type=pathlib.Path, help="write effective/plan JSON to this path instead of stdout")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="nas-v2", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for command, help_text in (
        ("validate", "validate desired state offline"),
        ("effective", "compile and print the normalized effective model offline"),
        ("plan", "compile and print the deterministic native plan offline"),
        ("apply", "run the normal finite reconciliation path"),
    ):
        child = sub.add_parser(command, help=help_text)
        _add_common_options(child)
        if command == "apply":
            child.add_argument("--history-repository", type=pathlib.Path)
            child.add_argument("--git-bin", default=os.environ.get("NAS_V2_GIT_BIN", "git"))
    return parser


def _compile(args: argparse.Namespace) -> dict:
    # Keep imports below command dispatch so ``nas-v2 --help`` remains usable
    # in a minimal developer environment without the compiler dependencies.
    from nas_v2_apply import _compile_document_with_platform
    from nas_v2_spec import load_schema, parse_yaml

    platform = None if args.no_platform else args.platform
    if platform is not None and not platform.is_file():
        raise RuntimeError(f"platform capability inventory does not exist: {platform}")
    return _compile_document_with_platform(parse_yaml(args.spec), load_schema(args.schema), platform)


def _write_json(value: object, output: pathlib.Path | None) -> None:
    rendered = json.dumps(value, indent=2, sort_keys=True) + "\n"
    if output is None:
        sys.stdout.write(rendered)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8")


def _apply(args: argparse.Namespace) -> int:
    import nas_v2_entry

    platform = None if args.no_platform else args.platform
    if platform is not None and not platform.is_file():
        raise RuntimeError(f"platform capability inventory does not exist: {platform}")

    effective_output = os.environ.get("NAS_V2_EFFECTIVE", "/run/nas-control/effective.json")
    if args.output is not None:
        effective_output = str(args.output)
    overrides = {
        "NAS_V2_DESIRED": str(args.spec),
        "NAS_V2_SCHEMA": str(args.schema),
        "NAS_V2_PLATFORM": str(platform) if platform is not None else None,
        "NAS_V2_EFFECTIVE": effective_output,
        "NAS_V2_GIT_BIN": args.git_bin,
        "NAS_V2_HISTORY_REPOSITORY": str(args.history_repository) if args.history_repository is not None else None,
    }
    status = nas_v2_entry.main(overrides=overrides)
    if status == 0:
        _write_json({"ok": True, "command": "apply", "spec": str(args.spec)}, None)
    return status


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "apply":
            return _apply(args)
        if args.command == "validate":
            effective = _compile(args)
            _write_json({"ok": True, "schemaVersion": effective["schemaVersion"]}, args.output)
            return 0
        effective = _compile(args)
        if args.command == "effective":
            _write_json(effective, args.output)
            return 0
        if args.command == "plan":
            from nas_v2_plan import build_plan

            _write_json(build_plan(effective), args.output)
            return 0
        raise ValueError(f"unsupported command: {args.command}")
    except Exception as exc:
        print(
            json.dumps(
                {"ok": False, "error": {"type": type(exc).__name__, "message": str(exc)}},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
