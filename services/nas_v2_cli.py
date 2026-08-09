#!/usr/bin/env python3
"""Public CLI for the canonical Managed Services V2 schema runtime."""

from __future__ import annotations

import argparse
import json
import pathlib

import nas_v2_apply as apply_engine
import nas_v2_lifecycle as lifecycle
import nas_v2_runtime as runtime
from nas_v2_schedules import reconcile_schedules


def _load(args: argparse.Namespace) -> dict:
    return runtime.load_document(args.spec, args.schema)


def _print(value: object) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nas-v2-runtime")
    parser.add_argument(
        "command",
        choices=(
            "validate",
            "compile",
            "plan",
            "apply",
            "start",
            "stop",
            "touch",
            "reap",
            "run-job",
            "session-begin",
            "session-touch",
            "session-end",
        ),
    )
    parser.add_argument("target", nargs="?")
    parser.add_argument("--session-id")
    parser.add_argument("--spec", type=pathlib.Path, default=runtime.DEFAULT_SPEC)
    parser.add_argument("--schema", type=pathlib.Path, default=runtime.DEFAULT_SCHEMA)
    parser.add_argument("--effective", type=pathlib.Path, default=runtime.DEFAULT_EFFECTIVE)
    parser.add_argument("--skip-authentik", action="store_true")
    args = parser.parse_args(argv)

    try:
        document = _load(args)
        if args.command == "validate":
            _print(document)
            return 0
        if args.command == "compile":
            _print(runtime.compile_effective(document))
            return 0
        if args.command in {"plan", "apply"}:
            dry_run = args.command == "plan"
            result = apply_engine.apply_document(
                document,
                effective_path=args.effective,
                dry_run=dry_run,
                authentik=not args.skip_authentik,
            )
            result["schedules"] = reconcile_schedules(
                document,
                spec_path=str(args.spec),
                schema_path=str(args.schema),
                dry_run=dry_run,
            )
            _print(result)
            return 0

        if args.command == "reap":
            _print(lifecycle.reap(document))
            return 0
        if args.command == "session-touch":
            session_id = args.session_id or args.target
            if not session_id:
                parser.error("session-touch requires --session-id or target")
            _print(lifecycle.session_touch(session_id, document))
            return 0
        if args.command == "session-end":
            session_id = args.session_id or args.target
            if not session_id:
                parser.error("session-end requires --session-id or target")
            _print(lifecycle.session_end(session_id, document))
            return 0

        if not args.target:
            parser.error(f"{args.command} requires a service target")
        if args.command == "start":
            _print(lifecycle.start_service(args.target, document))
        elif args.command == "stop":
            _print(lifecycle.stop_service(args.target, document))
        elif args.command == "touch":
            _print(lifecycle.touch_service(args.target, document))
        elif args.command == "run-job":
            _print(lifecycle.run_job(args.target, document))
        elif args.command == "session-begin":
            if not args.session_id:
                parser.error("session-begin requires --session-id")
            _print(lifecycle.session_begin(args.target, args.session_id, document))
        else:  # pragma: no cover - argparse guards this branch
            parser.error(f"unsupported command {args.command}")
    except Exception as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
