#!/usr/bin/env python3
"""Execute a V2 generated exec workload without passing user data through a shell."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
from typing import Any


class ExecRunnerError(RuntimeError):
    """Raised when a generated exec descriptor is malformed."""


def load_descriptor(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ExecRunnerError(f"unable to read exec descriptor {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ExecRunnerError("exec descriptor must be an object")
    return value


def validate_descriptor(value: dict[str, Any]) -> tuple[list[str], str | None]:
    command = value.get("command")
    if not isinstance(command, list) or not command or not all(isinstance(item, str) and item for item in command):
        raise ExecRunnerError("exec descriptor command must be a non-empty string array")
    executable = pathlib.PurePosixPath(command[0])
    if command[0] == "/" or str(executable) == "/" or not executable.is_absolute() or ".." in executable.parts:
        raise ExecRunnerError("exec descriptor executable must be an absolute safe path")

    working_directory = value.get("workingDirectory")
    if working_directory is not None:
        if not isinstance(working_directory, str):
            raise ExecRunnerError("workingDirectory must be a string")
        directory = pathlib.PurePosixPath(working_directory)
        if not directory.is_absolute() or ".." in directory.parts:
            raise ExecRunnerError("workingDirectory must be an absolute safe path")

    return command, working_directory


def run_descriptor(value: dict[str, Any]) -> None:
    command, working_directory = validate_descriptor(value)
    if working_directory is not None:
        os.chdir(working_directory)
    os.execve(command[0], command, os.environ.copy())


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Execute a generated Managed Services V2 exec descriptor")
    parser.add_argument("--config", required=True, type=pathlib.Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        run_descriptor(load_descriptor(args.config))
    except (ExecRunnerError, OSError) as exc:
        print(f"nas-v2-exec-runner: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
