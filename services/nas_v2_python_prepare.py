#!/usr/bin/env python3
"""Prepare an isolated per-service Python environment for Managed Services V2."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
from typing import Any


class PythonPrepareError(RuntimeError):
    """Raised when a generated Python runtime descriptor is invalid or cannot be prepared."""


SERVICE_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
APP_ROOT = pathlib.Path("/var/lib/nas-control/apps")
VENV_ROOT = pathlib.Path("/var/lib/nas-control/venvs")
_STATE_FILE = ".nas-v2-environment.json"


def _read_descriptor(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PythonPrepareError(f"unable to read Python runtime descriptor {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise PythonPrepareError("Python runtime descriptor must be an object")
    return value


def _safe_existing_file(value: Any, *, field: str, executable: bool = False) -> pathlib.Path:
    if not isinstance(value, str) or not value:
        raise PythonPrepareError(f"{field} must be a non-empty path")
    candidate = pathlib.Path(value)
    if not candidate.is_absolute() or ".." in candidate.parts:
        raise PythonPrepareError(f"{field} must be an absolute safe path")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise PythonPrepareError(f"{field} does not exist: {candidate}") from exc
    if not resolved.is_file():
        raise PythonPrepareError(f"{field} must name a file: {candidate}")
    if executable and not os.access(resolved, os.X_OK):
        raise PythonPrepareError(f"{field} is not executable: {candidate}")
    return resolved


def _path_under(root: pathlib.Path, value: Any, *, field: str, must_exist: bool) -> pathlib.Path:
    if not isinstance(value, str) or not value:
        raise PythonPrepareError(f"{field} must be a non-empty path")
    candidate = pathlib.Path(value)
    if not candidate.is_absolute() or ".." in candidate.parts:
        raise PythonPrepareError(f"{field} must be an absolute safe path")
    try:
        resolved_root = root.resolve(strict=True)
        resolved = candidate.resolve(strict=must_exist)
        resolved.relative_to(resolved_root)
    except (OSError, ValueError) as exc:
        raise PythonPrepareError(f"{field} must resolve beneath {root}") from exc
    return resolved


def _sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_descriptor(value: dict[str, Any]) -> dict[str, Any]:
    service_id = value.get("serviceId")
    if not isinstance(service_id, str) or not SERVICE_ID_RE.fullmatch(service_id):
        raise PythonPrepareError("serviceId is invalid")

    uv = _safe_existing_file(value.get("uv"), field="uv", executable=True)
    interpreter = _safe_existing_file(value.get("interpreter"), field="interpreter", executable=True)

    venv = value.get("venv")
    expected_venv = VENV_ROOT / service_id / "venv"
    if not isinstance(venv, str) or pathlib.Path(venv) != expected_venv:
        raise PythonPrepareError(f"venv must be exactly {expected_venv}")

    environment_fingerprint = value.get("environmentFingerprint")
    if not isinstance(environment_fingerprint, str) or not SHA256_RE.fullmatch(environment_fingerprint):
        raise PythonPrepareError("environmentFingerprint must be a lowercase SHA-256 digest")

    requirements = value.get("requirementsFile")
    expected_requirements_hash = value.get("requirementsSha256")
    if requirements is not None:
        app_root = APP_ROOT / service_id
        requirements = _path_under(app_root, requirements, field="requirementsFile", must_exist=True)
        if not requirements.is_file():
            raise PythonPrepareError("requirementsFile must name a file")
        if not isinstance(expected_requirements_hash, str) or not SHA256_RE.fullmatch(expected_requirements_hash):
            raise PythonPrepareError("requirementsSha256 must be supplied with requirementsFile")
        actual_requirements_hash = _sha256_file(requirements)
        if actual_requirements_hash != expected_requirements_hash:
            raise PythonPrepareError("requirementsFile changed after the V2 projection was compiled")
    elif expected_requirements_hash is not None:
        raise PythonPrepareError("requirementsSha256 is invalid without requirementsFile")

    require_hashes = value.get("requireHashes", True)
    if not isinstance(require_hashes, bool):
        raise PythonPrepareError("requireHashes must be a boolean")

    return {
        "serviceId": service_id,
        "uv": uv,
        "interpreter": interpreter,
        "venv": expected_venv,
        "requirementsFile": requirements,
        "requireHashes": require_hashes,
        "environmentFingerprint": environment_fingerprint,
    }


def _run(command: list[str]) -> None:
    result = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=900,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[:4000]
        raise PythonPrepareError(f"command failed ({result.returncode}): {detail}")


def _state_matches(venv: pathlib.Path, fingerprint: str) -> bool:
    python = venv / "bin" / "python"
    state_path = venv / _STATE_FILE
    if not python.is_file() or not os.access(python, os.X_OK):
        return False
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return isinstance(state, dict) and state.get("schemaVersion") == 1 and state.get("fingerprint") == fingerprint


def _write_state(venv: pathlib.Path, fingerprint: str) -> None:
    state_path = venv / _STATE_FILE
    payload = (json.dumps({"schemaVersion": 1, "fingerprint": fingerprint}, sort_keys=True) + "\n").encode()
    fd, raw_name = tempfile.mkstemp(prefix=f".{_STATE_FILE}.", dir=venv)
    temp = pathlib.Path(raw_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp, 0o644)
        os.replace(temp, state_path)
        directory_fd = os.open(venv, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temp.unlink(missing_ok=True)


def prepare(value: dict[str, Any]) -> bool:
    """Prepare the environment and return True only when it was rebuilt."""
    config = validate_descriptor(value)
    uv = str(config["uv"])
    interpreter = str(config["interpreter"])
    venv = pathlib.Path(config["venv"])
    fingerprint = str(config["environmentFingerprint"])

    if _state_matches(venv, fingerprint):
        return False

    venv.parent.mkdir(parents=True, exist_ok=True)
    _run(
        [
            uv,
            "venv",
            "--no-python-downloads",
            "--python",
            interpreter,
            "--clear",
            str(venv),
        ]
    )

    requirements = config["requirementsFile"]
    if requirements is not None:
        venv_python = venv / "bin" / "python"
        command = [
            uv,
            "pip",
            "sync",
            "--no-python-downloads",
            "--python",
            str(venv_python),
            "--strict",
        ]
        if config["requireHashes"]:
            command.append("--require-hashes")
        command.append(str(requirements))
        _run(command)

    _write_state(venv, fingerprint)
    return True


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Prepare a Managed Services V2 Python virtual environment")
    parser.add_argument("--config", required=True, type=pathlib.Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        changed = prepare(_read_descriptor(args.config))
    except PythonPrepareError as exc:
        print(f"nas-v2-python-prepare: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"changed": changed}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
