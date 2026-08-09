#!/usr/bin/env python3
"""Generic isolated Python runtime for Managed Services V2.

Every Python V2 service owns a private virtual environment below
``/var/lib/nas-control/venvs/<service-id>``.  Dependency installation never
modifies the appliance control-plane interpreter or another application's venv.
The runtime is entirely data-driven by the V2 service document.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import shlex
import subprocess
import tempfile
from typing import Any

APP_ROOT = pathlib.Path("/var/lib/nas-control/apps")
VENV_ROOT = pathlib.Path("/var/lib/nas-control/venvs")
UNIT_ROOT = pathlib.Path("/run/systemd/system")
SERVICE_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,47}$")
SAFE_ENV_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class PythonRuntimeError(RuntimeError):
    pass


def _safe_app_path(service_id: str, value: str, *, field: str) -> pathlib.Path:
    if not SERVICE_ID_RE.fullmatch(service_id):
        raise PythonRuntimeError(f"Invalid service id {service_id!r}")
    path = pathlib.Path(value)
    if not path.is_absolute():
        raise PythonRuntimeError(f"Service {service_id}: {field} must be absolute")
    root = (APP_ROOT / service_id).resolve()
    resolved = path.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise PythonRuntimeError(f"Service {service_id}: {field} must be beneath {root}") from exc
    return resolved


def venv_path(service_id: str) -> pathlib.Path:
    if not SERVICE_ID_RE.fullmatch(service_id):
        raise PythonRuntimeError(f"Invalid service id {service_id!r}")
    return VENV_ROOT / service_id


def unit_name(service_id: str) -> str:
    if not SERVICE_ID_RE.fullmatch(service_id):
        raise PythonRuntimeError(f"Invalid service id {service_id!r}")
    return f"nas-v2-python-{service_id}.service"


def _runtime(service_id: str, service: dict[str, Any]) -> dict[str, Any]:
    runtime = service.get("runtime")
    if not isinstance(runtime, dict) or runtime.get("type") != "python":
        raise PythonRuntimeError(f"Service {service_id}: runtime.type must be python")
    return runtime


def _fingerprint(service_id: str, runtime: dict[str, Any]) -> str:
    material: dict[str, Any] = {
        "interpreter": runtime.get("interpreter", "/run/current-system/sw/bin/python3"),
        "dependencies": runtime.get("dependencies", {}),
    }
    deps = runtime.get("dependencies") or {}
    for key in ("requirementsFile", "projectPath"):
        value = deps.get(key)
        if isinstance(value, str):
            path = _safe_app_path(service_id, value, field=f"runtime.dependencies.{key}")
            if path.is_file():
                material[f"{key}Sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    return hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _atomic_write(path: pathlib.Path, text: str, mode: int = 0o640) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = pathlib.Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def ensure_venv(service_id: str, service: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
    runtime = _runtime(service_id, service)
    interpreter = runtime.get("interpreter", "/run/current-system/sw/bin/python3")
    if not isinstance(interpreter, str) or not interpreter.startswith("/"):
        raise PythonRuntimeError(f"Service {service_id}: Python interpreter must be an absolute path")
    env_dir = venv_path(service_id)
    state_path = env_dir / ".nas-v2-runtime.json"
    fingerprint = _fingerprint(service_id, runtime)
    current: dict[str, Any] = {}
    try:
        current = json.loads(state_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        current = {}
    needs_sync = current.get("fingerprint") != fingerprint or not (env_dir / "bin/python").is_file()
    plan = {
        "service": service_id,
        "runtime": "python",
        "venv": str(env_dir),
        "interpreter": interpreter,
        "fingerprint": fingerprint,
        "sync": needs_sync,
    }
    if dry_run or not needs_sync:
        return plan

    env_dir.parent.mkdir(parents=True, exist_ok=True)
    if not (env_dir / "bin/python").is_file():
        subprocess.run([interpreter, "-m", "venv", str(env_dir)], check=True)
    python = env_dir / "bin/python"
    deps = runtime.get("dependencies") or {}
    requirements = deps.get("requirementsFile")
    if requirements is not None:
        requirements_path = _safe_app_path(
            service_id, requirements, field="runtime.dependencies.requirementsFile"
        )
        command = [str(python), "-m", "pip", "install", "--disable-pip-version-check"]
        if deps.get("requireHashes", True):
            command.append("--require-hashes")
        command.extend(["-r", str(requirements_path)])
        subprocess.run(command, check=True)
    project = deps.get("projectPath")
    if project is not None:
        project_path = _safe_app_path(service_id, project, field="runtime.dependencies.projectPath")
        command = [str(python), "-m", "pip", "install", "--disable-pip-version-check"]
        if not deps.get("installProjectDependencies", False):
            command.append("--no-deps")
        command.append(str(project_path))
        subprocess.run(command, check=True)
    _atomic_write(
        state_path,
        json.dumps({"schemaVersion": 1, "fingerprint": fingerprint}, indent=2, sort_keys=True) + "\n",
        0o600,
    )
    return plan


def _entrypoint_command(service_id: str, runtime: dict[str, Any]) -> list[str]:
    python = str(venv_path(service_id) / "bin/python")
    entrypoint = runtime.get("entrypoint") or {}
    if not isinstance(entrypoint, dict):
        raise PythonRuntimeError(f"Service {service_id}: runtime.entrypoint must be an object")
    if isinstance(entrypoint.get("module"), str):
        command = [python, "-m", entrypoint["module"]]
    elif isinstance(entrypoint.get("script"), str):
        script = _safe_app_path(service_id, entrypoint["script"], field="runtime.entrypoint.script")
        command = [python, str(script)]
    else:
        raise PythonRuntimeError(f"Service {service_id}: Python entrypoint requires module or script")
    args = runtime.get("args", [])
    if not isinstance(args, list) or any(not isinstance(item, str) for item in args):
        raise PythonRuntimeError(f"Service {service_id}: runtime.args must be an array of strings")
    return [*command, *args]


def render_unit(service_id: str, service: dict[str, Any]) -> str:
    runtime = _runtime(service_id, service)
    command = _entrypoint_command(service_id, runtime)
    environment = runtime.get("environment", {})
    if not isinstance(environment, dict):
        raise PythonRuntimeError(f"Service {service_id}: runtime.environment must be an object")
    lines = [
        "# Generated by NixOS NAS Managed Services V2; do not edit.",
        "[Unit]",
        f"Description=Managed Services V2 Python runtime: {service_id}",
        "After=network-online.target",
        "",
        "[Service]",
        "Type=simple",
        f"ExecStart={' '.join(shlex.quote(item) for item in command)}",
        "NoNewPrivileges=yes",
        "PrivateTmp=yes",
    ]
    working_directory = runtime.get("workingDirectory")
    if working_directory is not None:
        working = _safe_app_path(service_id, working_directory, field="runtime.workingDirectory")
        lines.append(f"WorkingDirectory={working}")
    user = runtime.get("user")
    if user:
        lines.append(f"User={user}")
    group = runtime.get("group")
    if group:
        lines.append(f"Group={group}")
    for key, value in sorted(environment.items()):
        if not SAFE_ENV_RE.fullmatch(str(key)) or not isinstance(value, str) or "\n" in value or "\x00" in value:
            raise PythonRuntimeError(f"Service {service_id}: invalid Python runtime environment entry {key!r}")
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'Environment="{key}={escaped}"')
    for credential in service.get("credentials", []):
        if credential.get("use") == "environment-file":
            source = credential.get("resolvedPath") or credential.get("path")
            if isinstance(source, str) and source.startswith("/run/nas-secrets/"):
                lines.append(f"EnvironmentFile={source}")
    restart = runtime.get("restart", "on-failure")
    if restart != "no":
        lines.append(f"Restart={restart}")
        lines.append(f"RestartSec={int(runtime.get('restartSeconds', 3))}")
    lines.extend(["", "[Install]", "WantedBy=multi-user.target", ""])
    return "\n".join(lines)


def apply_python(service_id: str, service: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
    sync = ensure_venv(service_id, service, dry_run=dry_run)
    workload = service.get("workload") or {}
    managed = bool(service.get("managed", True))
    enabled = bool(service.get("enabled"))
    persistent = workload.get("kind") == "daemon" and workload.get("activation") == "persistent"
    unit = unit_name(service_id)
    unit_path = UNIT_ROOT / unit
    operation = "stop" if managed and not enabled else ("restart" if persistent else None)
    plan = {**sync, "unit": unit, "unitPath": str(unit_path), "operation": operation}
    if dry_run:
        return plan
    if enabled or persistent:
        _atomic_write(unit_path, render_unit(service_id, service), 0o644)
        subprocess.run(["systemctl", "daemon-reload"], check=True)
    if operation is not None:
        subprocess.run(["systemctl", operation, unit], check=True)
    return plan


def remove_python(service_id: str, *, dry_run: bool = False, remove_venv: bool = False) -> None:
    unit = unit_name(service_id)
    if dry_run:
        return
    subprocess.run(["systemctl", "stop", unit], check=False)
    (UNIT_ROOT / unit).unlink(missing_ok=True)
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    if remove_venv:
        import shutil

        shutil.rmtree(venv_path(service_id), ignore_errors=True)
