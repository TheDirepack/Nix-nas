#!/usr/bin/env python3
"""Launch authenticated Pi coding-agent sessions as disposable Podman containers."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import secrets
import stat
import subprocess
import sys
import threading
from collections.abc import Sequence


class CodingAgentError(RuntimeError):
    """Expected coding-agent launch failure."""


USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9./:_@-]{0,255}$")
NETWORK_RE = re.compile(r"^(?:[A-Za-z0-9][A-Za-z0-9_.-]{0,63}|ns:/run/netns/[A-Za-z0-9_.-]+)$")


def configured_roots() -> tuple[pathlib.Path, ...]:
    raw = os.environ.get("NAS_CODING_WORKSPACE_ROOTS_JSON", "[]")
    try:
        values = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CodingAgentError("Invalid NAS coding workspace-root configuration") from exc
    if not isinstance(values, list) or not values or not all(isinstance(value, str) and value for value in values):
        raise CodingAgentError("At least one NAS coding workspace root must be configured")
    return tuple(pathlib.Path(value).resolve(strict=True) for value in values)


def validate_workspace(value: str, roots: Sequence[pathlib.Path]) -> pathlib.Path:
    candidate = pathlib.Path(value)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise CodingAgentError(f"Coding workspace does not exist: {candidate}") from exc
    if not resolved.is_dir():
        raise CodingAgentError(f"Coding workspace is not a directory: {resolved}")
    for root in roots:
        if resolved == root or resolved.is_relative_to(root):
            return resolved
    raise CodingAgentError(f"Coding workspace is outside the configured allowlist: {resolved}")


def run_checked(command: Sequence[str]) -> None:
    result = subprocess.run(command, check=False)
    if result.returncode != 0:
        raise CodingAgentError(f"Command failed with status {result.returncode}: {command[0]}")


def _validated_username(value: object) -> str:
    username = value if isinstance(value, str) else str(value)
    if not USERNAME_RE.fullmatch(username):
        raise CodingAgentError("Authenticated identity has an invalid username")
    return username


def ensure_user_state(username: str) -> pathlib.Path:
    username = _validated_username(username)
    root_raw = os.environ.get("NAS_PI_USER_STATE_ROOT", "/tank/apps/pi/users")
    root = pathlib.Path(root_raw)
    if not root.is_absolute():
        raise CodingAgentError("NAS Pi user-state root must be absolute")
    try:
        root = root.resolve(strict=True)
    except OSError as exc:
        raise CodingAgentError(f"NAS Pi user-state root is unavailable: {root_raw}") from exc
    if not root.is_dir():
        raise CodingAgentError(f"NAS Pi user-state root is not a directory: {root}")

    user_state = root / username
    try:
        current = user_state.lstat()
    except FileNotFoundError:
        user_state.mkdir(mode=0o700)
        current = user_state.lstat()
    if stat.S_ISLNK(current.st_mode) or not stat.S_ISDIR(current.st_mode):
        raise CodingAgentError(f"Pi user state must be a real directory: {user_state}")
    resolved = user_state.resolve(strict=True)
    if resolved.parent != root:
        raise CodingAgentError(f"Pi user-state path escaped its managed root: {resolved}")

    uid = int(os.environ.get("NAS_PI_CONTAINER_UID", "954"))
    gid = int(os.environ.get("NAS_PI_CONTAINER_GID", str(uid)))
    if uid <= 0 or gid <= 0:
        raise CodingAgentError("Pi container UID/GID must be positive")
    os.chown(resolved, uid, gid)
    os.chmod(resolved, 0o700)
    return resolved


def _bind_arg(source: pathlib.Path, target: str, *, read_only: bool = False) -> str:
    raw = str(source)
    if any(char in raw for char in ("\n", "\r", ":")):
        raise CodingAgentError(f"Podman bind source contains unsupported characters: {raw!r}")
    suffix = ":ro" if read_only else ":rw"
    return f"{raw}:{target}{suffix}"


def session_command(workspace: pathlib.Path, user_state: pathlib.Path, pi_args: Sequence[str]) -> list[str]:
    image = os.environ.get("NAS_PI_IMAGE", "")
    if not IMAGE_RE.fullmatch(image):
        raise CodingAgentError("NAS Pi container image is not configured")
    credential = pathlib.Path(
        os.environ.get("NAS_PI_CREDENTIAL", "/run/nas-secrets/ai/coding-agent-api-key")
    )
    if not credential.is_absolute():
        raise CodingAgentError("NAS Pi credential path must be absolute")
    network = os.environ.get("NAS_PI_NETWORK", "ns:/run/netns/pi")
    if not NETWORK_RE.fullmatch(network):
        raise CodingAgentError("NAS Pi container network is invalid")

    uid = int(os.environ.get("NAS_PI_CONTAINER_UID", "954"))
    gid = int(os.environ.get("NAS_PI_CONTAINER_GID", str(uid)))
    max_runtime = os.environ.get("NAS_CODING_MAX_RUNTIME_SEC", "14400")
    try:
        max_runtime_int = int(max_runtime)
        if not 600 <= max_runtime_int <= 86400:
            max_runtime_int = 14400
    except ValueError:
        max_runtime_int = 14400

    cpus_raw = os.environ.get("NAS_CODING_CPUS", "4")
    try:
        cpus = float(cpus_raw)
    except ValueError as exc:
        raise CodingAgentError("NAS coding CPU limit is invalid") from exc
    if not 0.1 <= cpus <= 64:
        raise CodingAgentError("NAS coding CPU limit must be between 0.1 and 64")
    memory = os.environ.get("NAS_CODING_MEMORY", "4g")
    if re.fullmatch(r"^[1-9][0-9]*[kKmMgG]?$", memory) is None:
        raise CodingAgentError("NAS coding memory limit is invalid")

    name = f"nas-pi-{secrets.token_hex(8)}"
    command = [
        "podman",
        "run",
        "--rm",
        "--replace",
        "--interactive",
        "--tty",
        f"--name={name}",
        "--pull=never",
        "--read-only",
        "--cap-drop=all",
        "--security-opt=no-new-privileges",
        f"--user={uid}:{gid}",
        f"--network={network}",
        f"--timeout={max_runtime_int}",
        f"--cpus={cpus:g}",
        f"--memory={memory}",
        "--pids-limit=512",
        "--tmpfs=/tmp:rw,nodev,nosuid,noexec,size=512m",
        "--workdir=/workspace",
        "--env=HOME=/home/pi",
        "--env=NAS_PI_CREDENTIAL_FILE=/run/secrets/llama-swap-api-key",
        "--volume",
        _bind_arg(workspace, "/workspace"),
        "--volume",
        _bind_arg(user_state, "/home/pi"),
        "--volume",
        _bind_arg(credential, "/run/secrets/llama-swap-api-key", read_only=True),
        image,
    ]
    command.extend(pi_args)
    return command


def heartbeat(stop: threading.Event, managed_service: str, interval: int) -> None:
    while not stop.wait(interval):
        subprocess.run(
            [managed_service, "touch", "ai-runtime"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        prog="nas-code-agent",
        description="Run a disposable Pi coding-agent container inside an approved NAS workspace.",
    )
    result.add_argument("workspace", help="Repository/workspace path under an approved root")
    result.add_argument(
        "pi_args", nargs=argparse.REMAINDER, help="Arguments passed to Pi after an optional -- separator"
    )
    return result


def _check_coding_access() -> str:
    identity_json = os.environ.get("NAS_AUTHENTICATED_IDENTITY_JSON", "")
    if identity_json.strip():
        try:
            data = json.loads(identity_json)
        except json.JSONDecodeError as exc:
            print("nas-code-agent: auth mode=identity-json malformed", file=sys.stderr)
            raise CodingAgentError(
                "Invalid NAS identity token; denied (malformed identity JSON) [mode=identity-json]"
            ) from exc
        if not isinstance(data, dict):
            print("nas-code-agent: auth mode=identity-json malformed", file=sys.stderr)
            raise CodingAgentError("Invalid NAS identity token; denied (malformed identity JSON) [mode=identity-json]")
        groups_raw = data.get("groups", [])
        if not isinstance(groups_raw, list) or not all(isinstance(entry, str) for entry in groups_raw):
            print("nas-code-agent: auth mode=identity-json malformed", file=sys.stderr)
            raise CodingAgentError("Invalid NAS identity token; denied (malformed identity JSON) [mode=identity-json]")
        groups: set[str] = set(groups_raw)
        if data.get("admin") is True or data.get("role") == "admin":
            groups.add("nas_admin")
            try:
                from nas_common import ADMIN_GROUP as _ADMIN_GROUP

                groups.add(_ADMIN_GROUP)
            except ImportError:
                pass
        username = _validated_username(data.get("username", ""))
        print("nas-code-agent: auth mode=identity-json", file=sys.stderr)
        try:
            from nas_common import ADMIN_GROUP, capability_allowed

            if capability_allowed(groups, "coding") or ADMIN_GROUP in groups or "nas_admin" in groups:
                return username
        except ImportError:
            if "nas_allow_coding" in groups or "nas_admin" in groups:
                return username
        raise CodingAgentError(
            f"User {username!r} denied: coding capability required (groups: {sorted(groups)}) [mode=identity-json]"
        )
    sudo_user = os.environ.get("SUDO_USER", "")
    insecure = os.environ.get("NAS_CODING_INSECURE_UID_AUTH", "") == "1"
    if sudo_user:
        sudo_user = _validated_username(sudo_user)
        if not insecure:
            print("nas-code-agent: auth mode=uid-deny (insecure flag not set)", file=sys.stderr)
            raise CodingAgentError(
                f"User {sudo_user!r} denied: coding agent requires authenticated identity (NAS_AUTHENTICATED_IDENTITY_JSON missing). "
                "Invoke via Cockpit/Caddy-authenticated path or set NAS_CODING_INSECURE_UID_AUTH=1 for legacy UID fallback [mode=uid-deny]"
            )
        print("nas-code-agent: auth mode=insecure-uid", file=sys.stderr)
        user_groups: set[str] = set()
        try:
            import grp
            import pwd

            try:
                pw = pwd.getpwnam(sudo_user)
                user_groups.add(pw.pw_name)
                for group in grp.getgrall():
                    if sudo_user in group.gr_mem:
                        user_groups.add(group.gr_name)
                result = subprocess.run(["id", "-nG", sudo_user], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    user_groups.update(result.stdout.strip().split())
            except (KeyError, OSError):
                pass
        except Exception:
            pass
        try:
            from nas_common import capability_allowed

            if capability_allowed(user_groups, "coding") or "nas_admin" in user_groups:
                return sudo_user
        except ImportError:
            if "nas_allow_coding" in user_groups or "nas_admin" in user_groups:
                return sudo_user
        raise CodingAgentError(
            f"User {sudo_user!r} is not in nas_allow_coding or nas_admin; "
            f"request access via Authentik and Cockpit (groups: {sorted(user_groups)}) [mode=insecure-uid]"
        )
    print("nas-code-agent: auth mode=no-identity (deny)", file=sys.stderr)
    if os.geteuid() == 0:
        raise CodingAgentError(
            "Coding agent denied: no authenticated identity and no SUDO_USER (euid==0 direct root invocation denied). "
            "Invoke via Cockpit/Caddy-authenticated path with NAS_AUTHENTICATED_IDENTITY_JSON [mode=no-identity]"
        )
    raise CodingAgentError(
        "Coding agent denied: no authenticated identity and no SUDO_USER. "
        "Invoke via Cockpit/Caddy-authenticated path [mode=no-identity]"
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if os.geteuid() != 0:
        print("nas-code-agent: run through sudo/root so Podman can create the isolated session", file=sys.stderr)
        return 1
    try:
        username = _check_coding_access()
        roots = configured_roots()
        workspace = validate_workspace(args.workspace, roots)
        credential = pathlib.Path(os.environ.get("NAS_PI_CREDENTIAL", "/run/nas-secrets/ai/coding-agent-api-key"))
        if not credential.is_file():
            raise CodingAgentError(
                "Coding-agent llama-swap client credential is unavailable; activate NAS secrets first"
            )
        user_state = ensure_user_state(username)
        managed_service = os.environ.get("NAS_MANAGED_SERVICE", "nas-managed-service")
        run_checked([managed_service, "start", "ai-runtime"])
        interval = max(30, int(os.environ.get("NAS_CODING_HEARTBEAT_SECONDS", "120")))
        stop = threading.Event()
        worker = threading.Thread(target=heartbeat, args=(stop, managed_service, interval), daemon=True)
        worker.start()
        try:
            pi_args = list(args.pi_args)
            if pi_args[:1] == ["--"]:
                pi_args = pi_args[1:]
            return subprocess.run(session_command(workspace, user_state, pi_args), check=False).returncode
        finally:
            stop.set()
            worker.join(timeout=2)
    except (CodingAgentError, ValueError) as exc:
        print(f"nas-code-agent: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
