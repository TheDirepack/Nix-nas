#!/usr/bin/env python3
"""Launch Pi coding-agent sessions inside the NAS systemd sandbox."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import secrets
import subprocess
import sys
import threading
from collections.abc import Sequence


class CodingAgentError(RuntimeError):
    """Expected coding-agent launch failure."""


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


def session_command(workspace: pathlib.Path, pi_args: Sequence[str]) -> list[str]:
    session_exec = os.environ.get("NAS_PI_SESSION_EXEC", "")
    if not session_exec or not pathlib.Path(session_exec).is_absolute():
        raise CodingAgentError("NAS Pi session executable is not configured")
    credential = os.environ.get("NAS_PI_CREDENTIAL", "/run/nas-secrets/ai/coding-agent-api-key")
    state_dir = os.environ.get("NAS_PI_STATE_DIR", "/var/lib/nas-code-agent")
    unit = f"nas-ai-coding-session-{secrets.token_hex(8)}.service"
    slice_name = os.environ.get("NAS_CODING_SLICE", "nas-ai-coding.slice")
    target_name = os.environ.get("NAS_CODING_TARGET", "nas-ai-coding-sessions.target")
    max_runtime = os.environ.get("NAS_CODING_MAX_RUNTIME_SEC", "14400")
    try:
        max_runtime_int = int(max_runtime)
        if not 600 <= max_runtime_int <= 86400:
            max_runtime_int = 14400
    except ValueError:
        max_runtime_int = 14400
    properties = (
        "NoNewPrivileges=yes",
        "PrivateTmp=yes",
        "PrivateDevices=yes",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "ProtectKernelTunables=yes",
        "ProtectKernelModules=yes",
        "ProtectKernelLogs=yes",
        "ProtectControlGroups=yes",
        "RestrictSUIDSGID=yes",
        "LockPersonality=yes",
        # Network allowed for Pi web/GitHub; host loopback blocked except via proxy (10.200.1.1)
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        "NetworkNamespacePath=/run/netns/pi",
        f"Slice={slice_name}",
        f"PartOf={target_name}",
        f"BindsTo={target_name}",
        f"RuntimeMaxSec={max_runtime_int}",
        "InaccessiblePaths=/run/nas-secrets",
        "InaccessiblePaths=/var/lib/nas-llama-swap",
        f"ReadWritePaths={workspace}",
        f"ReadWritePaths={state_dir}",
        f"LoadCredential=llama-swap-api-key:{credential}",
    )
    command = [
        "systemd-run",
        "--quiet",
        "--wait",
        "--collect",
        "--pty",
        "--service-type=exec",
        f"--unit={unit}",
        "--uid=nas-code-agent",
        "--gid=nas-code-agent",
        f"--working-directory={workspace}",
    ]
    for prop in properties:
        command.extend(("--property", prop))
    command.extend((session_exec, *pi_args))
    return command


def heartbeat(stop: threading.Event, feature_control: str, interval: int) -> None:
    while not stop.wait(interval):
        subprocess.run(
            [feature_control, "wake", "aiCoding"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        prog="nas-code-agent",
        description="Run a Pi coding-agent session inside an approved NAS workspace.",
    )
    result.add_argument("workspace", help="Repository/workspace path under an approved root")
    result.add_argument(
        "pi_args", nargs=argparse.REMAINDER, help="Arguments passed to Pi after an optional -- separator"
    )
    return result


def _check_coding_access() -> None:
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
        username = data.get("username", "")
        if not isinstance(username, str):
            username = str(username)
        print("nas-code-agent: auth mode=identity-json", file=sys.stderr)
        try:
            from nas_common import ADMIN_GROUP, capability_allowed

            if capability_allowed(groups, "coding") or ADMIN_GROUP in groups or "nas_admin" in groups:
                return
        except ImportError:
            if "nas_allow_coding" in groups or "nas_admin" in groups:
                return
        raise CodingAgentError(
            f"User {username!r} denied: coding capability required (groups: {sorted(groups)}) [mode=identity-json]"
        )
    sudo_user = os.environ.get("SUDO_USER", "")
    insecure = os.environ.get("NAS_CODING_INSECURE_UID_AUTH", "") == "1"
    if sudo_user:
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
                for g in grp.getgrall():
                    if sudo_user in g.gr_mem:
                        user_groups.add(g.gr_name)
                result = subprocess.run(["id", "-nG", sudo_user], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    user_groups.update(result.stdout.strip().split())
            except (KeyError, OSError):
                pass
        except Exception:
            pass
        try:
            from nas_common import capability_allowed

            if capability_allowed(user_groups, "coding"):
                return
            if "nas_admin" in user_groups:
                return
        except ImportError:
            if "nas_allow_coding" in user_groups or "nas_admin" in user_groups:
                return
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
        print("nas-code-agent: run through sudo/root so systemd can create the sandboxed service", file=sys.stderr)
        return 1
    try:
        _check_coding_access()
        roots = configured_roots()
        workspace = validate_workspace(args.workspace, roots)
        credential = pathlib.Path(os.environ.get("NAS_PI_CREDENTIAL", "/run/nas-secrets/ai/coding-agent-api-key"))
        if not credential.is_file():
            raise CodingAgentError(
                "Coding-agent llama-swap client credential is unavailable; activate NAS secrets first"
            )
        feature_control = os.environ.get("NAS_FEATURE_CONTROL", "nas-feature-control")
        run_checked([feature_control, "wake", "aiCoding"])
        interval = max(30, int(os.environ.get("NAS_CODING_HEARTBEAT_SECONDS", "120")))
        stop = threading.Event()
        worker = threading.Thread(target=heartbeat, args=(stop, feature_control, interval), daemon=True)
        worker.start()
        try:
            pi_args = list(args.pi_args)
            if pi_args[:1] == ["--"]:
                pi_args = pi_args[1:]
            return subprocess.run(session_command(workspace, pi_args), check=False).returncode
        finally:
            stop.set()
            worker.join(timeout=2)
    except (CodingAgentError, ValueError) as exc:
        print(f"nas-code-agent: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
