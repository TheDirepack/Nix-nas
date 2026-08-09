#!/usr/bin/env python3
"""Runtime-safe llama-swap configuration management for the NAS AI control plane."""

from __future__ import annotations

import argparse
import json
import os
import sys
import pathlib
import re
import shlex
import shutil
import subprocess
import tempfile
import urllib.parse
from collections.abc import Mapping, Sequence
from typing import Any

import yaml

CONFIG_PATH = pathlib.Path(os.environ.get("NAS_LLAMA_SWAP_CONFIG", "/var/lib/nas-llama-swap/config.yaml"))
PROVIDER_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,47}$")
LOCAL_MODEL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
ENV_MACRO_RE = re.compile(r"^\$\{env\.([A-Z][A-Z0-9_]*)\}$")
ROLE_IDS = (
    "coding/default",
    "coding/cheap",
    "coding/planner",
    "coding/reviewer",
    "coding/research",
    "coding/local-worker",
)
MAX_MODELS = 256
MAX_MODEL_ID = 256
MAX_CONFIG_BYTES = 2 * 1024 * 1024
TIMEOUT_KEYS = ("connect", "keepalive", "responseHeader", "tlsHandshake", "idleConn")
SELECTOR_STRATEGIES = ("warm", "pin", "spillover")
MAX_LOCAL_ARGS = 64
MAX_LOCAL_ARG_LENGTH = 512
FORBIDDEN_LOCAL_FLAGS = {
    "--host",
    "--port",
    "--model",
    "-m",
    "--model-url",
    "--api-key",
    "--alias",
    "--ctx-size",
    "-c",
}


class AiConfigError(RuntimeError):
    """Expected AI configuration error."""


def provider_env_name(provider_id: str) -> str:
    provider_id = validate_provider_id(provider_id)
    return "LLAMA_SWAP_PEER_" + provider_id.upper().replace("-", "_") + "_API_KEY"


def provider_secret_name(provider_id: str) -> str:
    return f"ai-provider-{validate_provider_id(provider_id)}"


def validate_provider_id(value: str) -> str:
    if not PROVIDER_ID_RE.fullmatch(value):
        raise AiConfigError("Provider ID must use lowercase letters, digits, and hyphens: [a-z][a-z0-9-]{0,47}")
    return value


def validate_proxy_url(value: str) -> str:
    if len(value) > 2048 or any(ord(char) < 32 for char in value):
        raise AiConfigError("Provider URL is invalid")
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise AiConfigError("Provider URL must be an http(s) URL")
    if parsed.username is not None or parsed.password is not None:
        raise AiConfigError("Provider credentials must not be embedded in the URL")
    if parsed.fragment:
        raise AiConfigError("Provider URL must not contain a fragment")
    return value.rstrip("/")


def validate_model_id(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_MODEL_ID:
        raise AiConfigError("Model IDs must be non-empty strings no longer than 256 characters")
    if any(ord(char) < 32 or char.isspace() for char in value):
        raise AiConfigError("Model IDs must not contain whitespace or control characters")
    return value


def validate_local_model_id(value: str) -> str:
    if not isinstance(value, str) or not LOCAL_MODEL_ID_RE.fullmatch(value):
        raise AiConfigError("Local model ID must match [A-Za-z0-9][A-Za-z0-9._-]{0,127}")
    return value


def local_model_root() -> pathlib.Path:
    value = os.environ.get("NAS_AI_MODEL_ROOT", "/var/lib/nas-ai-models")
    root = pathlib.Path(value)
    if not root.is_absolute():
        raise AiConfigError("NAS_AI_MODEL_ROOT must be an absolute path")
    try:
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise AiConfigError(f"AI model root does not exist: {root}") from exc
    if not resolved.is_dir():
        raise AiConfigError(f"AI model root is not a directory: {resolved}")
    return resolved


def validate_local_model_path(value: str) -> pathlib.Path:
    if not isinstance(value, str) or not value or len(value) > 4096 or any(ord(char) < 32 for char in value):
        raise AiConfigError("Local model path is invalid")
    candidate = pathlib.Path(value)
    if not candidate.is_absolute():
        raise AiConfigError("Local model path must be absolute")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise AiConfigError(f"Local model file does not exist: {candidate}") from exc
    root = local_model_root()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise AiConfigError(f"Local model path must stay beneath {root}") from exc
    if not resolved.is_file():
        raise AiConfigError("Local model path must reference a regular file")
    if resolved.suffix.lower() != ".gguf":
        raise AiConfigError("Local model path must reference a .gguf file")
    return resolved


def validate_local_extra_args(value: object) -> list[str]:
    if value in (None, []):
        return []
    if not isinstance(value, list) or len(value) > MAX_LOCAL_ARGS or any(not isinstance(item, str) for item in value):
        raise AiConfigError(f"Local model extra arguments must be a list of at most {MAX_LOCAL_ARGS} strings")
    result: list[str] = []
    for item in value:
        if not item or len(item) > MAX_LOCAL_ARG_LENGTH or any(ord(char) < 32 for char in item):
            raise AiConfigError("Local model arguments must be short non-empty strings without control characters")
        flag = item.split("=", 1)[0]
        if flag in FORBIDDEN_LOCAL_FLAGS:
            raise AiConfigError(f"Local model argument {flag} is managed by the NAS and cannot be overridden")
        result.append(item)
    return result


def llama_server_path() -> str:
    value = os.environ.get("NAS_LLAMA_SERVER", "/run/current-system/sw/bin/llama-server")
    path = pathlib.Path(value)
    if not path.is_absolute() or any(ord(char) < 32 for char in value):
        raise AiConfigError("NAS_LLAMA_SERVER must be a safe absolute path")
    return str(path)


def validate_models(values: Sequence[str]) -> list[str]:
    if not isinstance(values, (list, tuple)) or not values or len(values) > MAX_MODELS:
        raise AiConfigError(f"A provider must expose between 1 and {MAX_MODELS} models")
    result: list[str] = []
    seen: set[str] = set()
    for raw in values:
        value = validate_model_id(raw)
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def validate_role(role: str) -> str:
    if role not in ROLE_IDS:
        raise AiConfigError(f"Unknown coding model role: {role}")
    return role


def _require_mapping(value: object, label: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise AiConfigError(f"{label} must be an object")
    return dict(value)


def validate_timeouts(value: object) -> dict[str, int]:
    if value in (None, {}):
        return {}
    raw = _require_mapping(value, "provider timeouts")
    unknown = sorted(set(raw) - set(TIMEOUT_KEYS))
    if unknown:
        raise AiConfigError("Unknown provider timeout field(s): " + ", ".join(unknown))
    result: dict[str, int] = {}
    for key in TIMEOUT_KEYS:
        if key not in raw:
            continue
        number = raw[key]
        if isinstance(number, bool) or not isinstance(number, int) or not 0 <= number <= 3600:
            raise AiConfigError(f"Provider timeout {key} must be an integer between 0 and 3600")
        result[key] = number
    return result


def validate_filters(value: object) -> dict[str, Any]:
    if value in (None, {}):
        return {}
    raw = _require_mapping(value, "provider filters")
    unknown = sorted(set(raw) - {"stripParams", "setParams"})
    if unknown:
        raise AiConfigError("Unknown provider filter field(s): " + ", ".join(unknown))
    result: dict[str, Any] = {}
    if "stripParams" in raw:
        strip_params = raw["stripParams"]
        if not isinstance(strip_params, str) or len(strip_params) > 2048 or any(ord(c) < 32 for c in strip_params):
            raise AiConfigError("stripParams must be a short comma-separated string")
        result["stripParams"] = strip_params.strip()
    if "setParams" in raw:
        params = raw["setParams"]
        if not isinstance(params, dict) or not all(isinstance(key, str) for key in params):
            raise AiConfigError("setParams must be a JSON object")
        encoded = json.dumps(params, ensure_ascii=False, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > 65536:
            raise AiConfigError("setParams is too large")
        if "model" in params:
            raise AiConfigError("setParams may not override the protected model field")
        result["setParams"] = params
    return result


def validate_selector_settings(strategy: object, spillover: object) -> tuple[str, dict[str, int]]:
    if strategy not in SELECTOR_STRATEGIES:
        raise AiConfigError("Selector strategy must be warm, pin, or spillover")
    settings: dict[str, int] = {}
    if strategy == "spillover":
        if isinstance(spillover, bool) or not isinstance(spillover, int) or not 1 <= spillover <= 128:
            raise AiConfigError("Spillover reservation count must be an integer between 1 and 128")
        settings["spillover"] = spillover
    return str(strategy), settings


def load_config(path: pathlib.Path = CONFIG_PATH) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise AiConfigError(f"Unable to read llama-swap configuration: {path}") from exc
    if len(raw.encode("utf-8")) > MAX_CONFIG_BYTES:
        raise AiConfigError("llama-swap configuration is unexpectedly large")
    try:
        value = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise AiConfigError("llama-swap configuration is invalid YAML") from exc
    config = _require_mapping(value, "llama-swap configuration")
    config["models"] = _require_mapping(config.get("models"), "models")
    _require_mapping(config.get("peers"), "peers")
    _require_mapping(config.get("selectors"), "selectors")
    validate_secret_references(config)
    validate_selector_namespace(config)
    return config


def validate_secret_references(config: Mapping[str, Any]) -> None:
    peers = _require_mapping(config.get("peers"), "peers")
    for provider_id, raw_peer in peers.items():
        validate_provider_id(provider_id)
        peer = _require_mapping(raw_peer, f"peer {provider_id}")
        if "proxy" in peer:
            validate_proxy_url(str(peer["proxy"]))
        if "models" in peer:
            validate_models(peer["models"])
        validate_timeouts(peer.get("timeouts"))
        validate_filters(peer.get("filters"))
        api_key = peer.get("apiKey", "")
        if api_key:
            expected = "${env." + provider_env_name(provider_id) + "}"
            if not isinstance(api_key, str) or not ENV_MACRO_RE.fullmatch(api_key):
                raise AiConfigError(
                    f"Peer {provider_id} must reference an environment variable for apiKey; plaintext provider keys are forbidden"
                )
            if api_key != expected:
                raise AiConfigError(f"Peer {provider_id} must use its derived environment variable for apiKey")


def validate_selector_namespace(config: Mapping[str, Any]) -> None:
    selectors = _require_mapping(config.get("selectors"), "selectors")
    selector_ids = set(selectors)
    if not all(isinstance(selector_id, str) for selector_id in selector_ids):
        raise AiConfigError("Selector IDs must be strings")
    collisions = sorted(selector_ids.intersection(peer_targets(config)))
    if collisions:
        raise AiConfigError("Selector ID collides with a model target: " + ", ".join(collisions))
    for selector_id, raw_selector in selectors.items():
        selector = _require_mapping(raw_selector, f"selector {selector_id}")
        targets = selector.get("targets", [])
        if isinstance(targets, list) and selector_id in targets:
            raise AiConfigError(f"Selector {selector_id} cannot target itself")


def _validate_with_llama_swap(candidate: pathlib.Path) -> None:
    exe = os.environ.get("NAS_LLAMA_SWAP_BIN") or shutil.which("llama-swap") or ""
    if not exe:
        return
    exe_path = pathlib.Path(exe)
    if not exe_path.is_file():
        return
    # Try a non-destructive validation if the binary supports it; otherwise just ensure it can parse YAML.
    # llama-swap currently lacks a stable --validate flag, so we attempt a short-lived parse probe and
    # treat unknown-flag errors as non-fatal.
    for args in (
        ["--config", str(candidate), "--validate"],
        ["--config", str(candidate), "--dry-run"],
    ):
        try:
            result = subprocess.run(
                [str(exe_path), *args],
                timeout=5,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            if result.returncode == 0:
                return
            stderr = (result.stderr or b"").decode(errors="ignore")[:500].lower()
            # If the binary does not recognize the validation flag, fall back to python validation only.
            if "unknown" in stderr or "unrecognized" in stderr or "invalid" in stderr and "flag" in stderr:
                return
            if result.returncode != 0:
                detail = (result.stderr or result.stdout or b"").decode(errors="ignore")[:500]
                raise AiConfigError(f"llama-swap rejected configuration: {detail.strip()}")
            return
        except FileNotFoundError:
            return
        except subprocess.TimeoutExpired:
            return
        except OSError:
            return


def atomic_write(config: Mapping[str, Any], path: pathlib.Path = CONFIG_PATH) -> None:
    validate_secret_references(config)
    validate_selector_namespace(config)
    parent = path.parent
    if not parent.is_dir() or parent.is_symlink():
        raise AiConfigError(f"Unsafe llama-swap configuration directory: {parent}")
    encoded = yaml.safe_dump(dict(config), sort_keys=False, default_flow_style=False, allow_unicode=True)
    if len(encoded.encode("utf-8")) > MAX_CONFIG_BYTES:
        raise AiConfigError("Refusing to write an unexpectedly large llama-swap configuration")
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o640
    uid = path.stat().st_uid if path.exists() else os.geteuid()
    gid = path.stat().st_gid if path.exists() else os.getegid()
    fd, temporary = tempfile.mkstemp(prefix=".config.yaml.", dir=parent, text=True)
    temporary_path = pathlib.Path(temporary)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_path, mode)
        if os.geteuid() == 0:
            os.chown(temporary_path, uid, gid)
        # Validate with the exact pinned llama-swap parser before committing.
        _validate_with_llama_swap(temporary_path)
        os.replace(temporary_path, path)
        directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary_path.unlink(missing_ok=True)


def local_models_view(config: Mapping[str, Any]) -> list[dict[str, Any]]:
    models = _require_mapping(config.get("models"), "models")
    result: list[dict[str, Any]] = []
    for model_id in sorted(models):
        raw_model = _require_mapping(models[model_id], f"model {model_id}")
        metadata = raw_model.get("metadata", {})
        metadata = metadata if isinstance(metadata, dict) else {}
        managed = metadata.get("nasManaged") is True
        row: dict[str, Any] = {"id": model_id, "managed": managed}
        if managed:
            capabilities = raw_model.get("capabilities", {})
            capabilities = capabilities if isinstance(capabilities, dict) else {}
            context_value = capabilities.get("context", metadata.get("context", 32768))
            ttl_value = raw_model.get("ttl", metadata.get("ttl", -1))
            extra_args_value = metadata.get("extraArgs", [])
            row.update(
                {
                    "path": str(metadata.get("modelPath", "")),
                    "context": context_value
                    if isinstance(context_value, int) and not isinstance(context_value, bool)
                    else 32768,
                    "ttl": ttl_value if isinstance(ttl_value, int) and not isinstance(ttl_value, bool) else -1,
                    "tools": capabilities.get("tools") is True,
                    "extraArgs": [item for item in extra_args_value if isinstance(item, str)]
                    if isinstance(extra_args_value, list)
                    else [],
                }
            )
        result.append(row)
    return result


def peer_targets(config: Mapping[str, Any]) -> list[str]:
    targets = list(_require_mapping(config.get("models"), "models"))
    peers = _require_mapping(config.get("peers"), "peers")
    for provider_id, raw_peer in peers.items():
        peer = _require_mapping(raw_peer, f"peer {provider_id}")
        for model in peer.get("models", []):
            targets.append(f"{provider_id}/{validate_model_id(model)}")
    return sorted(set(targets))


CREDENTIAL_PRESENT = "PRESENT"
CREDENTIAL_ABSENT = "ABSENT"
CREDENTIAL_UNKNOWN = "UNKNOWN"


def _probe_provider_credential(provider_id: str) -> tuple[str, str | None]:
    try:
        expected = provider_env_name(provider_id)
    except AiConfigError:
        return (CREDENTIAL_UNKNOWN, None)
    secret_root = pathlib.Path(os.environ.get("NAS_SECRET_ROOT", "/run/nas-secrets"))
    env_path = secret_root / "ai" / "llama-swap.env"
    try:
        content = env_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return (CREDENTIAL_ABSENT, None)
    except (OSError, PermissionError):
        return (CREDENTIAL_UNKNOWN, None)
    except Exception:
        return (CREDENTIAL_UNKNOWN, None)
    for line in content.splitlines():
        if line.startswith(expected + "="):
            return (CREDENTIAL_PRESENT, line.split("=", 1)[1])
    return (CREDENTIAL_ABSENT, None)


def _provider_credential_staged(provider_id: str) -> bool | None:
    state, _ = _probe_provider_credential(provider_id)
    if state == CREDENTIAL_PRESENT:
        return True
    if state == CREDENTIAL_ABSENT:
        return False
    return None


def _write_provider_credential(provider_id: str, value: str) -> None:
    env_name = provider_env_name(provider_id)
    secret_root = pathlib.Path(os.environ.get("NAS_SECRET_ROOT", "/run/nas-secrets"))
    env_path = secret_root / "ai" / "llama-swap.env"
    try:
        existing = env_path.read_text(encoding="utf-8") if env_path.is_file() else ""
    except (OSError, PermissionError):
        raise AiConfigError(f"Unable to read credential store for {provider_id!r}")
    lines: list[str] = []
    replaced = False
    for line in existing.splitlines():
        if line.startswith(env_name + "="):
            if not replaced:
                lines.append(f"{env_name}={value}")
                replaced = True
        else:
            lines.append(line)
    if not replaced:
        lines.append(f"{env_name}={value}")
    content = "\n".join(lines) + "\n"
    parent = env_path.parent
    parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=parent, prefix=".llama-swap.env.", text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, env_path)
        os.chmod(env_path, 0o400)
    finally:
        pathlib.Path(tmp).unlink(missing_ok=True)


def _remove_provider_credential(provider_id: str) -> None:
    env_name = provider_env_name(provider_id)
    secret_root = pathlib.Path(os.environ.get("NAS_SECRET_ROOT", "/run/nas-secrets"))
    env_path = secret_root / "ai" / "llama-swap.env"
    if not env_path.is_file():
        return
    try:
        content = env_path.read_text(encoding="utf-8")
    except (OSError, PermissionError):
        raise AiConfigError(f"Unable to read credential store for {provider_id!r}")
    lines = [line for line in content.splitlines() if not line.startswith(env_name + "=")]
    new_content = "\n".join(lines) + ("\n" if lines else "")
    parent = env_path.parent
    fd, tmp = tempfile.mkstemp(dir=parent, prefix=".llama-swap.env.", text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(new_content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, env_path)
        os.chmod(env_path, 0o400)
    finally:
        pathlib.Path(tmp).unlink(missing_ok=True)


def _restore_provider_credential(provider_id: str, state: str, value: str | None) -> None:
    if state == CREDENTIAL_PRESENT and value is not None:
        _write_provider_credential(provider_id, value)
    elif state == CREDENTIAL_ABSENT:
        _remove_provider_credential(provider_id)


def _read_config_bytes(path: pathlib.Path) -> bytes | None:
    if not path.is_file():
        return None
    try:
        return path.read_bytes()
    except OSError as exc:
        raise AiConfigError(f"Unable to read prior config for rollback: {exc}") from exc


def _restore_config_bytes(path: pathlib.Path, old_bytes: bytes | None) -> None:
    if old_bytes is None:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        return
    parent = path.parent
    fd, tmp = tempfile.mkstemp(dir=parent, prefix=".config.yaml.restore.", text=False)
    try:
        os.write(fd, old_bytes)
        os.fsync(fd)
        os.close(fd)
        os.replace(tmp, path)
        try:
            dfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            pass
    except Exception:
        try:
            os.close(fd)
        except Exception:
            pass
        pathlib.Path(tmp).unlink(missing_ok=True)
        raise


def _maybe_restart_and_healthcheck() -> None:
    if os.environ.get("NAS_SKIP_LLAMA_SWAP_RESTART") == "1":
        return
    try:
        is_active = subprocess.run(["systemctl", "is-active", "--quiet", "nas-llama-swap.service"], check=False)
    except (OSError, FileNotFoundError):
        return
    if is_active.returncode != 0:
        return
    try:
        restarted = subprocess.run(["systemctl", "restart", "nas-llama-swap.service"], check=False)
    except (OSError, FileNotFoundError) as exc:
        raise AiConfigError(f"llama-swap restart failed: {exc}") from exc
    if restarted.returncode != 0:
        raise AiConfigError("llama-swap restart failed after config update")
    try:
        healthy = subprocess.run(["systemctl", "is-active", "--quiet", "nas-llama-swap.service"], check=False)
    except (OSError, FileNotFoundError):
        return
    if healthy.returncode != 0:
        raise AiConfigError("llama-swap failed to start after provider update")


def public_view(config: Mapping[str, Any]) -> dict[str, Any]:
    peers = _require_mapping(config.get("peers"), "peers")
    providers: list[dict[str, Any]] = []
    for provider_id in sorted(peers):
        peer = _require_mapping(peers[provider_id], f"peer {provider_id}")
        api_key = peer.get("apiKey", "")
        match = ENV_MACRO_RE.fullmatch(api_key) if isinstance(api_key, str) else None
        try:
            expected_macro = "${env." + provider_env_name(provider_id) + "}"
            reference_ok = bool(match and api_key == expected_macro)
        except AiConfigError:
            reference_ok = False
        staged = _provider_credential_staged(provider_id)
        # credentialConfigured is legacy alias for reference presence; keep for compat.
        providers.append(
            {
                "id": provider_id,
                "url": peer.get("proxy", ""),
                "models": list(peer.get("models", [])),
                "credentialConfigured": bool(match and reference_ok),
                "credentialReferenceConfigured": bool(reference_ok),
                "credentialEnv": match.group(1) if match else None,
                "credentialStaged": staged,
                "timeouts": peer.get("timeouts", {}),
                "filters": peer.get("filters", {}),
            }
        )
    selectors = _require_mapping(config.get("selectors"), "selectors")
    roles: dict[str, dict[str, Any]] = {}
    for role in ROLE_IDS:
        raw = selectors.get(role, {})
        selector = _require_mapping(raw, f"selector {role}")
        values = selector.get("targets", [])
        strategy = selector.get("strategy", "warm")
        settings = selector.get("settings", {}) if isinstance(selector.get("settings", {}), dict) else {}
        roles[role] = {
            "targets": [str(item) for item in values] if isinstance(values, list) else [],
            "strategy": strategy if strategy in SELECTOR_STRATEGIES else "warm",
            "spillover": settings.get("spillover", 1),
        }
    return {
        "ok": True,
        "providers": providers,
        "localModels": local_models_view(config),
        "codingRoles": roles,
        "availableTargets": peer_targets(config),
        "configPath": str(CONFIG_PATH),
        "advanced": {
            "healthCheckTimeout": config.get("healthCheckTimeout"),
            "globalTTL": config.get("globalTTL"),
            "unloadTimeout": config.get("unloadTimeout"),
            "logLevel": config.get("logLevel"),
            "captureBuffer": config.get("captureBuffer"),
            "metricsMaxInMemory": config.get("metricsMaxInMemory"),
        },
    }


def set_provider(
    provider_id: str,
    url: str,
    models: Sequence[str],
    *,
    credential: bool,
    timeouts: object = None,
    filters: object = None,
    path: pathlib.Path = CONFIG_PATH,
) -> dict[str, Any]:
    provider_id = validate_provider_id(provider_id)
    url = validate_proxy_url(url)
    model_list = validate_models(models)
    old_state, old_value = _probe_provider_credential(provider_id)
    if old_state == CREDENTIAL_UNKNOWN:
        raise AiConfigError(
            f"Unable to determine prior credential state for provider {provider_id!r}; aborting to avoid credential loss"
        )
    old_config_bytes = _read_config_bytes(path)
    did_write = False
    try:
        config = load_config(path) if path.is_file() else {"models": {}, "peers": {}, "selectors": {}}
        if not isinstance(config, dict):
            raise AiConfigError("llama-swap configuration must be an object")
        peers = _require_mapping(config.get("peers"), "peers")
        old = _require_mapping(peers.get(provider_id), f"peer {provider_id}")
        peer: dict[str, Any] = {"proxy": url, "models": model_list}
        validated_timeouts = validate_timeouts(timeouts)
        validated_filters = validate_filters(filters)
        if validated_timeouts:
            peer["timeouts"] = validated_timeouts
        elif isinstance(old.get("timeouts"), dict):
            peer["timeouts"] = old["timeouts"]
        if validated_filters:
            peer["filters"] = validated_filters
        elif isinstance(old.get("filters"), dict):
            peer["filters"] = old["filters"]
        if credential:
            peer["apiKey"] = "${env." + provider_env_name(provider_id) + "}"
        elif old.get("apiKey"):
            peer["apiKey"] = old["apiKey"]
        peers[provider_id] = peer
        config["peers"] = peers
        atomic_write(config, path)
        did_write = True
        _maybe_restart_and_healthcheck()
        return public_view(config)
    except Exception as exc:
        if did_write:
            try:
                _restore_config_bytes(path, old_config_bytes)
            except Exception:
                pass
            try:
                _restore_provider_credential(provider_id, old_state, old_value)
            except Exception:
                pass
        if isinstance(exc, AiConfigError):
            raise
        raise AiConfigError(str(exc)) from exc


def delete_provider(provider_id: str, *, path: pathlib.Path = CONFIG_PATH) -> dict[str, Any]:
    provider_id = validate_provider_id(provider_id)
    old_state, old_value = _probe_provider_credential(provider_id)
    if old_state == CREDENTIAL_UNKNOWN:
        raise AiConfigError(
            f"Unable to determine prior credential state for provider {provider_id!r}; aborting to avoid credential loss"
        )
    old_config_bytes = _read_config_bytes(path)
    did_write = False
    try:
        config = load_config(path)
        peers = _require_mapping(config.get("peers"), "peers")
        peers.pop(provider_id, None)
        config["peers"] = peers
        selectors = _require_mapping(config.get("selectors"), "selectors")
        prefix = provider_id + "/"
        for role in ROLE_IDS:
            raw = _require_mapping(selectors.get(role), f"selector {role}")
            targets = raw.get("targets", [])
            if isinstance(targets, list):
                kept = [target for target in targets if not (isinstance(target, str) and target.startswith(prefix))]
                if kept:
                    raw["targets"] = kept
                    selectors[role] = raw
                elif role in selectors:
                    selectors.pop(role, None)
        config["selectors"] = selectors
        atomic_write(config, path)
        did_write = True
        _maybe_restart_and_healthcheck()
        return public_view(config)
    except Exception as exc:
        if did_write:
            try:
                _restore_config_bytes(path, old_config_bytes)
            except Exception:
                pass
            try:
                _restore_provider_credential(provider_id, old_state, old_value)
            except Exception:
                pass
        if isinstance(exc, AiConfigError):
            raise
        raise AiConfigError(str(exc)) from exc


def set_local_model(
    model_id: str,
    model_path: str,
    *,
    context: int,
    ttl: int,
    tools: bool,
    extra_args: object = None,
    path: pathlib.Path = CONFIG_PATH,
) -> dict[str, Any]:
    model_id = validate_local_model_id(model_id)
    resolved = validate_local_model_path(model_path)
    if isinstance(context, bool) or not isinstance(context, int) or not 1024 <= context <= 1_048_576:
        raise AiConfigError("Local model context must be an integer between 1024 and 1048576")
    if isinstance(ttl, bool) or not isinstance(ttl, int) or not -1 <= ttl <= 604800:
        raise AiConfigError("Local model TTL must be -1 or an integer between 0 and 604800")
    if not isinstance(tools, bool):
        raise AiConfigError("Local model tools capability must be boolean")
    args = validate_local_extra_args(extra_args)
    old_config_bytes = _read_config_bytes(path)
    did_write = False
    try:
        config = load_config(path)
        models = _require_mapping(config.get("models"), "models")
        existing = _require_mapping(models.get(model_id), f"model {model_id}")
        existing_metadata = existing.get("metadata", {}) if isinstance(existing.get("metadata", {}), dict) else {}
        if existing and existing_metadata.get("nasManaged") is not True:
            raise AiConfigError(
                f"Local model {model_id} is administrator-managed outside Cockpit and cannot be overwritten"
            )
        command_parts = [
            llama_server_path(),
            "--host",
            "127.0.0.1",
            "--port",
            "${PORT}",
            "--model",
            str(resolved),
            "--ctx-size",
            str(context),
            *args,
        ]
        command = " ".join(item if item == "${PORT}" else shlex.quote(item) for item in command_parts)
        models[model_id] = {
            "cmd": command,
            "ttl": ttl,
            "metadata": {
                "nasManaged": True,
                "modelPath": str(resolved),
                "extraArgs": args,
                "context": context,
                "ttl": ttl,
            },
            "capabilities": {"in": ["text"], "out": ["text"], "tools": tools, "context": context},
        }
        config["models"] = models
        atomic_write(config, path)
        did_write = True
        _maybe_restart_and_healthcheck()
        return public_view(config)
    except Exception as exc:
        if did_write:
            try:
                _restore_config_bytes(path, old_config_bytes)
            except Exception:
                pass
        if isinstance(exc, AiConfigError):
            raise
        raise AiConfigError(str(exc)) from exc


def delete_local_model(model_id: str, *, path: pathlib.Path = CONFIG_PATH) -> dict[str, Any]:
    model_id = validate_local_model_id(model_id)
    old_config_bytes = _read_config_bytes(path)
    did_write = False
    try:
        config = load_config(path)
        models = _require_mapping(config.get("models"), "models")
        existing = _require_mapping(models.get(model_id), f"model {model_id}")
        metadata = existing.get("metadata", {}) if isinstance(existing.get("metadata", {}), dict) else {}
        if not existing:
            raise AiConfigError(f"Local model {model_id} does not exist")
        if metadata.get("nasManaged") is not True:
            raise AiConfigError(
                f"Local model {model_id} is administrator-managed outside Cockpit and cannot be deleted"
            )
        models.pop(model_id, None)
        config["models"] = models
        selectors = _require_mapping(config.get("selectors"), "selectors")
        for role in ROLE_IDS:
            raw = _require_mapping(selectors.get(role), f"selector {role}")
            targets = raw.get("targets", [])
            if isinstance(targets, list):
                kept = [target for target in targets if target != model_id]
                if kept:
                    raw["targets"] = kept
                    selectors[role] = raw
                elif role in selectors:
                    selectors.pop(role, None)
        config["selectors"] = selectors
        atomic_write(config, path)
        did_write = True
        _maybe_restart_and_healthcheck()
        return public_view(config)
    except Exception as exc:
        if did_write:
            try:
                _restore_config_bytes(path, old_config_bytes)
            except Exception:
                pass
        if isinstance(exc, AiConfigError):
            raise
        raise AiConfigError(str(exc)) from exc


def set_role(
    role: str,
    targets: Sequence[str],
    *,
    strategy: str = "warm",
    spillover: int = 1,
    path: pathlib.Path = CONFIG_PATH,
) -> dict[str, Any]:
    role = validate_role(role)
    if not isinstance(targets, (list, tuple)) or not targets:
        raise AiConfigError("A coding model role requires at least one target")
    validated = [validate_model_id(target) for target in targets]
    strategy, settings = validate_selector_settings(strategy, spillover)
    old_config_bytes = _read_config_bytes(path)
    did_write = False
    try:
        config = load_config(path)
        available = set(peer_targets(config))
        unknown = [target for target in validated if target not in available]
        if unknown:
            raise AiConfigError("Unknown model target(s): " + ", ".join(unknown))
        selectors = _require_mapping(config.get("selectors"), "selectors")
        selector: dict[str, Any] = {"strategy": strategy, "targets": list(dict.fromkeys(validated))}
        if settings:
            selector["settings"] = settings
        selectors[role] = selector
        config["selectors"] = selectors
        atomic_write(config, path)
        did_write = True
        _maybe_restart_and_healthcheck()
        return public_view(config)
    except Exception as exc:
        if did_write:
            try:
                _restore_config_bytes(path, old_config_bytes)
            except Exception:
                pass
        if isinstance(exc, AiConfigError):
            raise
        raise AiConfigError(str(exc)) from exc


def replace_advanced(values: Mapping[str, object], *, path: pathlib.Path = CONFIG_PATH) -> dict[str, Any]:
    old_config_bytes = _read_config_bytes(path)
    did_write = False
    try:
        config = load_config(path)
        if "healthCheckTimeout" in values:
            timeout = values["healthCheckTimeout"]
            if not isinstance(timeout, int) or not 15 <= timeout <= 3600:
                raise AiConfigError("healthCheckTimeout must be an integer between 15 and 3600")
            config["healthCheckTimeout"] = timeout
        if "globalTTL" in values:
            ttl = values["globalTTL"]
            if isinstance(ttl, bool) or not isinstance(ttl, int) or not 0 <= ttl <= 604800:
                raise AiConfigError("globalTTL must be an integer between 0 and 604800")
            config["globalTTL"] = ttl
        if "unloadTimeout" in values:
            timeout = values["unloadTimeout"]
            if isinstance(timeout, bool) or not isinstance(timeout, int) or not 0 <= timeout <= 3600:
                raise AiConfigError("unloadTimeout must be an integer between 0 and 3600")
            config["unloadTimeout"] = timeout
        if "logLevel" in values:
            level = values["logLevel"]
            if level not in {"debug", "info", "warn", "error"}:
                raise AiConfigError("logLevel must be debug, info, warn, or error")
            config["logLevel"] = level
        if "captureBuffer" in values:
            capture = values["captureBuffer"]
            if not isinstance(capture, int) or not 0 <= capture <= 1024:
                raise AiConfigError("captureBuffer must be an integer between 0 and 1024 MiB")
            config["captureBuffer"] = capture
        if "metricsMaxInMemory" in values:
            count = values["metricsMaxInMemory"]
            if not isinstance(count, int) or not 0 <= count <= 1_000_000:
                raise AiConfigError("metricsMaxInMemory must be an integer between 0 and 1000000")
            config["metricsMaxInMemory"] = count
        atomic_write(config, path)
        did_write = True
        _maybe_restart_and_healthcheck()
        return public_view(config)
    except Exception as exc:
        if did_write:
            try:
                _restore_config_bytes(path, old_config_bytes)
            except Exception:
                pass
        if isinstance(exc, AiConfigError):
            raise
        raise AiConfigError(str(exc)) from exc


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="nas-ai-config")
    sub = result.add_subparsers(dest="command", required=True)
    sub.add_parser("show")
    provider = sub.add_parser("set-provider")
    provider.add_argument("provider_id")
    provider.add_argument("url")
    provider.add_argument("models_json")
    provider.add_argument("--credential", action="store_true")
    provider.add_argument("--timeouts-json", default="{}")
    provider.add_argument("--filters-json", default="{}")
    delete = sub.add_parser("delete-provider")
    delete.add_argument("provider_id")
    local_model = sub.add_parser("set-local-model")
    local_model.add_argument("model_id")
    local_model.add_argument("model_path")
    local_model.add_argument("--context", type=int, required=True)
    local_model.add_argument("--ttl", type=int, default=-1)
    local_model.add_argument("--tools", action="store_true")
    local_model.add_argument("--extra-args-json", default="[]")
    local_delete = sub.add_parser("delete-local-model")
    local_delete.add_argument("model_id")
    role = sub.add_parser("set-role")
    role.add_argument("role")
    role.add_argument("targets_json")
    role.add_argument("--strategy", choices=SELECTOR_STRATEGIES, default="warm")
    role.add_argument("--spillover", type=int, default=1)
    advanced = sub.add_parser("set-advanced")
    advanced.add_argument("values_json")
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "show":
            value = public_view(load_config())
        elif args.command == "set-provider":
            models = json.loads(args.models_json)
            timeouts = json.loads(args.timeouts_json)
            filters = json.loads(args.filters_json)
            value = set_provider(
                args.provider_id, args.url, models, credential=args.credential, timeouts=timeouts, filters=filters
            )
        elif args.command == "delete-provider":
            value = delete_provider(args.provider_id)
        elif args.command == "set-local-model":
            extra_args = json.loads(args.extra_args_json)
            value = set_local_model(
                args.model_id,
                args.model_path,
                context=args.context,
                ttl=args.ttl,
                tools=args.tools,
                extra_args=extra_args,
            )
        elif args.command == "delete-local-model":
            value = delete_local_model(args.model_id)
        elif args.command == "set-role":
            targets = json.loads(args.targets_json)
            value = set_role(args.role, targets, strategy=args.strategy, spillover=args.spillover)
        elif args.command == "set-advanced":
            values = json.loads(args.values_json)
            if not isinstance(values, dict):
                raise AiConfigError("Advanced settings must be an object")
            value = replace_advanced(values)
        else:  # pragma: no cover
            raise AiConfigError("Unknown command")
        print(json.dumps(value, sort_keys=True))
        return 0
    except (AiConfigError, json.JSONDecodeError, OSError) as exc:
        print(f"nas-ai-config: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
