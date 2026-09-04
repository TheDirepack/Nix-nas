#!/usr/bin/env python3
"""Bootstrap Authentik NAS roles and reconcile Authentik-owned Syncthing data.

This service never writes CopyParty configuration. CopyParty owns volumes, ACLs,
flags, and share links; Authentik owns users, credentials, groups, application
capability assignments, and profile attributes. Managed Services V2 ensures
application capability objects separately. This reconciler updates base identity
roles and Syncthing objects in the reserved ``nas-`` namespace only.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import grp
import hashlib
import json
import os
import pathlib
import pwd
import re
import secrets
import sys
import syslog
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Mapping

from nas_common import ADMIN_GROUP, DISABLED_GROUP
from nas_operation_journal import JournalError, OperationJournal, load_json
from nas_operation_lock import (
    COORDINATION_TOKEN_ENV,
    OperationBusyError,
    acquire_operation,
    validate_coordination_token,
)
from nas_syncthing_devices import DeviceError, validate_username
from nas_identity_model import (
    RESERVED_GROUPS,
    IdentityModel,
    SyncError,
    build_model,
    capability_status,
    enabled_administrator_names,
    model_status,
    normalized_account_plan,
    raw_group_pks,
    user_detail_pk,
    validate_uid,
    desired_syncthing as desired_syncthing_model,
)

AUTHENTIK_URL = os.environ.get("NAS_AUTHENTIK_URL", "http://127.0.0.1:9000/identity").rstrip("/")
AUTHENTIK_TOKEN_FILE = pathlib.Path(os.environ.get("NAS_AUTHENTIK_TOKEN_FILE", "/run/nas-secrets/authentik/api-token"))
AUTHENTIK_BOOTSTRAP_TOKEN_FILE = pathlib.Path(
    os.environ.get("NAS_AUTHENTIK_BOOTSTRAP_TOKEN_FILE", "/run/nas-secrets/authentik/bootstrap-token")
)
SHARE_ROOT = pathlib.Path(os.environ.get("NAS_SHARE_ROOT", "/tank/shares"))
STATE_PATH = pathlib.Path(os.environ.get("NAS_IDENTITY_STATE", "/var/lib/nas-identity-sync/state.json"))
SYNCTHING_JOURNAL_PATH = pathlib.Path(
    os.environ.get(
        "NAS_SYNCTHING_JOURNAL",
        "/var/lib/nas-identity-sync/syncthing-reconcile-journal.json",
    )
)
LOCK_PATH = pathlib.Path(os.environ.get("NAS_IDENTITY_LOCK", "/run/lock/nas-identity-sync.lock"))
ACCOUNT_JOURNAL_PATH = pathlib.Path(
    os.environ.get("NAS_ACCOUNT_JOURNAL", "/var/lib/nas-identity-sync/account-plan-journal.json")
)
SYNCTHING_ENABLED = os.environ.get("NAS_SYNCTHING_ENABLE", "0") == "1"
PUBLIC_HOST = os.environ.get("NAS_PUBLIC_HOST", "").strip()
DEFAULT_FLOW_WAIT_SECONDS = 90.0
BOOTSTRAP_RECONCILE_ATTEMPTS = 4


def _resolve_syncthing_url() -> str:  # pragma: no cover - V2 integration
    explicit = os.environ.get("NAS_SYNCTHING_URL")
    if explicit:
        return explicit.rstrip("/")
    try:
        from nas_common import load_effective_authority

        data = load_effective_authority()
        port = (
            data.get("services", {}).get("syncthing", {}).get("routes", {}).get("web", {}).get("target", {}).get("port")
        )
        if isinstance(port, int) and 1 <= port <= 65535:
            return f"http://127.0.0.1:{port}"
        raise RuntimeError("syncthing web target port missing in effective state")
    except FileNotFoundError:
        # Effective state not yet present (early boot/test). Fall back to legacy default
        # but systemd ConditionPathExists will gate real VM execution until effective exists.
        return "http://127.0.0.1:8384"
    except Exception as exc:
        raise RuntimeError(f"unable to resolve syncthing URL from effective state: {exc}") from exc


try:
    SYNCTHING_URL = _resolve_syncthing_url()
except RuntimeError:
    # Defer failure to call site; keep module importable in test harnesses.
    SYNCTHING_URL = "http://127.0.0.1:8384"
SYNCTHING_CONFIG_DIR = pathlib.Path(os.environ.get("NAS_SYNCTHING_CONFIG_DIR", "/var/lib/syncthing/.config/syncthing"))


def diagnostic(message: str) -> None:
    try:
        syslog.syslog(syslog.LOG_ERR, message)
    except OSError:
        if os.environ.get("NAS_DIAGNOSTICS_STDERR") == "1":
            print(message, file=sys.stderr)


def endpoint_label(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def sanitize_error_payload(payload: bytes) -> str:
    text = payload.decode("utf-8", "replace")
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return "non-JSON response"

    def redact(item: Any) -> Any:
        if isinstance(item, dict):
            return {
                str(key): "[redacted]"
                if any(part in str(key).lower() for part in ("token", "password", "secret", "key"))
                else redact(nested)
                for key, nested in item.items()
            }
        if isinstance(item, list):
            return [redact(nested) for nested in item[:10]]
        if isinstance(item, str):
            return item[:120]
        return item

    return json.dumps(redact(value), sort_keys=True)[:500]


def _retry_delay(attempt: int, retry_after: str | None = None) -> float:
    """Return a bounded retry delay for idempotent Authentik reads."""
    if retry_after:
        try:
            return min(max(float(retry_after), 0.25), 5.0)
        except ValueError:
            pass
    base = min(0.25 * (2 ** max(attempt - 1, 0)), 2.0)
    jitter_ceiling = min(base * 0.25, 0.25)
    jitter = (secrets.randbelow(1_000_001) / 1_000_000) * jitter_ceiling
    return base + jitter


def bootstrap_identity(token: str) -> dict[str, Any]:
    """Converge bootstrap objects after Authentik's asynchronous blueprint startup."""
    for attempt in range(1, BOOTSTRAP_RECONCILE_ATTEMPTS + 1):
        try:
            return {
                "groups": ensure_groups(token),
                "portal": ensure_portal_proxy(token),
                "cockpit": ensure_cockpit_launcher(token),
                "setup": ensure_setup_launcher(token),
            }
        except SyncError:
            if attempt >= BOOTSTRAP_RECONCILE_ATTEMPTS:
                raise
            diagnostic(
                "nas-identity-sync: Authentik bootstrap reconciliation raced with startup; "
                f"retrying attempt {attempt + 1}/{BOOTSTRAP_RECONCILE_ATTEMPTS}"
            )
            time.sleep(_retry_delay(attempt))
    raise SyncError("Authentik bootstrap reconciliation exhausted retries")  # pragma: no cover


def http_json(
    url: str,
    *,
    method: str = "GET",
    body: Any | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 15.0,
) -> Any:
    data = None
    request_headers = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        request_headers["Content-Type"] = "application/json"
    if headers:
        request_headers.update(headers)

    normalized_method = method.upper()
    max_attempts = 3 if normalized_method in {"GET", "HEAD"} else 1
    reference = secrets.token_hex(6)
    last_error: BaseException | None = None

    for attempt in range(1, max_attempts + 1):
        request = urllib.request.Request(url, data=data, headers=request_headers, method=normalized_method)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = response.read()
            break
        except urllib.error.HTTPError as exc:
            payload = exc.read()
            request_id = exc.headers.get("X-Request-ID") if exc.headers else None
            detail = sanitize_error_payload(payload)
            transient = exc.code in {408, 425, 429} or 500 <= exc.code <= 599
            diagnostic(
                f"nas-identity-sync: request {reference} HTTP {exc.code} "
                f"attempt={attempt}/{max_attempts} endpoint={endpoint_label(url)} "
                f"upstream_request={request_id or '-'} detail={detail}"
            )
            last_error = exc
            if transient and attempt < max_attempts:
                retry_after = exc.headers.get("Retry-After") if exc.headers else None
                time.sleep(_retry_delay(attempt, retry_after))
                continue
            raise SyncError(f"Authentik request failed with HTTP {exc.code} (reference {reference})") from exc
        except urllib.error.URLError as exc:
            diagnostic(
                f"nas-identity-sync: request {reference} unreachable "
                f"attempt={attempt}/{max_attempts} endpoint={endpoint_label(url)} "
                f"reason={type(exc.reason).__name__}"
            )
            last_error = exc
            if attempt < max_attempts:
                time.sleep(_retry_delay(attempt))
                continue
            raise SyncError(f"Unable to reach Authentik (reference {reference})") from exc
    else:  # pragma: no cover
        raise SyncError(f"Unable to reach Authentik (reference {reference})") from last_error

    if not payload:
        return None
    try:
        return json.loads(payload)
    except json.JSONDecodeError as exc:
        diagnostic(f"nas-identity-sync: request {reference} invalid-json endpoint={endpoint_label(url)}")
        raise SyncError(f"Authentik returned invalid JSON (reference {reference})") from exc


def authentik_token(*, bootstrap: bool = False) -> str:
    token_file = AUTHENTIK_BOOTSTRAP_TOKEN_FILE if bootstrap else AUTHENTIK_TOKEN_FILE
    kind = "bootstrap" if bootstrap else "runtime API"
    try:
        token = token_file.read_text(encoding="utf-8").strip()
    except FileNotFoundError as exc:
        raise SyncError(f"Authentik {kind} token is missing: {token_file}") from exc
    if not token or len(token) > 4096:
        raise SyncError(f"Authentik {kind} token is empty or malformed")
    return token


def authentik_request(token: str, path: str, *, method: str = "GET", body: Any | None = None) -> Any:
    url = path if path.startswith(("http://", "https://")) else f"{AUTHENTIK_URL}/api/v3/{path.lstrip('/')}"
    return http_json(url, method=method, body=body, headers={"Authorization": f"Bearer {token}"})


def authentik_list(token: str, path: str) -> list[dict[str, Any]]:
    separator = "&" if "?" in path else "?"
    url = f"{AUTHENTIK_URL}/api/v3/{path.lstrip('/')}{separator}page_size=100"
    output: list[dict[str, Any]] = []
    seen: set[str] = set()
    while url:
        if url in seen:
            raise SyncError(f"Authentik returned a pagination loop for {path}")
        seen.add(url)
        value = authentik_request(token, url)
        if isinstance(value, list):
            output.extend(item for item in value if isinstance(item, dict))
            break
        if not isinstance(value, dict) or not isinstance(value.get("results"), list):
            raise SyncError(f"Authentik endpoint {path} did not return a result list")
        output.extend(item for item in value["results"] if isinstance(item, dict))
        pagination = value.get("pagination")
        next_page = pagination.get("next") if isinstance(pagination, dict) else None
        if isinstance(next_page, int) and next_page > 0:
            parsed = urllib.parse.urlsplit(url)
            query = urllib.parse.parse_qs(parsed.query)
            query["page"] = [str(next_page)]
            url = urllib.parse.urlunsplit(
                (parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(query, doseq=True), "")
            )
        else:
            url = ""
    return output


def ensure_groups(token: str) -> dict[str, Any]:
    existing = {
        str(item.get("name")): item
        for item in authentik_list(token, "core/groups/")
        if isinstance(item.get("name"), str)
    }
    created: list[str] = []
    corrected: list[str] = []
    for name in RESERVED_GROUPS:
        desired_superuser = name == ADMIN_GROUP
        current = existing.get(name)
        if current is None:
            authentik_request(
                token,
                "core/groups/",
                method="POST",
                body={"name": name, "is_superuser": desired_superuser, "attributes": {}},
            )
            created.append(name)
        elif bool(current.get("is_superuser")) != desired_superuser:
            primary_key = current.get("pk")
            if primary_key is None:
                raise SyncError(f"Authentik group {name} has no primary key")
            authentik_request(
                token,
                f"core/groups/{urllib.parse.quote(str(primary_key), safe='')}/",
                method="PATCH",
                body={"is_superuser": desired_superuser},
            )
            corrected.append(name)

    refreshed_groups = authentik_list(token, "core/groups/?include_users=true")
    admin_group = next((item for item in refreshed_groups if item.get("name") == ADMIN_GROUP), None)
    if not isinstance(admin_group, Mapping) or admin_group.get("pk") is None:
        raise SyncError(f"Authentik group {ADMIN_GROUP} could not be loaded after bootstrap")

    explicit_members = admin_group.get("users_obj")
    if not isinstance(explicit_members, list):
        explicit_members = admin_group.get("users")
    explicit_members = explicit_members if isinstance(explicit_members, list) else []
    bootstrapped_member: str | None = None
    if not explicit_members:
        users = authentik_list(token, "core/users/?include_groups=true")
        akadmin = next(
            (item for item in users if item.get("username") == "akadmin" and item.get("is_active") is True),
            None,
        )
        if not isinstance(akadmin, Mapping):
            raise SyncError(
                f"{ADMIN_GROUP} has no enabled members and the default akadmin account "
                "could not be found. Add an enabled user explicitly to the group."
            )
        user_pk = akadmin.get("num_pk", akadmin.get("pk"))
        if not isinstance(user_pk, int):
            raise SyncError("Authentik akadmin does not expose the numeric user ID required for group membership")
        group_pk = urllib.parse.quote(str(admin_group["pk"]), safe="")
        authentik_request(token, f"core/groups/{group_pk}/add_user/", method="POST", body={"pk": user_pk})
        bootstrapped_member = "akadmin"

    return {
        "createdGroups": created,
        "correctedSuperuserGroups": corrected,
        "bootstrappedAdministrator": bootstrapped_member,
        "note": (
            f"{ADMIN_GROUP} is the only Authentik superuser group. It may contain "
            "multiple fully trusted administrators; application capability assignments remain Authentik-owned."
        ),
    }


def default_flows(token: str) -> dict[str, Any]:
    required = {
        "authentication_flow": "default-authentication-flow",
        "authorization_flow": "default-provider-authorization-implicit-consent",
        "invalidation_flow": "default-invalidation-flow",
    }
    deadline = time.monotonic() + DEFAULT_FLOW_WAIT_SECONDS
    while True:
        flows = {str(item.get("slug")): item for item in authentik_list(token, "flows/instances/")}
        missing = [slug for slug in required.values() if not isinstance(flows.get(slug), Mapping)]
        if not missing:
            return flows
        if time.monotonic() >= deadline:
            raise SyncError("Authentik default flow(s) are missing: " + ", ".join(missing))
        time.sleep(1)


def _ensure_proxy_application(
    token: str,
    *,
    provider_name: str,
    application_slug: str,
    external_host: str,
    internal_host: str,
    application_metadata: Mapping[str, Any] | None = None,
    outpost_config_patch: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Reconcile one Authentik proxy application as a staged transaction."""
    flows = default_flows(token)
    provider_payload: dict[str, Any] = {
        "name": provider_name,
        "mode": "forward_single",
        "external_host": external_host,
        "internal_host": internal_host,
        "internal_host_ssl_validation": False,
    }
    for field, slug in {
        "authentication_flow": "default-authentication-flow",
        "authorization_flow": "default-provider-authorization-implicit-consent",
        "invalidation_flow": "default-invalidation-flow",
    }.items():
        flow = flows.get(slug)
        if not isinstance(flow, Mapping) or flow.get("pk") is None:
            raise SyncError(f"Authentik flow {slug} is missing")
        provider_payload[field] = flow["pk"]

    application_template: dict[str, Any] = {
        "name": provider_name,
        "slug": application_slug,
        "provider": None,
        "meta_launch_url": external_host,
        **dict(application_metadata or {}),
    }

    # Stage every dependency and rollback snapshot before the first write.
    provider_before = next(
        (item for item in authentik_list(token, "providers/proxy/") if item.get("name") == provider_name),
        None,
    )
    application_before = next(
        (item for item in authentik_list(token, "core/applications/") if item.get("slug") == application_slug),
        None,
    )
    outpost = next(
        (
            item
            for item in authentik_list(token, "outposts/instances/")
            if item.get("managed") == "goauthentik.io/outposts/embedded"
        ),
        None,
    )
    if not isinstance(outpost, Mapping) or outpost.get("pk") is None:
        raise SyncError("Authentik embedded outpost is missing")
    outpost_pk = outpost["pk"]
    providers_before = list(outpost.get("providers") or [])
    current_config = outpost.get("config")
    config_before = dict(current_config) if isinstance(current_config, Mapping) else {}
    desired_config = dict(config_before)
    if outpost_config_patch is not None:
        desired_config.update(outpost_config_patch)

    provider_existing = isinstance(provider_before, Mapping)
    provider_pk: Any | None = None
    provider_restore: dict[str, Any] | None = None
    if provider_existing:
        provider_pk = provider_before.get("pk")
        if provider_pk is None:
            raise SyncError(f"Authentik {provider_name} provider has no primary key")
        missing = [key for key in provider_payload if key not in provider_before]
        if missing:
            raise SyncError(
                f"Authentik {provider_name} provider cannot be transactionally updated; "
                f"rollback fields are missing: {', '.join(sorted(missing))}"
            )
        provider_restore = {key: provider_before[key] for key in provider_payload}

    application_existing = isinstance(application_before, Mapping)
    application_restore: dict[str, Any] | None = None
    if application_existing:
        application_restore = {}
        for key, desired in application_template.items():
            if key == "name":
                application_restore[key] = application_before.get(key, provider_name)
            elif key == "slug":
                application_restore[key] = application_slug
            elif key == "provider":
                application_restore[key] = application_before.get(key)
            else:
                default = False if isinstance(desired, bool) else ""
                application_restore[key] = application_before.get(key, default)

    provider_committed = False
    provider_create_attempted = False
    application_committed = False
    application_create_attempted = False
    application_restore_needed = False
    outpost_restore_needed = False
    try:
        if provider_existing:
            # A failed PATCH may have reached Authentik before the client
            # observed the transport failure, so restore this snapshot too.
            provider_committed = True
            authentik_request(
                token,
                f"providers/proxy/{provider_pk}/",
                method="PATCH",
                body=provider_payload,
            )
        else:
            provider_create_attempted = True
            provider = authentik_request(
                token,
                "providers/proxy/",
                method="POST",
                body=provider_payload,
            )
            provider_pk = provider.get("pk") if isinstance(provider, Mapping) else None
            if provider_pk is None:
                raise SyncError(f"Authentik {provider_name} provider has no primary key")
            provider_committed = True

        application_payload = dict(application_template)
        application_payload["provider"] = provider_pk
        if application_existing:
            application_restore_needed = True
            authentik_request(
                token,
                f"core/applications/{application_slug}/",
                method="PATCH",
                body=application_payload,
            )
            application_committed = True
        else:
            application_create_attempted = True
            authentik_request(
                token,
                "core/applications/",
                method="POST",
                body=application_payload,
            )
            application_committed = True

        desired_providers = providers_before if provider_pk in providers_before else providers_before + [provider_pk]
        outpost_payload: dict[str, Any] = {"providers": desired_providers}
        rollback_outpost_payload: dict[str, Any] = {"providers": providers_before}
        config_changed = outpost_config_patch is not None and desired_config != config_before
        if outpost_config_patch is not None:
            outpost_payload["config"] = desired_config
            rollback_outpost_payload["config"] = config_before
        if provider_pk not in providers_before or config_changed:
            outpost_restore_needed = True
            authentik_request(
                token,
                f"outposts/instances/{outpost_pk}/",
                method="PATCH",
                body=outpost_payload,
            )
        return {"provider": provider_name, "application": application_slug}
    except Exception as exc:  # noqa: BLE001 - rollback must cover transport failures too
        rollback_errors: list[str] = []

        def rollback(label: str, operation: Any) -> None:
            try:
                operation()
            except Exception as rollback_exc:  # noqa: BLE001
                rollback_errors.append(f"{label}: {type(rollback_exc).__name__}")

        # A non-idempotent POST can succeed upstream even when the client never
        # receives its response. The staged snapshot proves these reserved
        # objects did not exist before this transaction, so rediscover exact
        # names/slugs before rollback and remove any ambiguous creation.
        if not application_existing and application_create_attempted and not application_committed:
            try:
                created_application = next(
                    (
                        item
                        for item in authentik_list(token, "core/applications/")
                        if item.get("slug") == application_slug
                    ),
                    None,
                )
                application_committed = isinstance(created_application, Mapping)
            except Exception as discovery_exc:  # noqa: BLE001
                rollback_errors.append(f"application discovery: {type(discovery_exc).__name__}")

        if not provider_existing and provider_create_attempted and not provider_committed:
            try:
                created_provider = next(
                    (item for item in authentik_list(token, "providers/proxy/") if item.get("name") == provider_name),
                    None,
                )
                if isinstance(created_provider, Mapping):
                    discovered_pk = created_provider.get("pk")
                    if discovered_pk is None:
                        rollback_errors.append("provider discovery: missing primary key")
                    else:
                        provider_pk = discovered_pk
                        provider_committed = True
            except Exception as discovery_exc:  # noqa: BLE001
                rollback_errors.append(f"provider discovery: {type(discovery_exc).__name__}")

        if outpost_restore_needed:
            rollback(
                "embedded outpost",
                lambda: authentik_request(
                    token,
                    f"outposts/instances/{outpost_pk}/",
                    method="PATCH",
                    body=rollback_outpost_payload,
                ),
            )
        if application_existing and application_restore_needed and application_restore is not None:
            rollback(
                "application",
                lambda: authentik_request(
                    token,
                    f"core/applications/{application_slug}/",
                    method="PATCH",
                    body=application_restore,
                ),
            )
        elif application_committed:
            rollback(
                "application",
                lambda: authentik_request(
                    token,
                    f"core/applications/{application_slug}/",
                    method="DELETE",
                ),
            )
        if provider_existing and provider_committed and provider_restore is not None:
            rollback(
                "provider",
                lambda: authentik_request(
                    token,
                    f"providers/proxy/{provider_pk}/",
                    method="PATCH",
                    body=provider_restore,
                ),
            )
        elif provider_committed and provider_pk is not None:
            rollback(
                "provider",
                lambda: authentik_request(
                    token,
                    f"providers/proxy/{provider_pk}/",
                    method="DELETE",
                ),
            )

        if rollback_errors:
            raise SyncError(
                f"Authentik {provider_name} reconciliation failed and rollback incomplete: "
                + "; ".join(rollback_errors)
            ) from exc
        raise


def _validate_public_host() -> None:
    if not re.fullmatch(r"[A-Za-z0-9.-]+(?::[0-9]{1,5})?", PUBLIC_HOST):
        raise SyncError("NAS_PUBLIC_HOST is missing or invalid")
    if ":" in PUBLIC_HOST:
        port = int(PUBLIC_HOST.rsplit(":", 1)[1])
        if not 1 <= port <= 65535:
            raise SyncError("NAS_PUBLIC_HOST is missing or invalid")


def ensure_portal_proxy(token: str) -> dict[str, Any]:
    _validate_public_host()
    return _ensure_proxy_application(
        token,
        provider_name="NAS Portal",
        application_slug="nas-portal",
        external_host=f"https://{PUBLIC_HOST}",
        internal_host="http://127.0.0.1:8080",
        outpost_config_patch={
            # Advertise the browser-reachable public origin while the
            # appliance resolves it internally back through Caddy.
            "authentik_host": f"https://{PUBLIC_HOST}/identity/",
            "authentik_host_browser": f"https://{PUBLIC_HOST}/identity/",
        },
    )


def ensure_cockpit_launcher(token: str) -> dict[str, Any]:
    """Expose Cockpit as an Authentik launcher application behind forward auth."""
    _validate_public_host()
    return _ensure_proxy_application(
        token,
        provider_name="NAS Cockpit",
        application_slug="nas-cockpit",
        external_host=f"https://{PUBLIC_HOST}/console/",
        internal_host="http://127.0.0.1:9092",
    )


def ensure_setup_launcher(token: str) -> dict[str, Any]:
    """Expose first-start setup as an atomic Authentik application update."""
    _validate_public_host()
    return _ensure_proxy_application(
        token,
        provider_name="NAS Setup",
        application_slug="nas-setup",
        external_host=f"https://{PUBLIC_HOST}/setup/",
        internal_host="http://127.0.0.1:8980",
        application_metadata={
            "meta_description": "First-start setup for the NAS appliance",
            "meta_publisher": "NAS",
            "open_in_new_tab": False,
        },
    )


AUTOMATION_ROLE = "NAS automation"
AUTOMATION_USER = "nas-automation"
AUTOMATION_TOKEN_IDENTIFIER = "nas-automation-api"
DEFAULT_AUTOMATION_ROLE_WAIT_SECONDS = 600.0


def provision_runtime_token(token: str) -> dict[str, Any]:
    users = authentik_list(token, f"core/users/?username={urllib.parse.quote(AUTOMATION_USER)}")
    user = next((item for item in users if item.get("username") == AUTOMATION_USER), None)
    created = False
    if not isinstance(user, Mapping):
        value = authentik_request(
            token,
            "core/users/service_account/",
            method="POST",
            body={"name": AUTOMATION_USER, "create_group": False, "expiring": False},
        )
        if not isinstance(value, Mapping):
            raise SyncError("Authentik did not return the created automation service account")
        user_pk = value.get("user_pk")
        created = True
    else:
        user_pk = user.get("pk")
    if not isinstance(user_pk, int):
        raise SyncError("Authentik automation service account has no numeric primary key")

    role: Mapping[str, Any] | None = None
    role_wait = max(
        float(
            os.environ.get(
                "NAS_AUTOMATION_ROLE_WAIT_SECONDS",
                str(DEFAULT_AUTOMATION_ROLE_WAIT_SECONDS),
            )
        ),
        0.0,
    )
    deadline = time.monotonic() + role_wait
    attempt = 0
    while role is None:
        attempt += 1
        roles = authentik_list(token, f"rbac/roles/?name={urllib.parse.quote(AUTOMATION_ROLE)}")
        candidate = next((item for item in roles if item.get("name") == AUTOMATION_ROLE), None)
        if isinstance(candidate, Mapping) and isinstance(candidate.get("pk"), str):
            role = candidate
            break
        if time.monotonic() >= deadline:
            break
        time.sleep(min(_retry_delay(attempt), max(deadline - time.monotonic(), 0.0)))
    if not isinstance(role, Mapping) or not isinstance(role.get("pk"), str):
        raise SyncError("Authentik NAS automation role is missing; verify blueprint deployment")
    authentik_request(token, f"rbac/roles/{role['pk']}/add_user/", method="POST", body={"pk": user_pk})

    tokens = authentik_list(token, f"core/tokens/?identifier={urllib.parse.quote(AUTOMATION_TOKEN_IDENTIFIER)}")
    if not any(item.get("identifier") == AUTOMATION_TOKEN_IDENTIFIER for item in tokens):
        authentik_request(
            token,
            "core/tokens/",
            method="POST",
            body={
                "identifier": AUTOMATION_TOKEN_IDENTIFIER,
                "intent": "api",
                "user": user_pk,
                "description": "NixOS NAS runtime identity reconciliation",
                "expiring": False,
            },
        )
    runtime_token = secrets.token_urlsafe(48)
    authentik_request(
        token,
        f"core/tokens/{AUTOMATION_TOKEN_IDENTIFIER}/set_key/",
        method="POST",
        body={"key": runtime_token},
    )
    return {
        "createdServiceAccount": created,
        "role": AUTOMATION_ROLE,
        "username": AUTOMATION_USER,
        "token": runtime_token,
    }


def verify_token(token: str) -> dict[str, Any]:
    users = authentik_list(token, "core/users/?page_size=1")
    groups = authentik_list(token, "core/groups/?page_size=100")
    names = {str(item.get("name")) for item in groups}
    return {
        "ok": True,
        "verifiedPermissions": ["authentik_core.view_user", "authentik_core.view_group"],
        "usersReadable": isinstance(users, list),
        "groupsReadable": True,
        "reservedGroupsPresent": sorted(name for name in RESERVED_GROUPS if name in names),
        "reservedGroupsMissing": sorted(name for name in RESERVED_GROUPS if name not in names),
    }


def load_model(token: str) -> IdentityModel:
    return build_model(
        {
            "users": authentik_list(token, "core/users/?include_groups=true"),
            "groups": authentik_list(token, "core/groups/?include_users=true"),
        }
    )


def fixture_model(path: pathlib.Path) -> IdentityModel:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SyncError("Fixture must contain an Authentik API object")
    return build_model(data)


def desired_syncthing(
    model: IdentityModel,
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    return desired_syncthing_model(model, SHARE_ROOT)


def syncthing_api_key() -> str:
    key_file = SYNCTHING_CONFIG_DIR / "apikey"
    if key_file.exists() and (value := key_file.read_text(encoding="utf-8").strip()):
        return value
    try:
        text = (SYNCTHING_CONFIG_DIR / "config.xml").read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise SyncError("Syncthing API key is unavailable") from exc
    match = re.search(r"<apikey>([^<]+)</apikey>", text)
    if not match:
        raise SyncError("Syncthing config does not contain an API key")
    return match.group(1)


def syncthing_request(path: str, *, method: str = "GET", body: Any | None = None) -> Any:
    return http_json(f"{SYNCTHING_URL}{path}", method=method, body=body, headers={"X-API-Key": syncthing_api_key()})


def load_state() -> dict[str, Any]:
    try:
        value = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"folders": [], "devices": []}
    except json.JSONDecodeError as exc:
        raise SyncError(f"Invalid identity sync state: {STATE_PATH}") from exc
    if not isinstance(value, dict):
        raise SyncError("Identity sync state must be a JSON object")
    return value


def atomic_write(path: pathlib.Path, content: str, *, mode: int = 0o600) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        current = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        current = None
    if current == content:
        return False

    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(name, mode)
        os.replace(name, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass
    return True


def atomic_write_json(path: pathlib.Path, value: Mapping[str, Any], *, mode: int = 0o600) -> bool:
    return atomic_write(path, json.dumps(dict(value), indent=2, sort_keys=True) + "\n", mode=mode)


def remove_file_durable(path: pathlib.Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        return
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def syncthing_generation(
    folders: Mapping[str, Mapping[str, Any]],
    devices: Mapping[str, Mapping[str, Any]],
) -> str:
    payload = json.dumps(
        {"folders": folders, "devices": devices},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def object_by_identifier(value: Any, identifier: str, *, label: str) -> dict[str, dict[str, Any]]:
    if not isinstance(value, list):
        raise SyncError(f"Syncthing {label} configuration did not return a list")
    output: dict[str, dict[str, Any]] = {}
    for item in value:
        if not isinstance(item, dict) or not isinstance(item.get(identifier), str):
            raise SyncError(f"Syncthing {label} configuration contains an invalid object")
        item_id = item[identifier]
        if item_id in output:
            raise SyncError(f"Syncthing {label} configuration contains duplicate identifier {item_id}")
        output[item_id] = item
    return output


def expected_subset(observed: Any, expected: Any) -> bool:
    if isinstance(expected, Mapping):
        return isinstance(observed, Mapping) and all(
            key in observed and expected_subset(observed[key], value) for key, value in expected.items()
        )
    if isinstance(expected, list):
        if not isinstance(observed, list):
            return False
        if all(isinstance(item, Mapping) and isinstance(item.get("deviceID"), str) for item in expected):
            expected_ids = {str(item["deviceID"]) for item in expected}
            observed_ids = {
                str(item["deviceID"])
                for item in observed
                if isinstance(item, Mapping) and isinstance(item.get("deviceID"), str)
            }
            return expected_ids.issubset(observed_ids)
        return observed == expected
    return observed == expected


def verify_syncthing_configuration(
    folders: Mapping[str, Mapping[str, Any]],
    devices: Mapping[str, Mapping[str, Any]],
    *,
    removed_folders: set[str],
    removed_devices: set[str],
) -> None:
    observed_folders = object_by_identifier(
        syncthing_request("/rest/config/folders"),
        "id",
        label="folder",
    )
    observed_devices = object_by_identifier(
        syncthing_request("/rest/config/devices"),
        "deviceID",
        label="device",
    )
    for folder_id, expected in folders.items():
        observed = observed_folders.get(folder_id)
        if observed is None or not expected_subset(observed, expected):
            raise SyncError(f"Syncthing folder {folder_id} did not converge to the desired configuration")
    for device_id, expected in devices.items():
        observed = observed_devices.get(device_id)
        if observed is None or not expected_subset(observed, expected):
            raise SyncError(f"Syncthing device {device_id} did not converge to the desired configuration")
    unexpected_folders = sorted(removed_folders & observed_folders.keys())
    unexpected_devices = sorted(removed_devices & observed_devices.keys())
    if unexpected_folders:
        raise SyncError("Syncthing retained removed managed folder(s): " + ", ".join(unexpected_folders))
    if unexpected_devices:
        raise SyncError("Syncthing retained removed managed device(s): " + ", ".join(unexpected_devices))


def ensure_syncthing_folder(path: pathlib.Path) -> None:
    try:
        relative = path.relative_to(SHARE_ROOT)
    except ValueError as exc:
        raise SyncError(f"Syncthing folder is outside the managed share root: {path}") from exc
    if len(relative.parts) != 3 or relative.parts[0] != "users" or relative.parts[2] != "syncthing":
        raise SyncError(f"Unexpected managed Syncthing folder path: {path}")
    try:
        username = validate_username(relative.parts[1])
    except DeviceError as exc:
        raise SyncError(f"Unsafe personal-share username in path: {path}") from exc

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptors: list[int] = []
    try:
        current_fd = os.open(SHARE_ROOT, flags)
        descriptors.append(current_fd)
        for component in ("users", username):
            try:
                current_fd = os.open(component, flags, dir_fd=current_fd)
            except (FileNotFoundError, NotADirectoryError, OSError) as exc:
                raise SyncError(
                    f"CopyParty personal-share directory does not exist or is unsafe for Syncthing: {path.parent}"
                ) from exc
            descriptors.append(current_fd)
        try:
            os.mkdir("syncthing", mode=0o2770, dir_fd=current_fd)
        except FileExistsError:
            pass
        leaf_fd = os.open("syncthing", flags, dir_fd=current_fd)
        descriptors.append(leaf_fd)
        owner = pwd.getpwnam("syncthing").pw_uid
        group = grp.getgrnam("copyparty").gr_gid
        os.fchown(leaf_fd, owner, group)
        os.fchmod(leaf_fd, 0o2770)
    except OSError as exc:
        raise SyncError(f"Unable to create safe Syncthing folder {path}: {exc}") from exc
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def reconcile_syncthing(model: IdentityModel) -> dict[str, int]:
    if not SYNCTHING_ENABLED:
        return {"folders": 0, "devices": 0, "removedFolders": 0, "removedDevices": 0}
    folders, devices = desired_syncthing(model)
    state = load_state()
    old_folders = {str(value) for value in state.get("folders", [])}
    old_devices = {str(value) for value in state.get("devices", [])}
    generation = syncthing_generation(folders, devices)
    journal: dict[str, Any] = {
        "schemaVersion": 1,
        "phase": "prepared",
        "generation": generation,
        "previousState": state,
        "desired": {"folders": folders, "devices": devices},
    }
    atomic_write_json(SYNCTHING_JOURNAL_PATH, journal)
    for device_id, device in devices.items():
        syncthing_request(f"/rest/config/devices/{urllib.parse.quote(device_id, safe='')}", method="PUT", body=device)
    for folder_id, folder in folders.items():
        ensure_syncthing_folder(pathlib.Path(folder["path"]))
        syncthing_request(f"/rest/config/folders/{urllib.parse.quote(folder_id, safe='')}", method="PUT", body=folder)
    removed_folders = old_folders - folders.keys()
    for folder_id in sorted(removed_folders):
        syncthing_request(f"/rest/config/folders/{urllib.parse.quote(folder_id, safe='')}", method="DELETE")
    removed_devices: set[str] = set()
    retained_devices: set[str] = set()
    for device_id in sorted(old_devices - devices.keys()):
        try:
            syncthing_request(f"/rest/config/devices/{urllib.parse.quote(device_id, safe='')}", method="DELETE")
            removed_devices.add(device_id)
        except SyncError as exc:
            message = str(exc)
            if "HTTP 409" not in message and "still referenced" not in message.lower():
                raise
            print(f"nas-identity-sync: retaining {device_id}: {message}", file=sys.stderr)
            retained_devices.add(device_id)
    journal["phase"] = "mutated"
    journal["retainedDevices"] = sorted(retained_devices)
    atomic_write_json(SYNCTHING_JOURNAL_PATH, journal)
    verify_syncthing_configuration(
        folders,
        devices,
        removed_folders=removed_folders,
        removed_devices=removed_devices,
    )
    restart = syncthing_request("/rest/config/restart-required")
    if isinstance(restart, dict) and restart.get("requiresRestart"):
        syncthing_request("/rest/system/restart", method="POST")
    committed_state = {
        "schemaVersion": 2,
        "generation": generation,
        "folders": sorted(folders),
        "devices": sorted(set(devices) | retained_devices),
    }
    atomic_write_json(STATE_PATH, committed_state)
    journal["phase"] = "committed"
    atomic_write_json(SYNCTHING_JOURNAL_PATH, journal)
    remove_file_durable(SYNCTHING_JOURNAL_PATH)
    return {
        "folders": len(folders),
        "devices": len(devices),
        "removedFolders": len(removed_folders),
        "removedDevices": len(removed_devices),
    }


def acquire_lock() -> Any:
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    handle = LOCK_PATH.open("a+")
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        handle.close()
        raise SyncError("Another identity reconciliation is already running") from exc
    return handle


def load_account_plan(source: str) -> dict[str, Any]:
    try:
        text = sys.stdin.read() if source == "-" else pathlib.Path(source).read_text(encoding="utf-8")
        value = json.loads(text)
    except (OSError, json.JSONDecodeError) as exc:
        raise SyncError(f"Unable to read account plan from {source}: {exc}") from exc
    if not isinstance(value, dict):
        raise SyncError("Account plan must contain one JSON object")
    unknown = sorted(
        str(key) for key in value if key not in {"schemaVersion", "accounts", "deactivateMissingManagedAccounts"}
    )
    if unknown:
        raise SyncError(f"Account plan contains unknown field(s): {', '.join(unknown)}")
    if value.get("schemaVersion", 1) != 1:
        raise SyncError("Unsupported account-plan schemaVersion")
    deactivate_missing = value.get("deactivateMissingManagedAccounts", False)
    if not isinstance(deactivate_missing, bool):
        raise SyncError("deactivateMissingManagedAccounts must be true or false")
    accounts = value.get("accounts", [])
    if not isinstance(accounts, list):
        raise SyncError("Account plan accounts must be a list")
    return value


def account_plan_fingerprint(plan: Mapping[str, Any]) -> str:
    sanitized = json.loads(json.dumps(plan))
    accounts = sanitized.get("accounts", [])
    if isinstance(accounts, list):
        for account in accounts:
            if isinstance(account, dict) and "password" in account:
                account["password"] = account["password"] is not None
    payload = json.dumps(sanitized, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def journal_step(journal: OperationJournal, step: str, action: Any) -> Any:
    if journal.step_complete(step):
        return journal.result(step)
    journal.start_step(step)
    try:
        result = action()
    except Exception as exc:
        journal.fail_step(step, str(exc))
        raise
    journal.complete_step(step, result)
    return result


def apply_account_plan(
    token: str,
    plan: Mapping[str, Any],
    *,
    confirm_password_reapply: bool = False,
) -> dict[str, Any]:
    unknown = sorted(
        str(key) for key in plan if key not in {"schemaVersion", "accounts", "deactivateMissingManagedAccounts"}
    )
    if unknown:
        raise SyncError(f"Account plan contains unknown field(s): {', '.join(unknown)}")
    deactivate_missing = plan.get("deactivateMissingManagedAccounts", False)
    if not isinstance(deactivate_missing, bool):
        raise SyncError("deactivateMissingManagedAccounts must be true or false")
    accounts_raw = plan.get("accounts", [])
    if not isinstance(accounts_raw, list):
        raise SyncError("Account plan accounts must be a list")
    accounts = [normalized_account_plan(item, index) for index, item in enumerate(accounts_raw)]
    usernames = [item["username"] for item in accounts]
    duplicates = sorted({name for name in usernames if usernames.count(name) > 1})
    if duplicates:
        raise SyncError(f"Duplicate account-plan usernames: {', '.join(duplicates)}")

    password_accounts = sorted(account["username"] for account in accounts if account["password"] is not None)
    try:
        existing_journal = load_json(ACCOUNT_JOURNAL_PATH)
    except JournalError as exc:
        raise SyncError(str(exc)) from exc
    is_resume = existing_journal is not None and existing_journal.get("status") not in {"complete", "cancelled"}
    if is_resume and password_accounts and not confirm_password_reapply:
        raise SyncError(
            "The incomplete account operation includes password changes for "
            + ", ".join(password_accounts)
            + "; repeat with --confirm-password-reapply after confirming the intended passwords"
        )

    try:
        journal = OperationJournal.open(
            ACCOUNT_JOURNAL_PATH,
            workflow="authentik-account-plan",
            fingerprint=account_plan_fingerprint(plan),
            metadata={"usernames": sorted(usernames), "deactivateMissing": deactivate_missing},
        )
    except JournalError as exc:
        raise SyncError(str(exc)) from exc

    try:
        journal_step(journal, "reserved-groups", lambda: (ensure_groups(token), {"ensured": True})[1])
        groups = authentik_list(token, "core/groups/?include_users=true")
        group_by_name = {
            str(item.get("name")): item
            for item in groups
            if isinstance(item.get("name"), str) and item.get("pk") is not None
        }
        missing = sorted(set(RESERVED_GROUPS) - set(group_by_name))
        if missing:
            raise SyncError(f"Reserved groups are missing after bootstrap: {', '.join(missing)}")
        group_name_by_pk = {str(item["pk"]): name for name, item in group_by_name.items()}

        users = authentik_list(token, "core/users/?include_groups=true")
        existing_by_name = {str(item.get("username")): item for item in users if isinstance(item.get("username"), str)}
        created: list[str] = []
        updated: list[str] = []
        password_changed: list[str] = []
        desired_names = set(usernames)

        current_administrators = enabled_administrator_names(users, groups)
        resulting_administrators = set(current_administrators)
        for account in accounts:
            if account["active"] and ADMIN_GROUP in account["groups"]:
                resulting_administrators.add(account["username"])
            else:
                resulting_administrators.discard(account["username"])
        if deactivate_missing:
            for username, current in existing_by_name.items():
                if username in desired_names or username == "akadmin":
                    continue
                attrs = current.get("attributes")
                if isinstance(attrs, Mapping) and attrs.get("nasManagedBySetup") is True:
                    resulting_administrators.discard(username)
        if not resulting_administrators:
            raise SyncError(
                f"Account plan would leave no enabled members of {ADMIN_GROUP}; add or retain at least one administrator"
            )

        def write_priority(account: Mapping[str, Any]) -> int:
            desired_administrator = account["active"] and ADMIN_GROUP in account["groups"]
            if desired_administrator:
                return 0
            if account["username"] in current_administrators:
                return 2
            return 1

        ordered_accounts = sorted(enumerate(accounts), key=lambda pair: (write_priority(pair[1]), pair[0]))
        for _, account in ordered_accounts:
            username = account["username"]
            current = existing_by_name.get(username)
            current_attrs = current.get("attributes", {}) if isinstance(current, Mapping) else {}
            merged_attrs = dict(current_attrs) if isinstance(current_attrs, Mapping) else {}
            merged_attrs.update(account["attributes"])
            merged_attrs["nasManagedBySetup"] = True

            current_group_pks = raw_group_pks(current) if isinstance(current, Mapping) else set()
            # Application capability assignments are Authentik-owned and are not
            # members of RESERVED_GROUPS, so account setup preserves them.
            non_reserved_pks = {key for key in current_group_pks if group_name_by_pk.get(key) not in RESERVED_GROUPS}
            desired_group_pks = non_reserved_pks | {str(group_by_name[name]["pk"]) for name in account["groups"]}
            body = {
                "name": account["name"],
                "email": account["email"],
                "is_active": account["active"],
                "groups": sorted(desired_group_pks),
                "attributes": merged_attrs,
            }
            core_step = f"account:{username}"
            if not journal.step_complete(core_step):
                journal.start_step(core_step)
                try:
                    if current is None:
                        created_user = authentik_request(
                            token,
                            "core/users/",
                            method="POST",
                            body={"username": username, "path": "users", "type": "internal", **body},
                        )
                        if not isinstance(created_user, Mapping):
                            raise SyncError(f"Authentik did not return the created user {username}")
                        current = dict(created_user)
                        existing_by_name[username] = dict(created_user)
                        created.append(username)
                        action = "created"
                    else:
                        pk = user_detail_pk(current)
                        authentik_request(token, f"core/users/{pk}/", method="PATCH", body=body)
                        updated.append(username)
                        action = "updated"
                except Exception as exc:
                    journal.fail_step(core_step, str(exc))
                    raise
                journal.complete_step(core_step, {"username": username, "action": action})
            else:
                prior = journal.result(core_step)
                if isinstance(prior, Mapping) and prior.get("action") == "created":
                    created.append(username)
                else:
                    updated.append(username)
                current = existing_by_name.get(username)
                if current is None:
                    raise SyncError(f"Completed journal step has no current Authentik user: {username}")

            if account["password"] is not None:
                password_step = f"password:{username}"
                journal.start_step(password_step)
                try:
                    pk = user_detail_pk(current)
                    authentik_request(
                        token,
                        f"core/users/{pk}/set_password/",
                        method="POST",
                        body={"password": account["password"]},
                    )
                except Exception as exc:
                    journal.fail_step(password_step, str(exc))
                    raise
                journal.complete_step(password_step, {"username": username, "changed": True})
                password_changed.append(username)

        deactivated: list[str] = []
        if deactivate_missing:
            for username, current in existing_by_name.items():
                if username in desired_names or username == "akadmin":
                    continue
                attrs = current.get("attributes")
                if not isinstance(attrs, Mapping) or attrs.get("nasManagedBySetup") is not True:
                    continue
                step = f"deactivate:{username}"
                if not journal.step_complete(step):
                    current_pks = raw_group_pks(current)
                    kept = {key for key in current_pks if group_name_by_pk.get(key) not in RESERVED_GROUPS}
                    kept.add(str(group_by_name[DISABLED_GROUP]["pk"]))
                    journal.start_step(step)
                    try:
                        authentik_request(
                            token,
                            f"core/users/{user_detail_pk(current)}/",
                            method="PATCH",
                            body={"is_active": False, "groups": sorted(kept)},
                        )
                    except Exception as exc:
                        journal.fail_step(step, str(exc))
                        raise
                    journal.complete_step(step, {"username": username, "deactivated": True})
                deactivated.append(username)

        result = {
            "created": sorted(created),
            "updated": sorted(updated),
            "passwordsChanged": sorted(password_changed),
            "deactivated": sorted(deactivated),
            "administrators": sorted(resulting_administrators),
            "managed": sorted(desired_names),
            "journal": str(ACCOUNT_JOURNAL_PATH),
            "note": "Passwords were accepted only in the transient account plan and are not returned.",
        }
        journal.complete(result)
        return result
    except JournalError as exc:
        raise SyncError(str(exc)) from exc
    except (SyncError, OSError, ValueError) as exc:
        if journal.value.get("status") != "manual-recovery-required":
            journal.fail(str(exc))
        raise


def preview_account_plan(token: str, plan: Mapping[str, Any]) -> dict[str, Any]:
    accounts_raw = plan.get("accounts", [])
    if not isinstance(accounts_raw, list):
        raise SyncError("Account plan accounts must be a list")
    accounts = [normalized_account_plan(item, index) for index, item in enumerate(accounts_raw)]
    users = authentik_list(token, "core/users/?include_groups=true")
    existing = {str(item.get("username")): item for item in users if isinstance(item.get("username"), str)}
    desired = {account["username"] for account in accounts}
    deactivate_missing = plan.get("deactivateMissingManagedAccounts", False) is True
    return {
        "schemaVersion": 1,
        "create": sorted(account["username"] for account in accounts if account["username"] not in existing),
        "update": sorted(account["username"] for account in accounts if account["username"] in existing),
        "passwordChange": sorted(account["username"] for account in accounts if account["password"] is not None),
        "deactivate": sorted(
            username
            for username, current in existing.items()
            if deactivate_missing
            and username not in desired
            and username != "akadmin"
            and isinstance(current.get("attributes"), Mapping)
            and current["attributes"].get("nasManagedBySetup") is True
        ),
        "applied": False,
    }


def export_account(token: str, username: str) -> dict[str, Any]:
    username = validate_uid(username)
    users = authentik_list(token, "core/users/?include_groups=true")
    groups = authentik_list(token, "core/groups/")
    group_name_by_pk = {
        str(item.get("pk")): str(item.get("name"))
        for item in groups
        if item.get("pk") is not None and isinstance(item.get("name"), str)
    }
    raw = next((item for item in users if item.get("username") == username), None)
    if not isinstance(raw, Mapping):
        raise SyncError(f"Authentik account does not exist: {username}")
    names = sorted(name for key in raw_group_pks(raw) if (name := group_name_by_pk.get(key)) in RESERVED_GROUPS)
    attrs = raw.get("attributes", {})
    return {
        "username": username,
        "name": str(raw.get("name") or username),
        "email": str(raw.get("email") or f"{username}@invalid.local"),
        "active": raw.get("is_active") is True,
        "groups": names,
        "attributes": dict(attrs) if isinstance(attrs, Mapping) else {},
    }


def retire_bootstrap_administrator(token: str, administrator: str) -> dict[str, str]:
    administrator = validate_uid(administrator)
    users = authentik_list(token, "core/users/?include_groups=true")
    groups = authentik_list(token, "core/groups/?include_users=true")
    admin_group = next((group for group in groups if group.get("name") == ADMIN_GROUP), None)
    if not isinstance(admin_group, Mapping):
        raise SyncError(f"Authentik group {ADMIN_GROUP} is missing")
    replacement = next((user for user in users if user.get("username") == administrator), None)
    replacement_pk = replacement.get("pk") if isinstance(replacement, Mapping) else None
    members = admin_group.get("users_obj", admin_group.get("users", []))
    member_pks = (
        {member.get("pk", member.get("num_pk")) if isinstance(member, Mapping) else member for member in members}
        if isinstance(members, list)
        else set()
    )
    if (
        not isinstance(replacement, Mapping)
        or replacement.get("is_active") is not True
        or replacement_pk not in member_pks
    ):
        raise SyncError(f"Chosen administrator {administrator!r} is not an enabled explicit member of {ADMIN_GROUP}")
    bootstrap = next((user for user in users if user.get("username") == "akadmin"), None)
    if isinstance(bootstrap, Mapping):
        bootstrap_pk = user_detail_pk(bootstrap)
        authentik_request(token, f"core/users/{bootstrap_pk}/", method="DELETE")
    return {"retiredBootstrapAdministrator": "akadmin", "verifiedAdministrator": administrator}


@contextlib.contextmanager
def identity_mutation_operation(action: str):
    token = os.environ.get(COORDINATION_TOKEN_ENV)
    if token:
        try:
            validate_coordination_token(token, ("identity", "runtime"))
        except OperationBusyError as exc:
            raise SyncError(str(exc)) from exc
        yield
        return
    try:
        with acquire_operation(action, ("identity", "runtime"), blocking=False):
            yield
    except OperationBusyError as exc:
        raise SyncError(str(exc)) from exc


READ_ONLY_COMMANDS = frozenset(
    {
        "capabilities",
        "export-account",
        "plan-accounts",
        "status",
        "status-fixture",
        "verify-token",
    }
)


@contextlib.contextmanager
def identity_command_lock(command: str):
    if command in READ_ONLY_COMMANDS:
        yield
        return
    with acquire_lock():
        yield


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("bootstrap", help="Create/correct base NAS identity roles using the bootstrap token")
    sub.add_parser("verify-token", help="Verify the scoped runtime token can read identity state")
    sub.add_parser("bootstrap-runtime-token", help="Issue the scoped runtime token using bootstrap authority")
    retire = sub.add_parser(
        "retire-bootstrap", help="Delete Authentik bootstrap administrator after replacement verification"
    )
    retire.add_argument("administrator")
    sub.add_parser("sync", help="Validate Authentik identity state and reconcile Syncthing when enabled")
    fixture = sub.add_parser("status-fixture", help="Report identity state from fixture JSON without touching services")
    fixture.add_argument("fixture", type=pathlib.Path)
    sub.add_parser("sync-syncthing", help="Reconcile only Authentik-owned Syncthing objects")
    sub.add_parser("status", help="Report the current Authentik identity model")
    sub.add_parser("capabilities", help="Report Authentik-owned Managed Services V2 application assignments")
    apply_parser = sub.add_parser("apply-accounts", help="Create/update Authentik accounts from a transient JSON plan")
    apply_parser.add_argument("source", help="JSON file or - for stdin")
    apply_parser.add_argument(
        "--confirm-password-reapply",
        action="store_true",
        help="Explicitly permit password mutations to be repeated while resuming an incomplete journal",
    )
    preview_parser = sub.add_parser("plan-accounts", help="Show a password-free account diff without applying it")
    preview_parser.add_argument("source", help="JSON file or - for stdin")
    export_parser = sub.add_parser("export-account", help="Export one account as a password-free setup object")
    export_parser.add_argument("username")
    args = parser.parse_args()

    try:
        mutating = {
            "bootstrap",
            "bootstrap-runtime-token",
            "retire-bootstrap",
            "apply-accounts",
            "sync",
            "sync-syncthing",
        }
        operation = (
            identity_mutation_operation(f"identity-{args.command}")
            if args.command in mutating
            else contextlib.nullcontext()
        )
        with operation, identity_command_lock(args.command):
            if args.command == "bootstrap":
                token = authentik_token(bootstrap=True)
                result = bootstrap_identity(token)
            elif args.command == "bootstrap-runtime-token":
                result = provision_runtime_token(authentik_token(bootstrap=True))
            elif args.command == "retire-bootstrap":
                result = retire_bootstrap_administrator(authentik_token(bootstrap=True), args.administrator)
            elif args.command == "apply-accounts":
                result = apply_account_plan(
                    authentik_token(),
                    load_account_plan(args.source),
                    confirm_password_reapply=args.confirm_password_reapply,
                )
            elif args.command == "plan-accounts":
                result = preview_account_plan(authentik_token(), load_account_plan(args.source))
            elif args.command == "export-account":
                result = export_account(authentik_token(), args.username)
            elif args.command == "verify-token":
                result = verify_token(authentik_token())
            else:
                model = (
                    fixture_model(args.fixture) if args.command == "status-fixture" else load_model(authentik_token())
                )
                if args.command in {"sync", "sync-syncthing"}:
                    result = reconcile_syncthing(model)
                elif args.command == "capabilities":
                    result = capability_status(model)
                else:
                    result = model_status(model)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (SyncError, DeviceError, OSError, ValueError) as exc:
        print(f"nas-identity-sync: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
