#!/usr/bin/env python3
"""Ensure Managed Services V2 capability objects exist in Authentik.

V2 owns capability *objects* only. Authentik remains the sole authority for
which users or groups are assigned to those capabilities. This reconciler
therefore creates missing inert groups and never mutates membership, roles,
parentage, or user/group assignments.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


class AuthentikProjectionError(RuntimeError):
    """Raised when Authentik capability objects cannot be reconciled safely."""


CAPABILITY_RE = re.compile(r"^application\.[a-z][a-z0-9-]{0,63}\.[a-z][a-z0-9.-]{0,127}$")
MAX_TOKEN_BYTES = 4096


def _read_json_object(path: pathlib.Path, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AuthentikProjectionError(f"unable to read {label} {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise AuthentikProjectionError(f"{label} must contain a JSON object")
    return value


def _read_token(path: pathlib.Path) -> str:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise AuthentikProjectionError(f"unable to read Authentik API token file {path}: {exc}") from exc
    if not raw or len(raw) > MAX_TOKEN_BYTES:
        raise AuthentikProjectionError("Authentik API token is empty or malformed")
    try:
        token = raw.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise AuthentikProjectionError("Authentik API token is not UTF-8") from exc
    if not token or any(character.isspace() for character in token):
        raise AuthentikProjectionError("Authentik API token is empty or malformed")
    return token


def _api_root(authentik_url: str) -> str:
    parsed = urllib.parse.urlsplit(authentik_url.rstrip("/"))
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise AuthentikProjectionError("Authentik URL must use http or https and include a host")
    if parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
        raise AuthentikProjectionError("Authentik URL must not contain credentials, query parameters, or fragments")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/") + "/api/v3", "", ""))


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, hdrs, newurl):  # noqa: ARG002
        raise urllib.error.HTTPError(newurl, code, f"redirect blocked to {newurl!r} to avoid token leak", hdrs, fp)


def _request_json(
    *,
    url: str,
    token: str,
    method: str = "GET",
    body: dict[str, Any] | None = None,
    timeout: float = 15.0,
) -> Any:
    data = None if body is None else json.dumps(body, sort_keys=True).encode("utf-8")
    headers = {"Accept": "application/json", "Authorization": f"Bearer {token}"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    opener = urllib.request.build_opener(_NoRedirectHandler())
    try:
        with opener.open(request, timeout=timeout) as response:
            payload = response.read()
    except urllib.error.HTTPError as exc:
        # Never include a response body here: an upstream error may echo secrets or
        # other Authentik object data into the journal.
        raise AuthentikProjectionError(f"Authentik API returned HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise AuthentikProjectionError(f"unable to reach Authentik: {type(exc.reason).__name__}") from exc
    if not payload:
        return None
    try:
        return json.loads(payload)
    except json.JSONDecodeError as exc:
        raise AuthentikProjectionError("Authentik API returned invalid JSON") from exc


def _list_groups(*, api_root: str, token: str) -> list[dict[str, Any]]:
    url = f"{api_root}/core/groups/?include_users=false&page_size=100"
    groups: list[dict[str, Any]] = []
    seen_urls: set[str] = set()
    while url:
        if url in seen_urls:
            raise AuthentikProjectionError("Authentik group pagination loop detected")
        seen_urls.add(url)
        value = _request_json(url=url, token=token)
        if not isinstance(value, dict) or not isinstance(value.get("results"), list):
            raise AuthentikProjectionError("Authentik group listing did not return a result list")
        groups.extend(item for item in value["results"] if isinstance(item, dict))
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
    return groups


def desired_capabilities(effective: dict[str, Any]) -> dict[str, str]:
    if effective.get("schemaVersion") != 3:
        raise AuthentikProjectionError("compiled effective state must use schema version 3")
    derived = effective.get("derived")
    authorization = derived.get("authorization") if isinstance(derived, dict) else None
    if not isinstance(authorization, dict):
        raise AuthentikProjectionError("compiled effective state is missing authorization metadata")

    capabilities: dict[str, str] = {}
    for service_id in sorted(authorization):
        service_auth = authorization[service_id]
        mapping = service_auth.get("capabilities") if isinstance(service_auth, dict) else None
        if not isinstance(mapping, dict):
            raise AuthentikProjectionError(f"authorization metadata for {service_id!r} is invalid")
        for capability_id, canonical_name in mapping.items():
            if not isinstance(capability_id, str) or not isinstance(canonical_name, str):
                raise AuthentikProjectionError(f"authorization metadata for {service_id!r} is invalid")
            if not CAPABILITY_RE.fullmatch(canonical_name):
                raise AuthentikProjectionError(f"canonical capability name is unsafe: {canonical_name!r}")
            previous = capabilities.setdefault(canonical_name, service_id)
            if previous != service_id:
                raise AuthentikProjectionError(
                    f"canonical capability {canonical_name!r} is shared by multiple services"
                )
    return capabilities


def reconcile_capabilities(
    effective: dict[str, Any],
    *,
    token: str,
    authentik_url: str,
) -> dict[str, Any]:
    """Create missing capability groups without changing assignments."""
    api_root = _api_root(authentik_url)
    desired = desired_capabilities(effective)
    existing_by_name: dict[str, dict[str, Any]] = {}
    for group in _list_groups(api_root=api_root, token=token):
        name = group.get("name")
        if not isinstance(name, str):
            continue
        if name in existing_by_name:
            raise AuthentikProjectionError(f"Authentik contains duplicate group name {name!r}")
        existing_by_name[name] = group

    created: list[str] = []
    preexisting: list[str] = []
    for capability_name, service_id in sorted(desired.items()):
        current = existing_by_name.get(capability_name)
        if current is not None:
            if current.get("is_superuser") is True:
                raise AuthentikProjectionError(
                    f"capability group {capability_name!r} is a superuser group; refusing to use it"
                )
            preexisting.append(capability_name)
            continue

        body = {
            "name": capability_name,
            "is_superuser": False,
            "attributes": {
                "nasManagedCapability": True,
                "nasManagedService": service_id,
            },
        }
        value = _request_json(
            url=f"{api_root}/core/groups/",
            token=token,
            method="POST",
            body=body,
        )
        if not isinstance(value, dict) or value.get("name") != capability_name:
            raise AuthentikProjectionError(
                f"Authentik did not confirm creation of capability group {capability_name!r}"
            )
        created.append(capability_name)

    return {
        "schemaVersion": 1,
        "desired": sorted(desired),
        "created": created,
        "preexisting": preexisting,
        "assignmentsChanged": False,
    }


def desired_route_apps(effective: dict[str, Any]) -> list[dict[str, Any]]:
    """Collect Authentik proxy applications for identity-gated hostname routes.

    Every V2 route exposed on its own hostname (sub- or sub-sub-domain) shares
    the same Caddy forward-auth boundary; this projection only ensures each
    such host has a matching Authentik application so the outpost can authorize
    and redirect for it.
    """
    apps: list[dict[str, Any]] = []
    seen: set[str] = set()
    services = effective.get("services")
    if not isinstance(services, dict):
        return apps
    for service_id, service in sorted(services.items()):
        if not isinstance(service, dict):
            continue
        routes = service.get("routes")
        if not isinstance(routes, dict):
            continue
        runtime = service.get("runtime") or {}
        unit = runtime.get("unit") if isinstance(runtime, dict) else None
        for route_id, route in sorted(routes.items()):
            if not isinstance(route, dict) or route.get("enabled") is False:
                continue
            authz = route.get("auth") or {}
            if authz.get("mode") != "identity":
                continue
            exposure = route.get("exposure") or {}
            if exposure.get("type") != "hostname":
                continue
            target = route.get("target") or {}
            host = target.get("host", "127.0.0.1")
            port = target.get("port")
            internal = f"http://{host}:{port}" if isinstance(port, int) else None
            for hostname in exposure.get("hostnames") or []:
                key = f"{service_id}/{route_id}/{hostname}"
                if key in seen or not isinstance(internal, str):
                    continue
                seen.add(key)
                apps.append(
                    {
                        "slug": f"v2-{service_id}-{route_id}",
                        "name": f"NAS {service_id} ({route_id})",
                        "hostname": hostname,
                        "internalHost": internal,
                        "launchUrl": f"https://{hostname}/",
                        "unit": unit if isinstance(unit, str) else "",
                    }
                )
    return apps


def reconcile_route_apps(
    effective: dict[str, Any],
    *,
    token: str,
    authentik_url: str,
    public_authentik_path: str = "/identity/",
) -> dict[str, Any]:
    """Ensure one forward_single proxy provider + application per hostname route."""
    api_root = _api_root(authentik_url)
    desired_apps = desired_route_apps(effective)

    providers = _request_json(url=f"{api_root}/providers/proxy/?page_size=100", token=token, method="GET")
    provider_by_name = {p.get("name"): p for p in providers if isinstance(p, dict)}
    applications = _request_json(url=f"{api_root}/core/applications/?page_size=100", token=token, method="GET")
    app_by_slug = {a.get("slug"): a for a in applications if isinstance(a, dict)}

    outposts = _request_json(url=f"{api_root}/outposts/instances/?page_size=100", token=token, method="GET")
    outpost = next(
        (o for o in outposts if isinstance(o, dict) and o.get("managed") == "goauthentik.io/outposts/embedded"), None
    )
    outpost_pk = outpost.get("pk") if isinstance(outpost, dict) else None

    flows = _request_json(url=f"{api_root}/flows/instances/?page_size=100", token=token, method="GET")
    flow_by_slug = {f.get("slug"): f.get("pk") for f in flows if isinstance(f, dict)}

    def _flow(slug: str) -> int:
        pk = flow_by_slug.get(slug)
        if pk is None:
            raise AuthentikProjectionError(f"Authentik flow {slug!r} is missing")
        return pk

    created: list[str] = []
    updated: list[str] = []
    for app in desired_apps:
        name = app["name"]
        external_host = f"https://{app['hostname']}"
        provider_body = {
            "name": name,
            "mode": "forward_single",
            "external_host": external_host,
            "internal_host": app["internalHost"],
            "internal_host_ssl_validation": False,
            "authentication_flow": _flow("default-authentication-flow"),
            "authorization_flow": _flow("default-provider-authorization-implicit-consent"),
            "invalidation_flow": _flow("default-invalidation-flow"),
        }
        existing_provider = provider_by_name.get(name)
        if existing_provider is None:
            provider = _request_json(url=f"{api_root}/providers/proxy/", token=token, method="POST", body=provider_body)
            created.append(app["slug"])
        else:
            provider = _request_json(
                url=f"{api_root}/providers/proxy/{existing_provider['pk']}/",
                token=token,
                method="PATCH",
                body=provider_body,
            )
            updated.append(app["slug"])
        provider_pk = provider.get("pk") if isinstance(provider, dict) else None
        if provider_pk is None:
            raise AuthentikProjectionError(f"provider for {name!r} has no primary key")

        application_payload = {
            "name": name,
            "slug": app["slug"],
            "provider": provider_pk,
            "meta_launch_url": app["launchUrl"],
        }
        existing_app = app_by_slug.get(app["slug"])
        if existing_app is None:
            _request_json(url=f"{api_root}/core/applications/", token=token, method="POST", body=application_payload)
        else:
            _request_json(
                url=f"{api_root}/core/applications/{app['slug']}/",
                token=token,
                method="PATCH",
                body=application_payload,
            )

        if not isinstance(outpost, dict) or outpost_pk is None:
            continue
        assigned = [p for p in (outpost.get("providers") or []) if isinstance(p, int)]
        raw_config = outpost.get("config")
        config = dict(raw_config) if isinstance(raw_config, dict) else {}
        config.update(
            {
                "authentik_host": f"https://{_public_host_from_launch(app['launchUrl'])}{public_authentik_path}",
                "authentik_host_browser": f"https://{_public_host_from_launch(app['launchUrl'])}{public_authentik_path}",
            }
        )
        if provider_pk not in assigned:
            assigned.append(provider_pk)
        _request_json(
            url=f"{api_root}/outposts/instances/{outpost_pk}/",
            token=token,
            method="PATCH",
            body={"providers": assigned, "config": config},
        )

    return {"schemaVersion": 1, "desired": [a["slug"] for a in desired_apps], "created": created, "updated": updated}


def _public_host_from_launch(launch_url: str) -> str:
    parsed = urllib.parse.urlsplit(launch_url)
    return parsed.netloc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Ensure Managed Services V2 capability groups in Authentik")
    parser.add_argument("--effective", type=pathlib.Path, default=pathlib.Path("/run/nas-control/effective.json"))
    parser.add_argument(
        "--token-file",
        type=pathlib.Path,
        default=pathlib.Path("/run/nas-secrets/authentik/api-token"),
    )
    parser.add_argument("--authentik-url", default="http://127.0.0.1:9000/identity")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        effective_state = _read_json_object(args.effective, label="compiled effective state")
        result = reconcile_capabilities(
            effective_state,
            token=_read_token(args.token_file),
            authentik_url=args.authentik_url,
        )
        result["routeApps"] = reconcile_route_apps(
            effective_state,
            token=_read_token(args.token_file),
            authentik_url=args.authentik_url,
        )
    except AuthentikProjectionError as exc:
        print(f"nas-v2-authentik: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
