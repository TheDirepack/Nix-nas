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
import os
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


def _list_objects(*, url: str, token: str, label: str) -> list[dict[str, Any]]:
    """Read every page from one Authentik v3 list endpoint."""
    objects: list[dict[str, Any]] = []
    seen_urls: set[str] = set()
    while url:
        if url in seen_urls:
            raise AuthentikProjectionError(f"Authentik {label} pagination loop detected")
        seen_urls.add(url)
        value = _request_json(url=url, token=token)
        if not isinstance(value, dict) or not isinstance(value.get("results"), list):
            raise AuthentikProjectionError(f"Authentik {label} listing did not return a result list")
        objects.extend(item for item in value["results"] if isinstance(item, dict))
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
    return objects


def _list_groups(*, api_root: str, token: str) -> list[dict[str, Any]]:
    return _list_objects(
        url=f"{api_root}/core/groups/?include_users=false&page_size=100",
        token=token,
        label="group",
    )


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


def desired_route_apps(effective: dict[str, Any], *, public_host: str) -> list[dict[str, Any]]:
    """Collect Authentik applications that make V2 web apps visible in the launcher.

    The Authentik user library is the appliance home page. Every portal-visible
    identity-gated route becomes an application tile there:

    - hostname-exposed routes get a forward_single proxy provider so the
      outpost can authorize and redirect for their dedicated host;
    - path-exposed routes get a provider-less application whose launch URL is
      the public path — Caddy's forward_auth (NAS Portal provider plus the
      capability check) already enforces authentication on those paths.
    """
    apps: list[dict[str, Any]] = []
    seen: set[str] = set()
    derived = effective.get("derived") or {}
    routes = derived.get("routes") if isinstance(derived, dict) else None
    if not isinstance(routes, list):
        return apps
    for entry in sorted(routes, key=lambda r: (str(r.get("service")), str(r.get("route")))):
        if not isinstance(entry, dict):
            continue
        service_id = entry.get("service")
        route_id = entry.get("route")
        if not service_id or not route_id:
            continue
        slug = f"v2-{service_id}-{route_id}"
        if slug in seen:
            continue
        if entry.get("authMode") != "identity":
            continue
        portal = entry.get("portal") or {}
        if not isinstance(portal, dict) or portal.get("visible") is not True:
            continue
        exposure = entry.get("exposure") or {}
        exposure_type = exposure.get("type")
        title = portal.get("title")
        name = title if isinstance(title, str) and title else f"NAS {service_id} ({route_id})"
        if exposure_type == "hostname":
            target = entry.get("target") or {}
            host = target.get("host", "127.0.0.1")
            port = target.get("port")
            internal = f"http://{host}:{port}" if isinstance(port, int) else None
            if internal is None:
                continue
            for hostname in exposure.get("hostnames") or []:
                key = f"{slug}/{hostname}"
                if key in seen:
                    continue
                seen.add(key)
                apps.append(
                    {
                        "slug": slug,
                        "name": name,
                        "hostname": str(hostname),
                        "internalHost": internal,
                        "launchUrl": f"https://{hostname}/",
                        "providerless": False,
                    }
                )
        elif exposure_type == "path":
            paths = exposure.get("paths") or []
            first = next((pth for pth in paths if isinstance(pth, str) and pth.startswith("/")), None)
            if first is None:
                continue
            launch_path = first if first.endswith("/") else first + "/"
            seen.add(slug)
            apps.append(
                {
                    "slug": slug,
                    "name": name,
                    "hostname": "",
                    "internalHost": "",
                    "launchUrl": f"https://{public_host}{launch_path}",
                    "providerless": True,
                }
            )
    return apps


def reconcile_route_apps(
    effective: dict[str, Any],
    *,
    token: str,
    authentik_url: str,
    public_host: str,
    public_authentik_path: str = "/identity/",
) -> dict[str, Any]:
    """Ensure launcher applications exist for every portal-visible V2 route."""
    api_root = _api_root(authentik_url)
    desired_apps = desired_route_apps(effective, public_host=public_host)

    providers = _list_objects(
        url=f"{api_root}/providers/proxy/?page_size=100", token=token, label="proxy provider"
    )
    provider_by_name = {p.get("name"): p for p in providers if isinstance(p.get("name"), str)}
    applications = _list_objects(
        url=f"{api_root}/core/applications/?page_size=100", token=token, label="application"
    )
    app_by_slug = {a.get("slug"): a for a in applications if isinstance(a.get("slug"), str)}

    outposts = _list_objects(
        url=f"{api_root}/outposts/instances/?page_size=100", token=token, label="outpost"
    )
    outpost = next(
        (o for o in outposts if o.get("managed") == "goauthentik.io/outposts/embedded"), None
    )
    outpost_pk = outpost.get("pk") if isinstance(outpost, dict) else None

    flows = _list_objects(url=f"{api_root}/flows/instances/?page_size=100", token=token, label="flow")
    flow_by_slug = {f.get("slug"): f.get("pk") for f in flows if isinstance(f.get("slug"), str)}

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
        application_payload = {
            "name": name,
            "slug": app["slug"],
            "meta_launch_url": app["launchUrl"],
        }
        if app.get("providerless"):
            application_payload["provider"] = None
            existing_app = app_by_slug.get(app["slug"])
            if existing_app is None:
                _request_json(
                    url=f"{api_root}/core/applications/", token=token, method="POST", body=application_payload
                )
            else:
                _request_json(
                    url=f"{api_root}/core/applications/{app['slug']}/",
                    token=token,
                    method="PATCH",
                    body=application_payload,
                )
            if existing_app is None:
                created.append(app["slug"])
            else:
                updated.append(app["slug"])
            continue
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

        application_payload.update({"provider": provider_pk})
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
    parser.add_argument(
        "--public-host",
        default=os.environ.get("NAS_V2_AUTHENTIK_PUBLIC_HOST", ""),
        help="Public appliance host[:port] used for launcher URLs of path routes",
    )
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
            public_host=args.public_host,
        )
    except AuthentikProjectionError as exc:
        print(f"nas-v2-authentik: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
