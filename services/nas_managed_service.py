#!/usr/bin/env python3
"""File-based managed-service store for the unified Applications layer.

No SQLite, no new daemon — just an atomic JSON file at /var/lib/nas-control/services.json
plus a validated effective projection at /run/nas-control/effective-endpoints.json.
Accept-list only: service IDs, host paths, images, hostnames, ports, Authentik IDs.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import tempfile
from typing import Any

try:
    import jsonschema  # type: ignore[import-untyped]

    _HAS_JSONSCHEMA = True
except ImportError:
    jsonschema = None  # type: ignore[assignment]
    _HAS_JSONSCHEMA = False

STORE_PATH = pathlib.Path(os.environ.get("NAS_MANAGED_SERVICE_STORE", "/var/lib/nas-control/services.json"))
EFFECTIVE_PATH = pathlib.Path(os.environ.get("NAS_EFFECTIVE_REGISTRY", "/run/nas-control/effective-endpoints.json"))
PORTAL_PATH = pathlib.Path(os.environ.get("NAS_PORTAL_JSON", "/run/nas-control/portal.json"))
BUILTIN_REGISTRY = pathlib.Path(os.environ.get("NAS_BUILTIN_REGISTRY", "/etc/nas-control/endpoints.json"))
SCHEMA_PATH = pathlib.Path(
    os.environ.get(
        "NAS_MANAGED_SERVICE_SCHEMA",
        str(pathlib.Path(__file__).resolve().parents[1] / "schemas/managed-service.schema.json"),
    )
)

SCHEMA_VERSION = 2
ALLOWED_HOST_ROOTS = ("/tank", "/srv", "/var/lib/nas-control/apps")
APPS_ROOT = pathlib.Path("/var/lib/nas-control/apps")
SERVICE_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,47}$")
ENDPOINT_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,47}$")
IMAGE_RE = re.compile(
    r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*(?::[a-z0-9_.-]+)?(?:@[a-z0-9:]+)?$", re.IGNORECASE
)
HOSTNAME_RE = re.compile(r"^(?:[a-z0-9-]{1,63}\.)*[a-z0-9-]{1,63}$", re.IGNORECASE)
AUTH_MODE_VALUES = frozenset({"public", "forward-auth", "oidc"})
AUTH_ALLOW_VALUES = frozenset({"any", "groups", "users", "all"})
EXPOSURE_TYPE_VALUES = frozenset({"none", "path", "hostname", "dns", "port"})


class ManagedServiceError(RuntimeError):
    pass


_CACHED_SCHEMA: dict[str, Any] | None = None


def _load_schema() -> dict[str, Any] | None:
    global _CACHED_SCHEMA
    if _CACHED_SCHEMA is not None:
        return _CACHED_SCHEMA
    try:
        _CACHED_SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        _CACHED_SCHEMA = None
    return _CACHED_SCHEMA


def _schema_validate_document(data: dict[str, Any]) -> None:
    schema = _load_schema()
    if schema is None:
        return
    if _HAS_JSONSCHEMA:
        try:
            jsonschema.validate(data, schema)
        except jsonschema.ValidationError as exc:
            path = "/" + "/".join(str(p) for p in exc.path) if exc.path else ""
            raise ManagedServiceError(f"Schema validation failed at {path}: {exc.message}") from exc
    else:
        if not isinstance(data.get("schemaVersion"), int) or isinstance(data.get("schemaVersion"), bool):
            raise ManagedServiceError("schemaVersion must be integer 2")
        if data.get("schemaVersion") != SCHEMA_VERSION:
            raise ManagedServiceError(f"Schema validation failed: schemaVersion must be {SCHEMA_VERSION}")
        services = data.get("services")
        if not isinstance(services, dict):
            raise ManagedServiceError("Schema validation failed: services must be object")
        for sid, svc in services.items():
            if not isinstance(svc, dict):
                raise ManagedServiceError(f"Schema validation failed: service {sid!r} must be object")
            if not isinstance(svc.get("enabled"), bool):
                raise ManagedServiceError(
                    f"Schema validation failed: service {sid!r} enabled must be boolean, got {type(svc.get('enabled')).__name__}"
                )
            for eid, ep in (svc.get("endpoints") or {}).items():
                if not isinstance(ep, dict):
                    raise ManagedServiceError(f"Schema validation failed: endpoint {eid!r} must be object")
                tp = ep.get("targetPort")
                if isinstance(tp, bool) or not isinstance(tp, int):
                    raise ManagedServiceError(f"Schema validation failed: endpoint {eid!r} targetPort must be integer")


def _validate_service_id(value: str) -> str:
    if not SERVICE_ID_RE.fullmatch(value):
        raise ManagedServiceError(f"Invalid service ID {value!r}: must match {SERVICE_ID_RE.pattern}")
    return value


def _validate_host_path(path: str) -> str:
    if not path.startswith("/"):
        raise ManagedServiceError(f"hostPath must be absolute: {path!r}")
    if not any(path == root or path.startswith(root + "/") for root in ALLOWED_HOST_ROOTS):
        raise ManagedServiceError(f"hostPath {path!r} is not beneath allow-list {ALLOWED_HOST_ROOTS}")
    if ".." in pathlib.PurePosixPath(path).parts:
        raise ManagedServiceError(f"hostPath must not contain '..': {path!r}")
    p = pathlib.Path(path)
    try:
        resolved = p.resolve()
    except OSError as exc:
        raise ManagedServiceError(f"hostPath {path!r} cannot be resolved: {exc}") from exc
    if not any(str(resolved) == root or str(resolved).startswith(root + "/") for root in ALLOWED_HOST_ROOTS):
        raise ManagedServiceError(f"hostPath {path!r} resolves outside allow-list to {resolved!r}")
    cur = pathlib.Path("/")
    for part in p.parts[1:]:
        cur = cur / part
        try:
            st = cur.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise ManagedServiceError(f"hostPath {path!r} component {cur!r} cannot be stated: {exc}") from exc
        import stat as _stat

        if _stat.S_ISLNK(st.st_mode):
            try:
                link_target = cur.resolve()
            except OSError:
                raise ManagedServiceError(f"hostPath {path!r} component {cur!r} is a symlink that cannot be resolved")
            if not any(
                str(link_target) == root or str(link_target).startswith(root + "/") for root in ALLOWED_HOST_ROOTS
            ):
                raise ManagedServiceError(
                    f"hostPath {path!r} component {cur!r} is a symlink escaping allow-list to {link_target!r}"
                )
    return path


def _validate_image(image: str) -> str:
    if len(image) > 512 or not IMAGE_RE.fullmatch(image):
        raise ManagedServiceError(f"Invalid image reference {image!r}")
    return image


def _validate_hostname(hostname: str) -> str:
    if len(hostname) > 253 or not HOSTNAME_RE.fullmatch(hostname):
        raise ManagedServiceError(f"Invalid hostname {hostname!r}")
    return hostname


def _validate_port(port: Any) -> int:
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ManagedServiceError(f"Invalid port {port!r}")
    return port


def _validate_runtime_source(service_id: str, source: str) -> str:
    if not isinstance(source, str) or not source:
        raise ManagedServiceError(f"Service {service_id}: runtime.source must be a non-empty string")
    p = pathlib.Path(source)
    if not str(source).startswith("/var/lib/nas-control/apps/"):
        raise ManagedServiceError(f"Service {service_id}: runtime.source must be under /var/lib/nas-control/apps/")
    try:
        resolved = p.resolve()
    except OSError as exc:
        raise ManagedServiceError(f"Service {service_id}: runtime.source cannot be resolved: {exc}") from exc
    service_root = APPS_ROOT / service_id
    try:
        resolved.relative_to(service_root.resolve() if service_root.exists() else service_root)
    except ValueError:
        raise ManagedServiceError(
            f"Service {service_id}: runtime.source {source!r} resolves to {resolved!r} outside service root {service_root}"
        )
    if ".." in pathlib.PurePosixPath(source).parts:
        raise ManagedServiceError(f"Service {service_id}: runtime.source must not contain '..'")
    return source


def validate_service(service_id: str, data: dict[str, Any]) -> dict[str, Any]:
    _validate_service_id(service_id)
    label = data.get("label", "")
    if not isinstance(label, str) or not label or len(label) > 64:
        raise ManagedServiceError(f"Service {service_id}: label must be 1..64 chars")
    enabled = data.get("enabled")
    if not isinstance(enabled, bool):
        raise ManagedServiceError(f"Service {service_id}: enabled must be boolean, got {type(enabled).__name__}")
    runtime = data.get("runtime", {})
    if not isinstance(runtime, dict):
        raise ManagedServiceError(f"Service {service_id}: runtime must be object")
    if runtime.get("type") not in ("quadlet", "compose", "vm", "external", "native"):
        raise ManagedServiceError(f"Service {service_id}: runtime.type invalid")
    source = runtime.get("source", "")
    _validate_runtime_source(service_id, source)
    if "image" in runtime:
        _validate_image(runtime["image"])
    for mount in data.get("storage", []):
        if not isinstance(mount, dict):
            raise ManagedServiceError(f"Service {service_id}: storage entry must be object")
        _validate_host_path(mount.get("hostPath", ""))
        guest = mount.get("guestPath", "")
        if not guest.startswith("/"):
            raise ManagedServiceError(f"Service {service_id}: guestPath must be absolute")
    endpoints = data.get("endpoints")
    if endpoints is not None and not isinstance(endpoints, dict):
        raise ManagedServiceError(f"Service {service_id}: endpoints must be object")
    for endpoint_id, endpoint in (data.get("endpoints") or {}).items():
        if not ENDPOINT_ID_RE.fullmatch(endpoint_id):
            raise ManagedServiceError(f"Service {service_id}: endpoint {endpoint_id!r} invalid")
        if not isinstance(endpoint, dict):
            raise ManagedServiceError(f"Service {service_id}: endpoint {endpoint_id!r} must be object")
        _validate_port(endpoint.get("targetPort", 0))
        exposure = endpoint.get("exposure")
        if exposure is None or not isinstance(exposure, dict):
            raise ManagedServiceError(
                f"Service {service_id}: endpoint {endpoint_id!r} exposure must be object with type"
            )
        exp_type = exposure.get("type")
        if exp_type not in EXPOSURE_TYPE_VALUES:
            raise ManagedServiceError(
                f"Service {service_id}: endpoint {endpoint_id!r} exposure.type must be one of {sorted(EXPOSURE_TYPE_VALUES)}, got {exp_type!r}"
            )
        if exp_type in ("hostname", "dns"):
            hostname = exposure.get("value", "")
            _validate_hostname(hostname)
            if any(c in hostname for c in ("\r", "\n", "{", "}")):
                raise ManagedServiceError(
                    f"Service {service_id}: endpoint {endpoint_id!r} hostname contains invalid characters"
                )
            lan_host = os.environ.get("NAS_LAN_HOST", "nas.local")
            if hostname == lan_host or hostname.endswith(f".{lan_host}"):
                raise ManagedServiceError(
                    f"Service {service_id}: endpoint {endpoint_id!r} hostname {hostname!r} collides with NAS host"
                )
        elif exp_type == "port":
            _validate_port(
                exposure.get("value")
                if isinstance(exposure.get("value"), int)
                else int(exposure.get("value", 0))
                if str(exposure.get("value", "")).isdigit()
                else exposure.get("value")
            )
            val = exposure.get("value")
            try:
                _validate_port(int(val) if isinstance(val, str) and val.isdigit() else val)
            except (ValueError, TypeError):
                raise ManagedServiceError(
                    f"Service {service_id}: endpoint {endpoint_id!r} exposure port invalid: {val!r}"
                )
        elif exp_type == "path":
            val = exposure.get("value", "")
            if not isinstance(val, str) or not val.startswith("/"):
                raise ManagedServiceError(
                    f"Service {service_id}: endpoint {endpoint_id!r} path exposure must start with '/'"
                )
            if any(c in val for c in ("\r", "\n", "{", "}")):
                raise ManagedServiceError(
                    f"Service {service_id}: endpoint {endpoint_id!r} path contains invalid characters"
                )
            reserved_prefixes = (
                "/api",
                "/outpost.goauthentik.io",
                "/identity",
                "/console",
                "/shares",
                "/share",
                "/dav",
                "/vault",
                "/ai",
                "/syncthing",
                "/metrics",
                "/victoriametrics",
                "/alerts",
                "/ups",
                "/notifications",
                "/settings",
            )
            if any(val == rp or val.startswith(rp + "/") for rp in reserved_prefixes):
                raise ManagedServiceError(
                    f"Service {service_id}: endpoint {endpoint_id!r} path {val!r} conflicts with reserved NAS path"
                )
        auth = endpoint.get("auth")
        if auth is None or not isinstance(auth, dict):
            raise ManagedServiceError(f"Service {service_id}: endpoint {endpoint_id!r} auth must be object")
        mode = auth.get("mode")
        if mode not in AUTH_MODE_VALUES:
            raise ManagedServiceError(
                f"Service {service_id}: endpoint {endpoint_id!r} auth.mode must be one of {sorted(AUTH_MODE_VALUES)}, got {mode!r}"
            )
        if "allow" in auth and auth["allow"] not in AUTH_ALLOW_VALUES:
            raise ManagedServiceError(
                f"Service {service_id}: endpoint {endpoint_id!r} auth.allow must be one of {sorted(AUTH_ALLOW_VALUES)}"
            )
        for gid in auth.get("groups", []):
            if not isinstance(gid, str) or not re.fullmatch(r"^([A-Za-z0-9_-]+|[0-9a-fA-F-]{36}|\d+)$", gid):
                raise ManagedServiceError(f"Invalid Authentik group ID {gid!r}")
        for uid in auth.get("users", []):
            if not isinstance(uid, str) or not re.fullmatch(r"^([A-Za-z0-9._-]+|[0-9a-fA-F-]{36}|\d+)$", uid):
                raise ManagedServiceError(f"Invalid Authentik user ID {uid!r}")
        if "groups" in auth and not isinstance(auth["groups"], list):
            raise ManagedServiceError(f"Service {service_id}: endpoint {endpoint_id!r} auth.groups must be array")
        if "users" in auth and not isinstance(auth["users"], list):
            raise ManagedServiceError(f"Service {service_id}: endpoint {endpoint_id!r} auth.users must be array")
        if os.environ.get("NAS_AUTHENTIK_LIVE_VALIDATION") == "1":
            _validate_authentik_stable_ids(auth)
    return data


def _validate_authentik_stable_ids(auth: dict[str, Any]) -> None:
    api = os.environ.get("NAS_AUTHENTIK_API", "")
    token = os.environ.get("NAS_AUTHENTIK_TOKEN", "")
    if not api or not token:
        return
    import urllib.request
    import urllib.error

    for gid in auth.get("groups", []):
        if re.fullmatch(r"^\d+$", gid) or re.fullmatch(r"^[0-9a-fA-F-]{36}$", gid):
            try:
                req = urllib.request.Request(f"{api}/core/groups/{gid}/", headers={"Authorization": f"Bearer {token}"})
                with urllib.request.urlopen(req, timeout=5) as resp:
                    if resp.status != 200:
                        raise ManagedServiceError(f"Authentik group {gid!r} not found")
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    raise ManagedServiceError(f"Authentik group {gid!r} not found") from exc
            except OSError:
                pass
    for uid in auth.get("users", []):
        if re.fullmatch(r"^\d+$", uid) or re.fullmatch(r"^[0-9a-fA-F-]{36}$", uid):
            try:
                req = urllib.request.Request(f"{api}/core/users/{uid}/", headers={"Authorization": f"Bearer {token}"})
                with urllib.request.urlopen(req, timeout=5) as resp:
                    if resp.status != 200:
                        raise ManagedServiceError(f"Authentik user {uid!r} not found")
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    raise ManagedServiceError(f"Authentik user {uid!r} not found") from exc
            except OSError:
                pass


def load_store(path: pathlib.Path = STORE_PATH) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {"schemaVersion": SCHEMA_VERSION, "generation": 1, "services": {}}
    except OSError as exc:
        raise ManagedServiceError(f"Unable to read {path}: {exc}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ManagedServiceError(f"Invalid JSON in {path}: {exc}") from exc
    _schema_validate_document(data)
    if data.get("schemaVersion") != SCHEMA_VERSION:
        raise ManagedServiceError(f"Unsupported schemaVersion in {path}")
    services = data.get("services", {})
    if not isinstance(services, dict):
        raise ManagedServiceError("services must be an object")
    for service_id, service in services.items():
        validate_service(service_id, service)
    return data


def atomic_write_store(data: dict[str, Any], path: pathlib.Path = STORE_PATH) -> None:
    _schema_validate_document(data)
    if data.get("schemaVersion") != SCHEMA_VERSION:
        raise ManagedServiceError("Refusing to write store with wrong schemaVersion")
    for service_id, service in data.get("services", {}).items():
        validate_service(service_id, service)
    try:
        existing_stat = path.stat()
        orig_mode = existing_stat.st_mode & 0o777
        orig_uid = existing_stat.st_uid
        orig_gid = existing_stat.st_gid
        has_orig = True
    except FileNotFoundError:
        orig_mode = 0o600
        orig_uid = -1
        orig_gid = -1
        has_orig = False
    data = dict(data)
    data["generation"] = int(data.get("generation", 1)) + 1 if has_orig else int(data.get("generation", 1))
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(data, indent=2, sort_keys=True) + "\n"
    fd, tmp = tempfile.mkstemp(prefix=".services.json.", dir=parent)
    tmp_path = pathlib.Path(tmp)
    try:
        with open(fd, "w", encoding="utf-8") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            if has_orig:
                os.chmod(tmp_path, orig_mode)
                if orig_uid != -1 and os.geteuid() == 0:
                    try:
                        os.chown(tmp_path, orig_uid, orig_gid)
                    except OSError:
                        pass
            else:
                tmp_path.chmod(0o600)
        except OSError:
            pass
        tmp_path.replace(path)
        dir_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        tmp_path.unlink(missing_ok=True)


def effective_registry(
    builtin_path: pathlib.Path = BUILTIN_REGISTRY, store_path: pathlib.Path = STORE_PATH
) -> dict[str, Any]:
    try:
        builtin = json.loads(builtin_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        builtin = {"schemaVersion": 1, "endpoints": {}}
    store = load_store(store_path)
    builtin_endpoints: dict[str, Any] = {}
    for eid, ep in builtin.get("endpoints", {}).items():
        norm = dict(ep)
        if "publicPath" in ep and "exposure" not in ep:
            norm["exposure"] = {"type": "path", "value": ep["publicPath"]}
        if "portal" not in norm and ep.get("linkKey"):
            norm["portal"] = {
                "visible": True,
                "category": "Administration" if ep.get("access") == "admin" else "Other",
                "icon": ep.get("linkKey", "box"),
            }
        builtin_endpoints[eid] = norm
    effective = {
        "schemaVersion": SCHEMA_VERSION,
        "generation": store.get("generation", 1),
        "endpoints": dict(builtin_endpoints),
        "services": dict(store.get("services", {})),
    }
    for service_id, service in store.get("services", {}).items():
        for endpoint_id, endpoint in (service.get("endpoints") or {}).items():
            key = f"{service_id}:{endpoint_id}"
            effective["endpoints"][key] = {
                "label": f"{service.get('label')}:{endpoint_id}",
                "serviceId": service_id,
                "endpointId": endpoint_id,
                "transport": endpoint.get("transport"),
                "targetPort": endpoint.get("targetPort"),
                "exposure": endpoint.get("exposure"),
                "auth": endpoint.get("auth"),
                "portal": endpoint.get("portal", service.get("portal", {})),
                "available": service.get("enabled", False),
            }
    return effective


def write_effective(
    builtin_path: pathlib.Path = BUILTIN_REGISTRY,
    store_path: pathlib.Path = STORE_PATH,
    effective_path: pathlib.Path = EFFECTIVE_PATH,
) -> dict[str, Any]:
    effective = effective_registry(builtin_path, store_path)
    parent = effective_path.parent
    parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(effective, indent=2, sort_keys=True) + "\n"
    fd, tmp = tempfile.mkstemp(prefix=".effective.json.", dir=parent)
    tmp_path = pathlib.Path(tmp)
    try:
        with open(fd, "w", encoding="utf-8") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        tmp_path.chmod(0o644)
        tmp_path.replace(effective_path)
        dir_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        tmp_path.unlink(missing_ok=True)
    return effective


def portal_projection(effective: dict[str, Any] | None = None) -> dict[str, Any]:
    if effective is None:
        effective = effective_registry()
    entries = []
    for key, endpoint in effective.get("endpoints", {}).items():
        if endpoint.get("linkKey") is None and not endpoint.get("portal", {}).get("visible", False):
            continue
        exposure = endpoint.get("exposure") or {}
        url = ""
        if exposure.get("type") == "path":
            url = exposure.get("value", "/")
        elif exposure.get("type") in ("hostname", "dns"):
            url = f"https://{exposure.get('value')}/"
        elif exposure.get("type") == "port":
            url = f"https://nas.local:{exposure.get('value')}/"
        if not url and endpoint.get("publicPath"):
            url = endpoint.get("publicPath")
        entries.append(
            {
                "id": key,
                "label": endpoint.get("label", key),
                "url": url,
                "category": endpoint.get("portal", {}).get("category", "Other"),
                "icon": endpoint.get("portal", {}).get("icon", "box"),
                "available": endpoint.get("available", False),
                "access": endpoint.get("auth") or {"mode": endpoint.get("access", "admin")},
            }
        )
    return {
        "schemaVersion": SCHEMA_VERSION,
        "generation": effective.get("generation", 1),
        "entries": sorted(entries, key=lambda x: x["id"]),
    }


def _read_effective_or_recompute(effective_path: pathlib.Path) -> dict[str, Any]:
    try:
        return json.loads(effective_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return effective_registry()


def write_portal(
    effective_path: pathlib.Path = EFFECTIVE_PATH, portal_path: pathlib.Path = PORTAL_PATH
) -> dict[str, Any]:
    effective = _read_effective_or_recompute(effective_path)
    portal = portal_projection(effective)
    parent = portal_path.parent
    parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(portal, indent=2, sort_keys=True) + "\n"
    fd, tmp = tempfile.mkstemp(prefix=".portal.json.", dir=parent)
    tmp_path = pathlib.Path(tmp)
    try:
        with open(fd, "w", encoding="utf-8") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        tmp_path.chmod(0o644)
        tmp_path.replace(portal_path)
        dir_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        tmp_path.unlink(missing_ok=True)
    return portal


def main(argv: list[str] | None = None) -> int:
    import argparse
    import sys

    parser = argparse.ArgumentParser(prog="nas-managed-service")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("reconcile", help="Rebuild effective registry and portal from store + built-ins")
    sub.add_parser("validate", help="Validate store and built-ins")
    show = sub.add_parser("show", help="Show effective registry")
    show.add_argument("--json", action="store_true")
    for cmd in ("plan", "create", "update", "delete", "start", "stop", "restart", "adopt", "export", "import"):
        sub.add_parser(cmd, help=f"Managed-service {cmd} (not yet implemented)")
    args = parser.parse_args(argv)
    try:
        if args.command in (
            "plan",
            "create",
            "update",
            "delete",
            "start",
            "stop",
            "restart",
            "adopt",
            "export",
            "import",
        ):
            print(
                f"nas-managed-service: {args.command} is not yet implemented (runtime adapters pending)",
                file=sys.stderr,
            )
            return 2
        if args.command == "reconcile":
            effective = write_effective()
            portal = write_portal()
            print(json.dumps({"effective": effective, "portal": portal}, indent=2))
            return 0
        elif args.command == "validate":
            load_store()
            effective_registry()
            print("store and effective registry are valid")
            return 0
        elif args.command == "show":
            effective = effective_registry()
            if args.json:
                print(json.dumps(effective, indent=2))
            else:
                print(json.dumps(effective, indent=2, sort_keys=True))
            return 0
        else:
            parser.print_help()
            return 2
    except ManagedServiceError as exc:
        print(f"nas-managed-service: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"nas-managed-service: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
