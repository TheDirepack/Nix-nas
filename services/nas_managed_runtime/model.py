#!/usr/bin/env python3
"""Unified file-backed managed-service model and validation."""
from __future__ import annotations
import copy, ipaddress, json, os, pathlib, re
from typing import Any, Mapping
STORE_PATH=pathlib.Path(os.environ.get("NAS_MANAGED_SERVICE_STORE","/var/lib/nas-control/services.json"));BUILTIN_REGISTRY=pathlib.Path(os.environ.get("NAS_BUILTIN_REGISTRY","/etc/nas-control/endpoints.json"));EFFECTIVE_PATH=pathlib.Path(os.environ.get("NAS_EFFECTIVE_REGISTRY","/run/nas-control/effective-endpoints.json"));PORTAL_PATH=pathlib.Path(os.environ.get("NAS_PORTAL_JSON","/run/nas-control/portal.json"));SCHEMA_PATH=pathlib.Path(os.environ.get("NAS_MANAGED_SERVICE_SCHEMA","/etc/nas-control/managed-service.schema.json"));APP_ROOT=pathlib.Path(os.environ.get("NAS_MANAGED_APP_ROOT","/var/lib/nas-control/apps"));JOURNAL_PATH=pathlib.Path(os.environ.get("NAS_MANAGED_SERVICE_JOURNAL","/var/lib/nas-control/managed-services-journal.json"));LAN_HOST=os.environ.get("NAS_LAN_HOST","nas.local");HOST_PORT_MIN=int(os.environ.get("NAS_MANAGED_HOST_PORT_MIN","20000"));HOST_PORT_MAX=int(os.environ.get("NAS_MANAGED_HOST_PORT_MAX","29999"));VM_POOL=ipaddress.ip_network(os.environ.get("NAS_MANAGED_VM_NETWORK_POOL","10.240.0.0/16"),strict=True);SCHEMA_VERSION=2
SERVICE_ID_RE=re.compile(r"^[a-z][a-z0-9-]{0,47}$");ENDPOINT_ID_RE=SERVICE_ID_RE;HOSTNAME_RE=re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",re.I);IMAGE_RE=re.compile(r"^[A-Za-z0-9][A-Za-z0-9./:_@+-]{0,511}$");UNIT_RE=re.compile(r"^[A-Za-z0-9_.@-]+\.(?:service|socket|target)$");NAME_RE=re.compile(r"^[A-Za-z0-9_.-]{1,63}$");ALLOWED_HOST_ROOTS=tuple(pathlib.Path(x) for x in os.environ.get("NAS_MANAGED_ALLOWED_HOST_ROOTS","/tank:/srv:/var/lib/nas-control/apps").split(":") if x);PROTECTED_ROOTS=tuple(pathlib.Path(x) for x in ("/etc","/boot","/dev","/proc","/sys","/run/nas-secrets","/var/lib/authentik","/var/lib/caddy"))
class ManagedServiceError(RuntimeError):pass
def _under(path:pathlib.Path,root:pathlib.Path)->bool:
    try:path.relative_to(root);return True
    except ValueError:return False
def _host_path(value:Any)->str:
    if not isinstance(value,str) or not value.startswith("/") or ".." in pathlib.PurePosixPath(value).parts:raise ManagedServiceError(f"invalid host path {value!r}")
    resolved=pathlib.Path(value).resolve(strict=False);roots=tuple(root.resolve(strict=False) for root in ALLOWED_HOST_ROOTS)
    if not any(_under(resolved,root) for root in roots):raise ManagedServiceError(f"host path {value!r} resolves outside allowed roots")
    if any(resolved==p or _under(resolved,p) for p in PROTECTED_ROOTS):raise ManagedServiceError(f"host path {value!r} resolves to protected host state")
    for root in roots:
        if not _under(resolved,root) or not root.exists():continue
        cur=pathlib.Path(value)
        while cur!=root and not cur.exists():cur=cur.parent
        if cur.exists() and not _under(cur.resolve(strict=True),root):raise ManagedServiceError(f"host path {value!r} escapes through a symlink")
    return value
def _port(value:Any)->int:
    if isinstance(value,bool) or not isinstance(value,int) or not 1<=value<=65535:raise ManagedServiceError(f"invalid port {value!r}")
    return value
def _hostname(value:Any)->str:
    if not isinstance(value,str) or len(value)>253 or HOSTNAME_RE.fullmatch(value) is None:raise ManagedServiceError(f"invalid hostname {value!r}")
    return value
def _validate_port(value:Any)->int:
    try:return _port(value)
    except ManagedServiceError as exc:raise ManagedServiceError(f"Invalid port {value!r}") from exc
def _validate_hostname(value:Any)->str:
    try:return _hostname(value)
    except ManagedServiceError as exc:raise ManagedServiceError(f"Invalid hostname {value!r}") from exc
def _validate_image(value:Any)->str:
    if not isinstance(value,str) or IMAGE_RE.fullmatch(value) is None:raise ManagedServiceError(f"Invalid image reference {value!r}")
    return value
def _source(service_id:str,value:Any)->str:
    if not isinstance(value,str) or not value:raise ManagedServiceError(f"service {service_id}: runtime source is required")
    resolved=pathlib.Path(value).resolve(strict=False);root=(APP_ROOT/service_id).resolve(strict=False)
    if not _under(resolved,root):raise ManagedServiceError(f"service {service_id}: runtime source must be below {root}")
    return value
def _validate_schema_if_available(store:dict[str,Any])->None:
    try:schema=json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    except (FileNotFoundError,OSError,json.JSONDecodeError):return
    try:import jsonschema
    except ImportError:return
    try:jsonschema.validate(store,schema)
    except jsonschema.ValidationError as exc:
        where="/".join(str(x) for x in exc.path);raise ManagedServiceError(f"schema validation failed at {where or '/'}: {exc.message}") from exc
def normalize_service(service_id:str,raw:Mapping[str,Any])->dict[str,Any]:
    if SERVICE_ID_RE.fullmatch(service_id) is None:raise ManagedServiceError(f"invalid service id {service_id!r}")
    service=copy.deepcopy(dict(raw));label=service.get("label")
    if not isinstance(label,str) or not 1<=len(label)<=64:raise ManagedServiceError(f"service {service_id}: label must be 1..64 characters")
    service.setdefault("ownership","runtime");service.setdefault("enabled",True)
    if not isinstance(service["enabled"],bool):raise ManagedServiceError(f"service {service_id}: enabled must be boolean")
    service.setdefault("generation",1);runtime=service.setdefault("runtime",{})
    if not isinstance(runtime,dict):raise ManagedServiceError(f"service {service_id}: runtime must be an object")
    typ=runtime.get("type")
    if typ not in {"container","compose","vm","native","external"}:raise ManagedServiceError(f"service {service_id}: unsupported runtime {typ!r}")
    runtime.setdefault("startPolicy","manual")
    if runtime["startPolicy"] not in {"boot","manual","disabled"}:raise ManagedServiceError(f"service {service_id}: invalid startPolicy")
    if typ=="container":
        image=runtime.get("image")
        if not isinstance(image,str) or IMAGE_RE.fullmatch(image) is None:raise ManagedServiceError(f"service {service_id}: safe runtime.image is required")
        if runtime.get("name") is not None and NAME_RE.fullmatch(str(runtime["name"])) is None:raise ManagedServiceError(f"service {service_id}: invalid container name")
    elif typ in {"compose","vm"}:
        runtime["source"]=_source(service_id,runtime.get("source"))
        if runtime.get("name") is not None and NAME_RE.fullmatch(str(runtime["name"])) is None:raise ManagedServiceError(f"service {service_id}: invalid runtime name")
    elif typ=="native":
        if not isinstance(runtime.get("systemdUnit"),str) or UNIT_RE.fullmatch(runtime["systemdUnit"]) is None:raise ManagedServiceError(f"service {service_id}: native runtime requires a safe systemdUnit")
    storage=service.setdefault("storage",[])
    if not isinstance(storage,list) or len(storage)>32:raise ManagedServiceError(f"service {service_id}: storage must be an array of at most 32 mounts")
    for mount in storage:
        if not isinstance(mount,dict):raise ManagedServiceError(f"service {service_id}: invalid storage entry")
        mount["hostPath"]=_host_path(mount.get("hostPath"));guest=mount.get("guestPath")
        if not isinstance(guest,str) or not guest.startswith("/") or ".." in pathlib.PurePosixPath(guest).parts:raise ManagedServiceError(f"service {service_id}: guestPath must be absolute and non-traversing")
        if mount.get("mode") not in {"ro","rw"}:raise ManagedServiceError(f"service {service_id}: mount mode must be ro or rw")
    endpoints=service.setdefault("endpoints",{})
    if not isinstance(endpoints,dict):raise ManagedServiceError(f"service {service_id}: endpoints must be an object")
    for endpoint_id,ep in endpoints.items():
        if ENDPOINT_ID_RE.fullmatch(endpoint_id) is None or not isinstance(ep,dict):raise ManagedServiceError(f"service {service_id}: invalid endpoint {endpoint_id!r}")
        if ep.get("transport") not in {"http","https","ws","tcp","udp"}:raise ManagedServiceError(f"service {service_id}: endpoint {endpoint_id} has invalid transport")
        ep["targetPort"]=_port(ep.get("targetPort"))
        if ep.get("hostPort") is not None:ep["hostPort"]=_port(ep["hostPort"])
        if ep.get("targetHost"):
            try:ipaddress.ip_address(str(ep["targetHost"]))
            except ValueError:_hostname(ep["targetHost"])
        exposure=ep.setdefault("exposure",{"type":"none"});kind=exposure.get("type")
        if kind not in {"none","path","hostname","dns","port"}:raise ManagedServiceError(f"service {service_id}: invalid exposure type")
        if kind=="path":
            value=exposure.get("value")
            if not isinstance(value,str) or not value.startswith("/") or ".." in pathlib.PurePosixPath(value).parts:raise ManagedServiceError(f"service {service_id}: invalid exposure path")
        elif kind in {"hostname","dns"}:_hostname(exposure.get("value"))
        elif kind=="port":exposure["value"]=_port(int(exposure["value"]) if isinstance(exposure.get("value"),str) and exposure["value"].isdigit() else exposure.get("value"))
        auth=ep.setdefault("auth",{"mode":"public"})
        if auth.get("mode") not in {"public","forward-auth","native"}:raise ManagedServiceError(f"service {service_id}: unsupported auth mode")
        auth.setdefault("allow","any");auth.setdefault("groups",[]);auth.setdefault("users",[]);auth["adminBypass"]=True
        if auth["allow"] not in {"any","groups","users"}:raise ManagedServiceError(f"service {service_id}: auth.allow must be any/groups/users")
        for key in ("groups","users"):
            if not isinstance(auth[key],list) or any(not isinstance(x,str) or not x or len(x)>128 for x in auth[key]):raise ManagedServiceError(f"service {service_id}: invalid auth.{key}")
        portal=ep.setdefault("portal",{});portal.setdefault("visible",False)
    network=service.setdefault("network",{})
    if not isinstance(network,dict):raise ManagedServiceError(f"service {service_id}: network must be an object")
    network.setdefault("outboundDefault","allow");network.setdefault("lanAccess",False);network.setdefault("hostAccess",False)
    if network["outboundDefault"] not in {"allow","deny"}:raise ManagedServiceError(f"service {service_id}: invalid outboundDefault")
    for rule in network.setdefault("allowedEgress",[]):
        if not isinstance(rule,dict):raise ManagedServiceError(f"service {service_id}: invalid egress rule")
        try:rule["cidr"]=str(ipaddress.ip_network(str(rule.get("cidr")),strict=False))
        except ValueError as exc:raise ManagedServiceError(f"service {service_id}: invalid CIDR") from exc
        if rule.get("protocol","any") not in {"tcp","udp","any"}:raise ManagedServiceError(f"service {service_id}: invalid egress protocol")
        rule.setdefault("ports",[])
        for value in rule["ports"]:_port(value)
    for rule in network.setdefault("allowedServices",[]):
        if not isinstance(rule,dict) or SERVICE_ID_RE.fullmatch(str(rule.get("service",""))) is None:raise ManagedServiceError(f"service {service_id}: invalid allowedServices rule")
        if rule.get("protocol","any") not in {"tcp","udp","any"}:raise ManagedServiceError(f"service {service_id}: invalid app protocol")
        rule.setdefault("ports",[])
        for value in rule["ports"]:_port(value)
    return service
