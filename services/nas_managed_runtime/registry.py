#!/usr/bin/env python3
"""Managed-service store, effective-registry, and portal projections."""
from __future__ import annotations
import copy, hashlib, ipaddress, json, os, pathlib, re, tempfile
from typing import Any, Mapping
from nas_operation_journal import atomic_write_json
from nas_managed_runtime.model import (
    STORE_PATH, BUILTIN_REGISTRY, EFFECTIVE_PATH, PORTAL_PATH, SCHEMA_PATH, APP_ROOT, LAN_HOST,
    HOST_PORT_MIN, HOST_PORT_MAX, VM_POOL, SCHEMA_VERSION, SERVICE_ID_RE, ENDPOINT_ID_RE,
    ManagedServiceError, normalize_service, _validate_schema_if_available, _validate_image, _validate_port, _validate_hostname, _port, _hostname,
)

def normalize_store(raw:Mapping[str,Any])->dict[str,Any]:
    store=copy.deepcopy(dict(raw));store.setdefault("schemaVersion",2);store.setdefault("generation",1);store.setdefault("services",{})
    if store["schemaVersion"]!=2 or not isinstance(store["services"],dict):raise ManagedServiceError("managed service store must be schemaVersion=2 with services object")
    store["services"]={sid:normalize_service(sid,svc) for sid,svc in store["services"].items()};_validate_schema_if_available(store);return store
def load_store(path:pathlib.Path|None=None)->dict[str,Any]:
    path=STORE_PATH if path is None else path
    try:raw=json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:raw={"schemaVersion":2,"generation":1,"services":{}}
    except (OSError,json.JSONDecodeError) as exc:raise ManagedServiceError(f"unable to read {path}: {exc}") from exc
    if not isinstance(raw,dict):raise ManagedServiceError("managed-service store must be a JSON object")
    return normalize_store(raw)
def atomic_write_store(store:Mapping[str,Any],path:pathlib.Path|None=None)->None:
    atomic_write_json(STORE_PATH if path is None else path,normalize_store(store),mode=0o600)
def _vm_mac(service_id:str)->str:
    digest=hashlib.sha256(("nas-vm:"+service_id).encode()).digest();return "52:54:00:"+":".join(f"{x:02x}" for x in digest[:3])
def allocate_runtime_addresses(store:dict[str,Any])->None:
    used_subnets={ipaddress.ip_network(svc["network"]["vmSubnet"],strict=True) for svc in store["services"].values() if svc["runtime"]["type"]=="vm" and svc["network"].get("vmSubnet")};free=(n for n in VM_POOL.subnets(new_prefix=24) if n not in used_subnets)
    for sid,svc in sorted(store["services"].items()):
        if svc["runtime"]["type"]!="vm":continue
        net=svc["network"]
        if not net.get("vmSubnet"):net["vmSubnet"]=str(next(free))
        subnet=ipaddress.ip_network(net["vmSubnet"],strict=True);net.setdefault("vmAddress",str(subnet.network_address+10));net.setdefault("vmMac",_vm_mac(sid))
        for ep in svc["endpoints"].values():
            if ep["exposure"]["type"]!="none":ep.setdefault("targetHost",net["vmAddress"])
    used_ports={int(ep["hostPort"]) for svc in store["services"].values() for ep in svc["endpoints"].values() if isinstance(ep.get("hostPort"),int)};cursor=HOST_PORT_MIN
    for sid,svc in sorted(store["services"].items()):
        if svc["runtime"]["type"] not in {"container","compose"}:continue
        for eid,ep in sorted(svc["endpoints"].items()):
            kind=ep["exposure"]["type"];web=ep["transport"] in {"http","https","ws"}
            if kind in {"path","hostname","dns"} or (kind=="port" and web):
                if not ep.get("hostPort"):
                    while cursor in used_ports and cursor<=HOST_PORT_MAX:cursor+=1
                    if cursor>HOST_PORT_MAX:raise ManagedServiceError("managed backend port pool exhausted")
                    ep["hostPort"]=cursor;used_ports.add(cursor);cursor+=1
            elif kind=="port" and not ep.get("hostPort"):ep["hostPort"]=int(ep["exposure"]["value"])
def effective_registry(builtin_path:pathlib.Path|None=None,store_path:pathlib.Path|None=None)->dict[str,Any]:
    builtin_path=BUILTIN_REGISTRY if builtin_path is None else builtin_path;store_path=STORE_PATH if store_path is None else store_path
    try:builtin=json.loads(builtin_path.read_text(encoding="utf-8"))
    except FileNotFoundError:builtin={"schemaVersion":2,"services":{}}
    store=load_store(store_path);services={};endpoints={}
    if isinstance(builtin,dict) and builtin.get("schemaVersion")==2 and isinstance(builtin.get("services"),dict):
        for sid,svc0 in builtin["services"].items():
            if not isinstance(svc0,dict):continue
            svc=copy.deepcopy(svc0);svc["builtin"]=True;svc["ownership"]="system";services[sid]=svc
            for eid,ep0 in (svc.get("endpoints") or {}).items():
                if not isinstance(ep0,dict):continue
                key=f"{sid}:{eid}";ep=copy.deepcopy(ep0);ep.update({"id":key,"serviceId":sid,"endpointId":eid,"label":ep.get("label") or svc.get("label",sid),"description":ep.get("description") or svc.get("description",""),"runtimeType":svc.get("runtime",{}).get("type","systemd"),"available":bool(svc.get("enabled")),"builtin":True});endpoints[key]=ep
    elif isinstance(builtin,dict):
        for key,ep0 in (builtin.get("endpoints") or {}).items():
            if not isinstance(ep0,dict):continue
            ep=copy.deepcopy(ep0);access=str(ep.get("access","admin"));ep.setdefault("exposure",{"type":"path","value":ep.get("publicPath","/")});ep.setdefault("portal",{"visible":ep.get("linkKey") is not None,"category":"Administration" if access=="admin" else "Other","icon":ep.get("linkKey") or "box"});ep.setdefault("auth",{"mode":"public"} if access in {"public","native","network"} else {"mode":"forward-auth","allow":"groups" if access=="admin" else "any","groups":["nas_admin"] if access=="admin" else [],"users":[],"adminBypass":True});ep.update({"id":key,"serviceId":str(ep.get("owner") or key),"endpointId":key,"available":bool(ep.get("available",True)),"builtin":True});endpoints[key]=ep
    for sid,svc in store["services"].items():
        services[sid]=copy.deepcopy(svc)
        for eid,ep0 in svc["endpoints"].items():
            key=f"{sid}:{eid}";ep=copy.deepcopy(ep0);ep.update({"id":key,"serviceId":sid,"endpointId":eid,"label":ep.get("label") or svc["label"],"description":ep.get("description") or svc.get("description",""),"runtimeType":svc["runtime"]["type"],"available":bool(svc["enabled"]),"builtin":False});endpoints[key]=ep
    return {"schemaVersion":2,"generation":store["generation"],"services":services,"endpoints":endpoints}
def validate_conflicts(effective:Mapping[str,Any])->None:
    paths=[];hosts={};ports={};backend={};reserved_paths=[str(ep.get("exposure",{}).get("value")) for ep in effective["endpoints"].values() if ep.get("builtin") and ep.get("exposure",{}).get("type")=="path"]
    for key,ep in effective["endpoints"].items():
        if ep.get("builtin"):continue
        hp=ep.get("hostPort")
        if isinstance(hp,int):
            if hp in backend:raise ManagedServiceError(f"backend port {hp} conflicts between {backend[hp]} and {key}")
            backend[hp]=key
        exp=ep.get("exposure") or {};typ=exp.get("type");value=exp.get("value")
        if typ=="path":
            val="/"+str(value).strip("/")+"/"
            if val=="//":raise ManagedServiceError("managed endpoint may not replace portal root")
            for other_key,other in [("built-in",p) for p in reserved_paths]+paths:
                o="/"+other.strip("/")+"/"
                if val==o or val.startswith(o) or o.startswith(val):raise ManagedServiceError(f"path {value} overlaps {other_key}:{other}")
            paths.append((key,str(value)))
        elif typ in {"hostname","dns"}:
            host=str(value).lower().rstrip(".")
            if host==LAN_HOST.lower().rstrip("."):raise ManagedServiceError("managed endpoint may not claim primary NAS hostname")
            if host in hosts:raise ManagedServiceError(f"hostname {host} claimed by {hosts[host]} and {key}")
            hosts[host]=key
        elif typ=="port":
            p=int(value)
            if p in {80,443}:raise ManagedServiceError(f"reserved public port {p}")
            if p in ports:raise ManagedServiceError(f"public port {p} claimed by {ports[p]} and {key}")
            ports[p]=key
    for sid,svc in effective["services"].items():
        if svc.get("builtin"):continue
        for rule in (svc.get("network") or {}).get("allowedServices",[]):
            if rule["service"] not in effective["services"]:raise ManagedServiceError(f"service {sid}: allowedServices references unknown {rule['service']}")
def portal_projection(effective:Mapping[str,Any]|None=None)->dict[str,Any]:
    if effective is None:effective=effective_registry()
    entries=[]
    for key,ep in effective["endpoints"].items():
        portal=ep.get("portal") or {}
        if portal.get("visible") is not True and ep.get("linkKey") is None:continue
        exp=ep.get("exposure") or {};typ=exp.get("type");val=exp.get("value");url=""
        if typ=="path":url=str(val)
        elif typ in {"hostname","dns"}:url=f"https://{val}/"
        elif typ=="port":url=f"https://{LAN_HOST}:{val}/"
        if not url:continue
        entries.append({"id":key,"label":ep.get("label",key),"description":ep.get("description",""),"url":url,"category":portal.get("category","Other"),"icon":portal.get("icon","box"),"available":bool(ep.get("available")),"access":copy.deepcopy(ep.get("auth") or {"mode":ep.get("access","admin")}),"builtin":bool(ep.get("builtin"))})
    return {"schemaVersion":2,"generation":effective.get("generation",1),"entries":sorted(entries,key=lambda x:(x["category"],x["label"],x["id"]))}
def _write_projection(path:pathlib.Path,value:Mapping[str,Any],mode:int=0o644)->None:atomic_write_json(path,dict(value),mode=mode)
def validate_service(service_id:str,data:Mapping[str,Any])->dict[str,Any]:
    if SERVICE_ID_RE.fullmatch(service_id) is None:raise ManagedServiceError(f"Invalid service ID {service_id!r}")
    value=copy.deepcopy(dict(data));label=value.get("label")
    if not isinstance(label,str) or not 1<=len(label)<=64:raise ManagedServiceError("label must be 1..64 characters")
    if "enabled" in value and not isinstance(value["enabled"],bool):raise ManagedServiceError("enabled must be boolean")
    runtime=value.setdefault("runtime",{});typ=runtime.get("type") if isinstance(runtime,dict) else None
    if typ=="quadlet":runtime["type"]="compose";typ="compose"
    if typ not in {"container","compose","vm","native","external"}:raise ManagedServiceError("runtime.type invalid")
    if typ in {"compose","vm"}:
        source=runtime.get("source")
        if not isinstance(source,str) or not source.startswith(f"/var/lib/nas-control/apps/{service_id}/") or ".." in pathlib.PurePosixPath(source).parts:raise ManagedServiceError("runtime.source must be below the service application root")
    if "image" in runtime:_validate_image(runtime["image"])
    for mount in value.get("storage",[]) or []:
        if not isinstance(mount,dict):raise ManagedServiceError("storage entry must be object")
        hp=mount.get("hostPath")
        if not isinstance(hp,str) or not hp.startswith("/"):raise ManagedServiceError("hostPath must be absolute")
        if ".." in pathlib.PurePosixPath(hp).parts:raise ManagedServiceError("hostPath must not contain '..'")
        mount.setdefault("mode","ro")
    endpoints=value.setdefault("endpoints",{})
    if not isinstance(endpoints,dict):raise ManagedServiceError("endpoints must be object")
    for eid,ep in endpoints.items():
        if ENDPOINT_ID_RE.fullmatch(str(eid)) is None or not isinstance(ep,dict):raise ManagedServiceError(f"endpoint {eid!r} invalid")
        ep.setdefault("transport","http");_validate_port(ep.get("targetPort"));exposure=ep.setdefault("exposure",{"type":"none"})
        if exposure.get("type") in {"hostname","dns"}:_validate_hostname(exposure.get("value"))
        auth=ep.setdefault("auth",{"mode":"public"})
        for group in auth.get("groups",[]) or []:
            if not isinstance(group,str) or re.fullmatch(r"^[A-Za-z0-9_-]+$",group) is None:raise ManagedServiceError(f"Invalid Authentik group ID {group!r}")
    return normalize_service(service_id,value)
def write_effective(builtin_path:pathlib.Path|None=None,store_path:pathlib.Path|None=None,effective_path:pathlib.Path|None=None)->dict[str,Any]:
    builtin_path=BUILTIN_REGISTRY if builtin_path is None else builtin_path;store_path=STORE_PATH if store_path is None else store_path;effective_path=EFFECTIVE_PATH if effective_path is None else effective_path;effective=effective_registry(builtin_path,store_path);validate_conflicts(effective);_write_projection(effective_path,effective);return effective
def write_portal(effective_path:pathlib.Path|None=None,portal_path:pathlib.Path|None=None)->dict[str,Any]:
    effective_path=EFFECTIVE_PATH if effective_path is None else effective_path;portal_path=PORTAL_PATH if portal_path is None else portal_path
    try:effective=json.loads(effective_path.read_text(encoding="utf-8"))
    except (FileNotFoundError,OSError,json.JSONDecodeError):effective=effective_registry()
    portal=portal_projection(effective);_write_projection(portal_path,portal);return portal
