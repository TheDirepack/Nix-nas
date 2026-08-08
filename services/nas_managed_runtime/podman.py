#!/usr/bin/env python3
"""Daemonless Podman adapter for one NAS-managed container."""
from __future__ import annotations
import hashlib, json, os, re
from typing import Any
from nas_common import run_command

NAME_RE=re.compile(r"^[A-Za-z0-9_.-]{1,63}$")

def _run(argv:list[str],check:bool=True):
    r=run_command(argv,timeout_seconds=300,max_output_bytes=512*1024)
    if check and r.returncode: raise RuntimeError((r.stderr or r.stdout or "podman command failed")[:1000])
    return r
def network_name(sid:str)->str: return f"nas-{sid}"
def interface_name(sid:str)->str: return "np"+hashlib.sha256(sid.encode()).hexdigest()[:10]
def container_name(sid:str,svc:dict[str,Any])->str:
    name=str(svc.get("runtime",{}).get("name") or f"nas-{sid}")
    if NAME_RE.fullmatch(name) is None: raise RuntimeError("invalid container name")
    return name

def _fingerprint(sid:str,svc:dict[str,Any])->str:
    return hashlib.sha256(json.dumps({"id":sid,"runtime":svc.get("runtime"),"resources":svc.get("resources"),"storage":svc.get("storage"),"endpoints":svc.get("endpoints"),"network":svc.get("network")},sort_keys=True,separators=(",",":")).encode()).hexdigest()

def _network_exists(name:str)->bool: return _run(["podman","network","exists",name],False).returncode==0

def ensure_network(sid:str)->dict[str,str]:
    name=network_name(sid); interface=interface_name(sid)
    if not _network_exists(name):
        _run(["podman","network","create","--interface-name",interface,"--opt","isolate=true","--label",f"io.nixos-nas.service={sid}",name])
    return {"name":name,"interface":interface}
def remove_network(sid:str)->None:
    _run(["podman","network","rm","--force",network_name(sid)],False)
def _create_args(sid:str,svc:dict[str,Any])->list[str]:
    runtime=svc["runtime"]; name=container_name(sid,svc); fp=_fingerprint(sid,svc)
    argv=["podman","create","--name",name,"--label",f"io.nixos-nas.service={sid}","--label",f"io.nixos-nas.spec-hash={fp}","--network",network_name(sid)]
    res=svc.get("resources") or {}
    if res.get("memoryBytes"): argv += ["--memory",str(int(res["memoryBytes"]))]
    if res.get("cpus"): argv += ["--cpus",str(res["cpus"])]
    for device in res.get("gpus",[]) or []: argv += ["--device",str(device)]
    for key,value in sorted((runtime.get("environment") or {}).items()): argv += ["--env",f"{key}={value}"]
    for mount in svc.get("storage",[]) or []: argv += ["--volume",f"{mount['hostPath']}:{mount['guestPath']}:{mount['mode']}"]
    for ep in (svc.get("endpoints") or {}).values():
        hp=ep.get("hostPort")
        if not hp: continue
        transport=str(ep.get("transport") or "tcp"); proto="udp" if transport=="udp" else "tcp"; web=transport in {"http","https","ws"}; kind=(ep.get("exposure") or {}).get("type")
        bind="127.0.0.1" if web and kind in {"path","hostname","dns","port"} else "0.0.0.0"
        argv += ["--publish",f"{bind}:{int(hp)}:{int(ep['targetPort'])}/{proto}"]
    argv.append(str(runtime["image"])); argv += [str(x) for x in runtime.get("command",[]) or []]
    return argv
def _inspect(name:str,fmt:str)->str:
    r=_run(["podman","inspect","--format",fmt,name],False); return r.stdout.strip() if r.returncode==0 else ""
def plan_podman(sid:str,svc:dict[str,Any])->dict[str,Any]: return {"service":sid,"runtime":"container","network":network_name(sid),"container":container_name(sid,svc),"createArgv":_create_args(sid,svc)}
def apply_podman(sid:str,svc:dict[str,Any],*,dry_run:bool=False)->dict[str,Any]:
    plan=plan_podman(sid,svc)
    if dry_run:return plan
    name=container_name(sid,svc)
    if not svc.get("enabled") or svc["runtime"].get("startPolicy")=="disabled":
        _run(["podman","stop","--time","20",name],False); return {**plan,"state":"disabled"}
    ensure_network(sid); desired=_fingerprint(sid,svc); current=_inspect(name,"{{ index .Config.Labels \"io.nixos-nas.spec-hash\" }}")
    if current!=desired:
        _run(["podman","rm","-f",name],False); _run(_create_args(sid,svc))
    if svc["runtime"].get("startPolicy")=="boot": _run(["podman","start",name],False)
    return {**plan,"state":status_podman(sid,svc)["state"]}
def remove_podman(sid:str,svc:dict[str,Any]|None=None,*,dry_run:bool=False)->None:
    if dry_run:return
    name=container_name(sid,svc or {"runtime":{}}); _run(["podman","rm","-f",name],False); remove_network(sid)
def action_podman(sid:str,svc:dict[str,Any],action:str)->dict[str,Any]:
    if action not in {"start","stop","restart"}: raise RuntimeError("invalid container action")
    if action=="start": ensure_network(sid)
    r=_run(["podman",action,container_name(sid,svc)],False)
    if r.returncode: raise RuntimeError((r.stderr or r.stdout or "podman action failed")[:1000])
    return {"runtime":"container","action":action,"state":status_podman(sid,svc)["state"]}
def status_podman(sid:str,svc:dict[str,Any])->dict[str,Any]:
    name=container_name(sid,svc); r=_run(["podman","inspect","--format","{{.State.Status}}",name],False)
    return {"runtime":"container","name":name,"state":r.stdout.strip() if r.returncode==0 else "absent"}
