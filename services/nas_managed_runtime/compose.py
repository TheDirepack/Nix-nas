#!/usr/bin/env python3
"""Podman Compose adapter with safety scanning and generated NAS override."""
from __future__ import annotations
import copy, os, pathlib
from typing import Any
import yaml
from nas_common import run_command
from nas_managed_runtime import podman

SOCKET_PATHS=("/var/run/docker.sock","/run/docker.sock","/run/podman/podman.sock")

def _run(argv:list[str],check:bool=True):
    r=run_command(argv,timeout_seconds=600,max_output_bytes=1024*1024,env={"PODMAN_COMPOSE_WARNING_LOGS":"false"})
    if check and r.returncode: raise RuntimeError((r.stderr or r.stdout or "podman compose failed")[:1200])
    return r

def validate_compose(value:dict[str,Any])->dict[str,Any]:
    if not isinstance(value,dict) or not isinstance(value.get("services"),dict) or not value["services"]: raise RuntimeError("Compose source must define services")
    if value.get("include") is not None: raise RuntimeError("Compose include must be flattened before import")
    for name,svc in value["services"].items():
        if not isinstance(svc,dict): raise RuntimeError(f"Compose service {name} must be an object")
        if svc.get("privileged") is True or svc.get("network_mode")=="host" or svc.get("pid")=="host" or svc.get("ipc")=="host": raise RuntimeError(f"Compose service {name} requests a forbidden host privilege")
        if svc.get("extends") is not None: raise RuntimeError("Compose extends must be flattened before import")
        if svc.get("ports"): raise RuntimeError(f"Compose service {name} publishes ports; declare NAS endpoints instead")
        for volume in svc.get("volumes",[]) or []:
            text=volume if isinstance(volume,str) else str(volume.get("source", "")) if isinstance(volume,dict) else ""
            if any(sock in text for sock in SOCKET_PATHS): raise RuntimeError(f"Compose service {name} mounts a container runtime socket")
    for net in (value.get("networks") or {}).values():
        if isinstance(net,dict) and net.get("external") is True: raise RuntimeError("external Compose networks are not allowed")
    return value

def validate_compose_text(text:str)->dict[str,Any]:
    try:value=yaml.safe_load(text)
    except yaml.YAMLError as exc: raise RuntimeError(f"invalid Compose YAML: {exc}") from exc
    return validate_compose(value)
def _source(svc:dict[str,Any])->pathlib.Path:return pathlib.Path(svc["runtime"]["source"])
def _generated(sid:str)->pathlib.Path:return _source_path_root(sid)/"compose.generated.yaml"
def _source_path_root(sid:str)->pathlib.Path:return pathlib.Path(os.environ.get("NAS_MANAGED_APP_ROOT","/var/lib/nas-control/apps"))/sid

def render_generated(sid:str,svc:dict[str,Any])->pathlib.Path:
    source=_source(svc)
    try:value=validate_compose_text(source.read_text(encoding="utf-8"))
    except OSError as exc: raise RuntimeError(f"unable to read Compose source: {exc}") from exc
    out=copy.deepcopy(value); out.pop("name",None); services=out["services"]
    networks=out.setdefault("networks",{})
    for name,net in list(networks.items()):
        if not isinstance(net,dict): net={}; networks[name]=net
        net["internal"]=True
    networks["nas-managed"]={"external":True,"name":podman.network_name(sid)}
    for name,item in services.items():
        item.setdefault("networks",[])
        if isinstance(item["networks"],list):
            if "nas-managed" not in item["networks"]: item["networks"].append("nas-managed")
        elif isinstance(item["networks"],dict): item["networks"].setdefault("nas-managed",{})
        env=item.setdefault("environment",{})
        if isinstance(env,dict): env.update(svc["runtime"].get("environment") or {})
    for mount in svc.get("storage",[]) or []:
        target=mount.get("targetService") or next(iter(services)); services[target].setdefault("volumes",[]).append(f"{mount['hostPath']}:{mount['guestPath']}:{mount['mode']}")
    for ep in svc.get("endpoints",{}).values():
        hp=ep.get("hostPort")
        if not hp: continue
        target=ep.get("targetService") or next(iter(services)); transport=ep.get("transport","tcp"); proto="udp" if transport=="udp" else "tcp"; web=transport in {"http","https","ws"}; bind="127.0.0.1" if web else "0.0.0.0"
        services[target].setdefault("ports",[]).append(f"{bind}:{int(hp)}:{int(ep['targetPort'])}/{proto}")
    resources=svc.get("resources") or {}
    if len(services)==1:
        item=next(iter(services.values()))
        if resources.get("memoryBytes"): item["mem_limit"]=int(resources["memoryBytes"])
        if resources.get("cpus"): item["cpus"]=float(resources["cpus"])
        for dev in resources.get("gpus",[]) or []: item.setdefault("devices",[]).append(str(dev))
    target=_generated(sid); target.parent.mkdir(parents=True,exist_ok=True); text=yaml.safe_dump(out,sort_keys=False)
    tmp=target.with_name("."+target.name+".tmp"); tmp.write_text(text,encoding="utf-8"); os.chmod(tmp,0o600); os.replace(tmp,target); return target

def _base(sid:str,svc:dict[str,Any])->list[str]:return ["podman","compose","-p",str(svc["runtime"].get("project") or sid),"-f",str(_generated(sid))]
def plan_compose(sid:str,svc:dict[str,Any])->dict[str,Any]:return {"service":sid,"runtime":"compose","source":str(_source(svc)),"generated":str(_generated(sid)),"network":podman.network_name(sid)}
def apply_compose(sid:str,svc:dict[str,Any],*,dry_run:bool=False)->dict[str,Any]:
    plan=plan_compose(sid,svc)
    if dry_run:return plan
    if not svc.get("enabled") or svc["runtime"].get("startPolicy")=="disabled": remove_compose(sid,svc); return {**plan,"state":"disabled"}
    podman.ensure_network(sid); render_generated(sid,svc); _run([*_base(sid,svc),"config","--quiet"])
    if svc["runtime"].get("startPolicy")=="boot": _run([*_base(sid,svc),"up","-d","--remove-orphans"])
    return {**plan,"state":status_compose(sid,svc)["state"]}
def remove_compose(sid:str,svc:dict[str,Any]|None=None,*,dry_run:bool=False)->None:
    if dry_run:return
    if svc is not None and _generated(sid).exists(): _run([*_base(sid,svc),"down","--remove-orphans"],False)
    podman.remove_network(sid)
def action_compose(sid:str,svc:dict[str,Any],action:str)->dict[str,Any]:
    if not _generated(sid).exists(): podman.ensure_network(sid); render_generated(sid,svc)
    cmd={"start":["up","-d"],"stop":["stop"],"restart":["restart"]}.get(action)
    if cmd is None: raise RuntimeError("invalid Compose action")
    _run([*_base(sid,svc),*cmd]); return {"runtime":"compose","action":action,"state":status_compose(sid,svc)["state"]}
def status_compose(sid:str,svc:dict[str,Any])->dict[str,Any]:
    if not _generated(sid).exists(): return {"runtime":"compose","state":"absent"}
    r=_run([*_base(sid,svc),"ps","--status","running","-q"],False); return {"runtime":"compose","state":"running" if r.returncode==0 and r.stdout.strip() else "stopped"}
