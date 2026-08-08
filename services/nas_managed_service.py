#!/usr/bin/env python3
"""Public one-shot managed-service controller and compatibility surface."""
from __future__ import annotations
import argparse, copy, hashlib, json, os, pathlib, sys, tempfile, xml.etree.ElementTree as ET
from typing import Any, Callable, Mapping
import yaml
from nas_operation_journal import OperationJournal, JournalError
from nas_operation_lock import OperationBusyError, acquire_operation
from nas_managed_runtime import model as _model, registry as _registry
STORE_PATH=_model.STORE_PATH;BUILTIN_REGISTRY=_model.BUILTIN_REGISTRY;EFFECTIVE_PATH=_model.EFFECTIVE_PATH;PORTAL_PATH=_model.PORTAL_PATH;SCHEMA_PATH=_model.SCHEMA_PATH;APP_ROOT=_model.APP_ROOT;JOURNAL_PATH=_model.JOURNAL_PATH;LAN_HOST=_model.LAN_HOST;HOST_PORT_MIN=_model.HOST_PORT_MIN;HOST_PORT_MAX=_model.HOST_PORT_MAX;VM_POOL=_model.VM_POOL;SCHEMA_VERSION=_model.SCHEMA_VERSION;SERVICE_ID_RE=_model.SERVICE_ID_RE;ENDPOINT_ID_RE=_model.ENDPOINT_ID_RE;HOSTNAME_RE=_model.HOSTNAME_RE;IMAGE_RE=_model.IMAGE_RE;UNIT_RE=_model.UNIT_RE;NAME_RE=_model.NAME_RE;ALLOWED_HOST_ROOTS=_model.ALLOWED_HOST_ROOTS;PROTECTED_ROOTS=_model.PROTECTED_ROOTS;ManagedServiceError=_model.ManagedServiceError
def _sync_modules()->None:
    for name in ("STORE_PATH","BUILTIN_REGISTRY","EFFECTIVE_PATH","PORTAL_PATH","SCHEMA_PATH","APP_ROOT","JOURNAL_PATH","LAN_HOST","HOST_PORT_MIN","HOST_PORT_MAX","VM_POOL","ALLOWED_HOST_ROOTS","PROTECTED_ROOTS"):
        value=globals()[name];setattr(_model,name,value);setattr(_registry,name,value)
def _under(path,path_root):_sync_modules();return _model._under(path,path_root)
def _host_path(value):_sync_modules();return _model._host_path(value)
def _port(value):_sync_modules();return _model._port(value)
def _hostname(value):_sync_modules();return _model._hostname(value)
def _validate_port(value):_sync_modules();return _model._validate_port(value)
def _validate_hostname(value):_sync_modules();return _model._validate_hostname(value)
def _validate_image(value):_sync_modules();return _model._validate_image(value)
def _source(service_id,value):_sync_modules();return _model._source(service_id,value)
def normalize_service(service_id,raw):_sync_modules();return _model.normalize_service(service_id,raw)
def normalize_store(raw):_sync_modules();return _registry.normalize_store(raw)
def load_store(path=None):_sync_modules();return _registry.load_store(path)
def atomic_write_store(store,path=None):_sync_modules();return _registry.atomic_write_store(store,path)
def allocate_runtime_addresses(store):_sync_modules();return _registry.allocate_runtime_addresses(store)
def effective_registry(builtin_path=None,store_path=None):_sync_modules();return _registry.effective_registry(builtin_path,store_path)
def validate_conflicts(effective):_sync_modules();return _registry.validate_conflicts(effective)
def portal_projection(effective=None):_sync_modules();return _registry.portal_projection(effective)
def _write_projection(path,value,mode=0o644):_sync_modules();return _registry._write_projection(path,value,mode)
def validate_service(service_id,data):_sync_modules();return _registry.validate_service(service_id,data)
def write_effective(builtin_path=None,store_path=None,effective_path=None):_sync_modules();return _registry.write_effective(builtin_path,store_path,effective_path)
def write_portal(effective_path=None,portal_path=None):_sync_modules();return _registry.write_portal(effective_path,portal_path)
def _runtime_module(typ:str):
    if typ=="container":from nas_managed_runtime import podman as mod
    elif typ=="compose":from nas_managed_runtime import compose as mod
    elif typ=="vm":from nas_managed_runtime import libvirt as mod
    else:return None
    return mod
def _remove_runtime(sid:str,svc:Mapping[str,Any])->None:
    typ=svc.get("runtime",{}).get("type");mod=_runtime_module(str(typ))
    if mod is not None:getattr(mod,{"container":"remove_podman","compose":"remove_compose","vm":"remove_libvirt"}[typ])(sid,dict(svc))
    elif typ=="native":
        from nas_common import run_command;run_command(["systemctl","stop",str(svc["runtime"]["systemdUnit"])],timeout_seconds=120)
def _apply_runtime(sid:str,svc:Mapping[str,Any])->dict[str,Any]:
    typ=svc["runtime"]["type"];mod=_runtime_module(typ)
    if mod is not None:return getattr(mod,{"container":"apply_podman","compose":"apply_compose","vm":"apply_libvirt"}[typ])(sid,dict(svc))
    if typ=="native":
        from nas_common import run_command
        unit=svc["runtime"]["systemdUnit"]
        if not svc["enabled"] or svc["runtime"]["startPolicy"]=="disabled":run_command(["systemctl","stop",unit],timeout_seconds=120);return {"runtime":"native","state":"disabled"}
        if svc["runtime"]["startPolicy"]=="boot":
            result=run_command(["systemctl","start",unit],timeout_seconds=120)
            if result.returncode:raise ManagedServiceError(f"failed to start {unit}")
        return {"runtime":"native","unit":unit}
    return {"runtime":"external","state":"external"}
def _runtime_status(sid:str,svc:Mapping[str,Any])->dict[str,Any]:
    typ=svc["runtime"]["type"];mod=_runtime_module(typ)
    if mod is not None:return getattr(mod,{"container":"status_podman","compose":"status_compose","vm":"status_libvirt"}[typ])(sid,dict(svc))
    if typ=="native":
        from nas_common import run_command;r=run_command(["systemctl","is-active",svc["runtime"]["systemdUnit"]],timeout_seconds=30);return {"runtime":"native","state":r.stdout.strip() or "inactive"}
    return {"runtime":typ,"state":"external"}
def _runtime_action(sid:str,svc:Mapping[str,Any],action:str)->dict[str,Any]:
    typ=svc["runtime"]["type"];mod=_runtime_module(typ)
    if mod is not None:return getattr(mod,{"container":"action_podman","compose":"action_compose","vm":"action_libvirt"}[typ])(sid,dict(svc),action)
    if typ=="native":
        from nas_common import run_command;r=run_command(["systemctl",action,svc["runtime"]["systemdUnit"]],timeout_seconds=120)
        if r.returncode:raise ManagedServiceError(f"systemctl {action} failed")
        return {"runtime":"native","action":action}
    raise ManagedServiceError(f"runtime {typ} does not support lifecycle actions")
def reconcile(*,include_runtime:bool=True)->dict[str,Any]:
    store=load_store();before=json.dumps(store,sort_keys=True);allocate_runtime_addresses(store)
    if json.dumps(store,sort_keys=True)!=before:store["generation"]+=1;atomic_write_store(store)
    effective=write_effective();validate_conflicts(effective)
    from nas_managed_runtime import authentik,firewall
    authentik_result={sid:authentik.apply_authentik(sid,svc) for sid,svc in sorted(store["services"].items())};firewall_result=firewall.apply_effective(effective);runtime={}
    if include_runtime:
        for sid,svc in sorted(store["services"].items()):runtime[sid]=_apply_runtime(sid,svc)
    for sid,svc in store["services"].items():
        status=_runtime_status(sid,svc);state=str(status.get("state",""));available=svc["enabled"] and svc["runtime"]["startPolicy"]!="disabled" and (state in {"running","active","external"} or svc["runtime"]["startPolicy"]=="manual")
        for eid in svc["endpoints"]:
            key=f"{sid}:{eid}"
            if key in effective["endpoints"]:effective["endpoints"][key]["available"]=available
    if effective.get("endpoints"):
        _write_projection(EFFECTIVE_PATH,effective);portal=write_portal();import nas_service_caddy as caddy;caddy_result=caddy.write_caddy_fragments(effective)
    else:portal=write_portal();caddy_result={"changed":False,"pathFragment":None,"hostFragment":None}
    return {"ok":True,"effective":effective,"portal":portal,"runtime":runtime,"authentik":authentik_result,"firewall":firewall_result,"caddy":caddy_result}
def _read_definition(source:str)->dict[str,Any]:
    try:text=sys.stdin.read() if source=="-" else pathlib.Path(source).read_text(encoding="utf-8")
    except OSError as exc:raise ManagedServiceError(f"unable to read {source}: {exc}") from exc
    try:value=yaml.safe_load(text)
    except yaml.YAMLError as exc:raise ManagedServiceError(f"invalid YAML/JSON: {exc}") from exc
    if not isinstance(value,dict):raise ManagedServiceError("service definition must be an object")
    return value
def _candidate(store:Mapping[str,Any],sid:str,svc:Mapping[str,Any])->dict[str,Any]:
    out=copy.deepcopy(dict(store));normalized=normalize_service(sid,svc);previous=out["services"].get(sid);normalized["generation"]=(int(previous.get("generation",0))+1 if isinstance(previous,dict) else 1);out["services"][sid]=normalized;out["generation"]=int(out.get("generation",1))+1;allocate_runtime_addresses(out);return normalize_store(out)
def _transaction(action:str,mutate:Callable[[dict[str,Any]],dict[str,Any]])->dict[str,Any]:
    with acquire_operation(f"managed-service:{action}",( "runtime","network","state"),blocking=False):
        old=load_store();new=mutate(copy.deepcopy(old));fingerprint=hashlib.sha256(json.dumps(new,sort_keys=True).encode()).hexdigest();journal=OperationJournal.open(JOURNAL_PATH,workflow="managed-service",fingerprint=fingerprint,metadata={"action":action})
        try:
            journal.start_step("persist");atomic_write_store(new);journal.complete_step("persist")
            for sid,oldsvc in old["services"].items():
                newsvc=new["services"].get(sid)
                if newsvc is None or newsvc["runtime"]["type"]!=oldsvc["runtime"]["type"]:_remove_runtime(sid,oldsvc)
            journal.start_step("reconcile");result=reconcile();journal.complete_step("reconcile",{"ok":True});journal.complete({"action":action});return result
        except Exception as exc:
            rollback_errors=[]
            try:atomic_write_store(old);reconcile()
            except Exception as rb:rollback_errors.append(str(rb))
            journal.fail(str(exc),manual_recovery=bool(rollback_errors))
            if rollback_errors:raise ManagedServiceError(f"{action} failed and rollback was incomplete: {rollback_errors[0]}") from exc
            raise
def create_service(sid:str,svc:Mapping[str,Any])->dict[str,Any]:
    def mutate(store):
        if sid in store["services"]:raise ManagedServiceError(f"service {sid} already exists")
        return _candidate(store,sid,svc)
    return _transaction(f"create:{sid}",mutate)
def update_service(sid:str,svc:Mapping[str,Any])->dict[str,Any]:
    def mutate(store):
        if sid not in store["services"]:raise ManagedServiceError(f"unknown service {sid}")
        return _candidate(store,sid,svc)
    return _transaction(f"update:{sid}",mutate)
def delete_service(sid:str)->dict[str,Any]:
    def mutate(store):
        if sid not in store["services"]:raise ManagedServiceError(f"unknown service {sid}")
        del store["services"][sid];store["generation"]+=1;return normalize_store(store)
    return _transaction(f"delete:{sid}",mutate)
def plan_service(sid:str,svc:Mapping[str,Any])->dict[str,Any]:
    store=load_store();candidate=_candidate(store,sid,svc);after=candidate["services"][sid];return {"service":sid,"operation":"update" if sid in store["services"] else "create","before":store["services"].get(sid),"after":after,"effects":{"runtime":after["runtime"]["type"],"endpoints":sorted(after["endpoints"]),"mounts":len(after["storage"]),"network":after["network"]}}
def stage_source(sid:str,kind:str,source:str="-")->dict[str,Any]:
    if SERVICE_ID_RE.fullmatch(sid) is None or kind not in {"compose","vm"}:raise ManagedServiceError("invalid stage-source request")
    text=sys.stdin.read() if source=="-" else pathlib.Path(source).read_text(encoding="utf-8")
    if len(text.encode())>2*1024*1024:raise ManagedServiceError("source exceeds 2 MiB")
    directory=APP_ROOT/sid;directory.mkdir(parents=True,exist_ok=True,mode=0o700);target=directory/("compose.yaml" if kind=="compose" else "domain.xml")
    if kind=="compose":
        from nas_managed_runtime import compose;compose.validate_compose_text(text)
    else:
        try:root=ET.fromstring(text)
        except ET.ParseError as exc:raise ManagedServiceError(f"invalid libvirt XML: {exc}") from exc
        if root.tag!="domain" or root.findall(".//hostdev"):raise ManagedServiceError("VM source must be a domain XML without unmanaged hostdev passthrough")
    fd,name=tempfile.mkstemp(prefix=f".{target.name}.",dir=directory)
    with os.fdopen(fd,"w",encoding="utf-8") as h:h.write(text);h.flush();os.fsync(h.fileno())
    os.chmod(name,0o600);os.replace(name,target);return {"ok":True,"path":str(target)}
def list_services()->dict[str,Any]:
    store=load_store();return {"schemaVersion":2,"generation":store["generation"],"services":[{"id":sid,"label":svc["label"],"enabled":svc["enabled"],"runtime":svc["runtime"]["type"],"startPolicy":svc["runtime"]["startPolicy"],"generation":svc["generation"]} for sid,svc in sorted(store["services"].items())]}
def service_status(sid:str)->dict[str,Any]:
    store=load_store();svc=store["services"].get(sid)
    if not isinstance(svc,dict):raise ManagedServiceError(f"unknown service {sid}")
    return {"id":sid,"enabled":svc["enabled"],**_runtime_status(sid,svc)}
def export_services(sid:str|None=None)->dict[str,Any]:
    store=load_store()
    if sid is None:return store
    if sid not in store["services"]:raise ManagedServiceError(f"unknown service {sid}")
    return {"schemaVersion":2,"serviceId":sid,"service":store["services"][sid]}
def import_services(source:str,*,replace:bool=False)->dict[str,Any]:
    doc=_read_definition(source)
    if doc.get("schemaVersion")!=2 or not isinstance(doc.get("services"),dict):raise ManagedServiceError("import requires a complete schemaVersion=2 store export")
    incoming=normalize_store(doc)
    def mutate(store):
        if replace:out=incoming
        else:
            out=copy.deepcopy(store)
            for sid,svc in incoming["services"].items():
                if sid in out["services"]:raise ManagedServiceError(f"import conflicts with {sid}")
                out["services"][sid]=svc
        out["generation"]=max(int(store["generation"]),int(incoming["generation"]))+1;allocate_runtime_addresses(out);return normalize_store(out)
    return _transaction("import",mutate)
def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser(prog="nas-managed-service");sub=p.add_subparsers(dest="command",required=True);r=sub.add_parser("reconcile");r.add_argument("--no-runtime",action="store_true");sub.add_parser("validate");sub.add_parser("list");show=sub.add_parser("show");show.add_argument("service",nargs="?");show.add_argument("--json",action="store_true")
    for name in ("plan","create","update"):q=sub.add_parser(name);q.add_argument("service");q.add_argument("definition")
    q=sub.add_parser("delete");q.add_argument("service")
    for name in ("start","stop","restart","status"):q=sub.add_parser(name);q.add_argument("service")
    q=sub.add_parser("stage-source");q.add_argument("service");q.add_argument("kind",choices=["compose","vm"]);q.add_argument("source",nargs="?",default="-");q=sub.add_parser("export");q.add_argument("service",nargs="?");q=sub.add_parser("import");q.add_argument("definition");q.add_argument("--replace",action="store_true");a=p.parse_args(argv)
    try:
        if a.command=="reconcile":result=reconcile(include_runtime=not a.no_runtime)
        elif a.command=="validate":result={"ok":True,"store":load_store(),"effective":effective_registry()}
        elif a.command=="list":result=list_services()
        elif a.command=="show":
            if a.service:
                s=load_store()
                if a.service not in s["services"]:raise ManagedServiceError(f"unknown service {a.service}")
                result={"id":a.service,**s["services"][a.service]}
            else:result=effective_registry()
        elif a.command in {"plan","create","update"}:
            definition=_read_definition(a.definition);result=plan_service(a.service,definition) if a.command=="plan" else create_service(a.service,definition) if a.command=="create" else update_service(a.service,definition)
        elif a.command=="delete":result=delete_service(a.service)
        elif a.command=="stage-source":result=stage_source(a.service,a.kind,a.source)
        elif a.command=="export":result=export_services(a.service)
        elif a.command=="import":result=import_services(a.definition,replace=a.replace)
        elif a.command=="status":result=service_status(a.service)
        else:
            store=load_store();svc=store["services"].get(a.service)
            if not isinstance(svc,dict):raise ManagedServiceError(f"unknown service {a.service}")
            with acquire_operation(f"managed-service:{a.command}:{a.service}",( "runtime",),blocking=False):result=_runtime_action(a.service,svc,a.command)
            result["reconcile"]=reconcile(include_runtime=False)
        print(json.dumps(result,indent=2,sort_keys=True));return 0
    except (ManagedServiceError,OperationBusyError,JournalError,OSError,StopIteration) as exc:print(f"nas-managed-service: {exc}",file=sys.stderr);return 1
if __name__=="__main__":raise SystemExit(main())
