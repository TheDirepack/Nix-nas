#!/usr/bin/env python3
"""firewalld adapter for NAS-managed containers, Compose apps, and VMs."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import pathlib
import shutil
import xml.etree.ElementTree as ET
from typing import Any, Mapping

from nas_common import run_command

STATE_PATH = pathlib.Path(os.environ.get("NAS_MANAGED_FIREWALL_STATE", "/var/lib/nas-firewall/managed-services.json"))
TRUSTED_ZONE = os.environ.get("NAS_MANAGED_FIREWALL_ZONE", "nas-trusted")
FIREWALL_REQUIRED = os.environ.get("NAS_MANAGED_FIREWALL_REQUIRED", "0") == "1"
PRIVATE_DESTINATIONS = (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
    "fc00::/7", "fe80::/10",
)

class FirewallError(RuntimeError):
    pass

def _run(argv: list[str], *, check: bool = True):
    result = run_command(argv, timeout_seconds=120, max_output_bytes=512 * 1024)
    if check and result.returncode:
        raise FirewallError((result.stderr or result.stdout or "firewalld command failed")[:1200])
    return result

def _short(value: str, length: int = 10) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:length]

def zone_name(service_id: str) -> str:
    return "nas-" + _short(service_id, 10)

def _podman_interface(service_id: str) -> str:
    return "np" + _short(service_id, 10)

def _vm_bridge(service_id: str) -> str:
    return "nv" + _short(service_id, 10)

def _validate_cidr(value: str) -> str:
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError as exc:
        raise FirewallError(f"invalid CIDR {value!r}: {exc}") from exc

def _xml(root: ET.Element) -> str:
    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="unicode") + "\n"

def _rule(parent: ET.Element, cidr: str, action: str, priority: int, *, port: int | None = None, protocol: str | None = None) -> None:
    network = ipaddress.ip_network(_validate_cidr(cidr), strict=False)
    node = ET.SubElement(parent, "rule", {"family": "ipv6" if network.version == 6 else "ipv4", "priority": str(priority)})
    ET.SubElement(node, "destination", {"address": str(network)})
    if port is not None and protocol is not None:
        ET.SubElement(node, "port", {"port": str(int(port)), "protocol": protocol})
    ET.SubElement(node, action)

def _zone_xml(service_id: str, service: Mapping[str, Any]) -> str:
    root = ET.Element("zone")
    ET.SubElement(root, "interface", {"name": _vm_bridge(service_id) if service.get("runtime", {}).get("type") == "vm" else _podman_interface(service_id)})
    return _xml(root)

def _egress_xml(service_id: str, service: Mapping[str, Any]) -> str:
    network = service.get("network") or {}; default = str(network.get("outboundDefault") or "allow")
    root = ET.Element("policy", {"target": "ACCEPT" if default == "allow" else "REJECT", "priority": "100"})
    ET.SubElement(root, "ingress-zone", {"name": zone_name(service_id)}); ET.SubElement(root, "egress-zone", {"name": "ANY"})
    for allowed in network.get("allowedEgress", []) or []:
        protocols = ("tcp", "udp") if allowed.get("protocol", "any") == "any" else (str(allowed.get("protocol")),)
        if allowed.get("ports"):
            for port in allowed["ports"]:
                for proto in protocols: _rule(root, str(allowed["cidr"]), "accept", -200, port=int(port), protocol=proto)
        else: _rule(root, str(allowed["cidr"]), "accept", -200)
    if default == "allow" and network.get("lanAccess") is False:
        for cidr in PRIVATE_DESTINATIONS: _rule(root, cidr, "reject", -100)
    return _xml(root)

def _host_xml(service_id: str, service: Mapping[str, Any]) -> str:
    network = service.get("network") or {}; root = ET.Element("policy", {"target": "ACCEPT" if network.get("hostAccess") is True else "REJECT", "priority": "50"})
    ET.SubElement(root, "ingress-zone", {"name": zone_name(service_id)}); ET.SubElement(root, "egress-zone", {"name": "HOST"})
    return _xml(root)

def _service_xml(source_id: str, target_id: str, rule: Mapping[str, Any]) -> str:
    ports=rule.get("ports") or []; root=ET.Element("policy", {"target":"ACCEPT" if not ports else "REJECT", "priority":"-100"})
    ET.SubElement(root,"ingress-zone",{"name":zone_name(source_id)}); ET.SubElement(root,"egress-zone",{"name":zone_name(target_id)})
    for port in ports:
        for proto in (("tcp","udp") if rule.get("protocol","any")=="any" else (str(rule.get("protocol")),)):
            node=ET.SubElement(root,"rule",{"priority":"-200"}); ET.SubElement(node,"port",{"port":str(int(port)),"protocol":proto}); ET.SubElement(node,"accept")
    return _xml(root)

def _documents(effective: Mapping[str, Any]) -> dict[pathlib.Path, str]:
    services=effective.get("services") or {}; enabled={sid for sid,svc in services.items() if not svc.get("builtin") and svc.get("enabled") and svc.get("runtime",{}).get("type") in {"container","compose","vm"}}
    docs={}
    for sid in sorted(enabled):
        svc=services[sid]; docs[pathlib.Path("zones")/f"{zone_name(sid)}.xml"]=_zone_xml(sid,svc); docs[pathlib.Path("policies")/f"nae{_short(sid,11)}.xml"]=_egress_xml(sid,svc); docs[pathlib.Path("policies")/f"nah{_short(sid,11)}.xml"]=_host_xml(sid,svc)
        for rule in (svc.get("network") or {}).get("allowedServices",[]) or []:
            target=str(rule["service"])
            if target not in enabled: raise FirewallError(f"service {sid}: allowedServices target {target!r} is not enabled")
            docs[pathlib.Path("policies")/f"nap{_short(sid+'>'+target,11)}.xml"]=_service_xml(sid,target,rule)
    return docs

def _rich_rule(cidr: str, action: str, *, port: int | None = None, protocol: str | None = None) -> str:
    net=ipaddress.ip_network(_validate_cidr(cidr),strict=False); parts=["rule",f"family={'ipv6' if net.version==6 else 'ipv4'}",f"destination address={net}"]
    if port is not None and protocol is not None: parts += [f"port port={int(port)} protocol={protocol}"]
    parts.append(action); return " ".join(parts)

def _policy(name: str, ingress: str, egress: str, target: str, priority: int) -> dict[str, Any]:
    return {"name":name,"ingress":ingress,"egress":egress,"target":target,"priority":priority,"services":[],"rich":[],"masquerade":False}

def _desired_spec(effective: Mapping[str, Any]) -> dict[str, Any]:
    services=effective.get("services") or {}; enabled={sid for sid,svc in services.items() if not svc.get("builtin") and svc.get("enabled") and svc.get("runtime",{}).get("type") in {"container","compose","vm"}}
    zones={}; policies={}; raw=[]
    for sid in sorted(enabled):
        svc=services[sid]; typ=svc["runtime"]["type"]; z=zone_name(sid); zones[z]=_vm_bridge(sid) if typ=="vm" else _podman_interface(sid); net=svc.get("network") or {}; default=str(net.get("outboundDefault") or "allow")
        e=_policy(f"nae{_short(sid,11)}",z,"ANY","ACCEPT" if default=="allow" else "REJECT",100)
        if typ=="vm" and default=="allow": e["masquerade"]=True
        for allowed in net.get("allowedEgress",[]) or []:
            protocols=("tcp","udp") if allowed.get("protocol","any")=="any" else (str(allowed.get("protocol")),)
            if allowed.get("ports"):
                for port in allowed["ports"]:
                    for proto in protocols:e["rich"].append(_rich_rule(str(allowed["cidr"]),"accept",port=int(port),protocol=proto))
            else:e["rich"].append(_rich_rule(str(allowed["cidr"]),"accept"))
        if default=="allow" and net.get("lanAccess") is False:
            e["rich"].extend(_rich_rule(cidr,"reject") for cidr in PRIVATE_DESTINATIONS)
        policies[e["name"]]=e
        h=_policy(f"nah{_short(sid,11)}",z,"HOST","ACCEPT" if net.get("hostAccess") is True else "REJECT",50)
        if net.get("hostAccess") is not True:
            h["services"].append("dns")
            if typ=="vm":h["services"].extend(["dhcp","dhcpv6"])
        policies[h["name"]]=h
        raw_ports=[ep for ep in (svc.get("endpoints") or {}).values() if (ep.get("exposure") or {}).get("type")=="port" and ep.get("transport") in {"tcp","udp"}]
        if raw_ports:
            p=_policy(f"nai{_short(sid,11)}",TRUSTED_ZONE,z,"REJECT",0)
            for ep in raw_ports:
                proto=str(ep["transport"]); p["rich"].append(f"rule priority=-200 port port={int(ep['targetPort'])} protocol={proto} accept")
                host_port=int((ep.get("exposure") or {})["value"])
                if typ=="vm":raw.append({"kind":"forward","zone":TRUSTED_ZONE,"port":host_port,"protocol":proto,"toPort":int(ep["targetPort"]),"toAddr":str(net["vmAddress"])})
                else:raw.append({"kind":"port","zone":TRUSTED_ZONE,"port":host_port,"protocol":proto})
            policies[p["name"]]=p
        web_ports={int(ep["targetPort"]) for ep in (svc.get("endpoints") or {}).values() if typ=="vm" and ep.get("transport") in {"http","https","ws"} and (ep.get("exposure") or {}).get("type") in {"path","hostname","dns","port"}}
        if web_ports:
            p=_policy(f"nab{_short(sid+':backend',11)}","HOST",z,"REJECT",-50); p["rich"].extend(f"rule priority=-200 port port={port} protocol=tcp accept" for port in sorted(web_ports)); policies[p["name"]]=p
        seen=set()
        for rule in net.get("allowedServices",[]) or []:
            target=str(rule["service"])
            if target not in enabled:raise FirewallError(f"service {sid}: allowedServices target {target!r} is not enabled")
            if target in seen:raise FirewallError(f"service {sid}: duplicate allowedServices target {target}")
            seen.add(target); ports=rule.get("ports") or []; p=_policy(f"nap{_short(sid+'>'+target,11)}",z,zone_name(target),"ACCEPT" if not ports else "REJECT",-100)
            for port in ports:
                for proto in (("tcp","udp") if rule.get("protocol","any")=="any" else (str(rule.get("protocol")),)):p["rich"].append(f"rule priority=-200 port port={int(port)} protocol={proto} accept")
            policies[p["name"]]=p
    return {"zones":zones,"policies":policies,"raw":raw}

def _ignore(argv: list[str]) -> None:
    _run(argv,check=False)

def _raw_argv(rule: Mapping[str, Any], remove: bool) -> list[str]:
    action="remove" if remove else "add"
    if rule["kind"]=="port":return ["firewall-cmd","--permanent",f"--zone={rule['zone']}",f"--{action}-port={rule['port']}/{rule['protocol']}"]
    spec=f"port={rule['port']}:proto={rule['protocol']}:toport={rule['toPort']}:toaddr={rule['toAddr']}";return ["firewall-cmd","--permanent",f"--zone={rule['zone']}",f"--{action}-forward-port={spec}"]

def _apply_spec(spec: Mapping[str, Any], previous: Mapping[str, Any] | None = None) -> None:
    previous=previous or {"zones":{},"policies":{},"raw":[]}
    for rule in previous.get("raw",[]) or []:_ignore(_raw_argv(rule,True))
    for name in sorted(set(previous.get("policies",{})) | set(spec.get("policies",{}))):_ignore(["firewall-cmd","--permanent",f"--delete-policy={name}"])
    for name in sorted(set(previous.get("zones",{})) | set(spec.get("zones",{}))):_ignore(["firewall-cmd","--permanent",f"--delete-zone={name}"])
    for name,iface in sorted((spec.get("zones") or {}).items()):
        _run(["firewall-cmd","--permanent",f"--new-zone={name}"]);_run(["firewall-cmd","--permanent",f"--zone={name}",f"--add-interface={iface}"])
    for name,p in sorted((spec.get("policies") or {}).items()):
        _run(["firewall-cmd","--permanent",f"--new-policy={name}"]);_run(["firewall-cmd","--permanent",f"--policy={name}",f"--set-target={p['target']}"]);_run(["firewall-cmd","--permanent",f"--policy={name}",f"--set-priority={p['priority']}"]);_run(["firewall-cmd","--permanent",f"--policy={name}",f"--add-ingress-zone={p['ingress']}"]);_run(["firewall-cmd","--permanent",f"--policy={name}",f"--add-egress-zone={p['egress']}"])
        if p.get("masquerade"):_run(["firewall-cmd","--permanent",f"--policy={name}","--add-masquerade"])
        for service in p.get("services",[]) or []:_run(["firewall-cmd","--permanent",f"--policy={name}",f"--add-service={service}"])
        for rule in p.get("rich",[]) or []:_run(["firewall-cmd","--permanent",f"--policy={name}",f"--add-rich-rule={rule}"])
    for rule in spec.get("raw",[]) or []:_run(_raw_argv(rule,False))
    check=_run(["firewall-cmd","--check-config"],check=False)
    if check.returncode:raise FirewallError(f"generated permanent firewalld config invalid: {(check.stderr or check.stdout)[:1000]}")
    _run(["firewall-cmd","--reload"])

def _read_state() -> dict[str, Any]:
    try:value=json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (FileNotFoundError,OSError,json.JSONDecodeError):return {"schemaVersion":3,"spec":{"zones":{},"policies":{},"raw":[]}}
    return value if isinstance(value,dict) else {"schemaVersion":3,"spec":{"zones":{},"policies":{},"raw":[]}}

def _write_state(value: Mapping[str, Any]) -> None:
    STATE_PATH.parent.mkdir(parents=True,exist_ok=True);tmp=STATE_PATH.with_name("."+STATE_PATH.name+".tmp");tmp.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n",encoding="utf-8");os.chmod(tmp,0o600);os.replace(tmp,STATE_PATH)

def apply_effective(effective: Mapping[str, Any]) -> dict[str, Any]:
    if shutil.which("firewall-cmd") is None:
        if FIREWALL_REQUIRED:raise FirewallError("firewalld is required for managed workload policy")
        return {"available":False,"zones":[],"policies":[],"rules":[]}
    desired=_desired_spec(effective);previous_state=_read_state();previous=previous_state.get("spec") if isinstance(previous_state.get("spec"),dict) else {"zones":{},"policies":{},"raw":[]}
    if desired==previous:return {"available":True,"changed":False,"zones":sorted(desired["zones"]),"policies":sorted(desired["policies"]),"rules":desired["raw"]}
    try:_apply_spec(desired,previous)
    except Exception as exc:
        try:_apply_spec(previous,desired)
        except Exception as rollback:raise FirewallError(f"firewall reconciliation failed and rollback failed: {rollback}") from exc
        raise
    _write_state({"schemaVersion":3,"spec":desired});return {"available":True,"changed":True,"zones":sorted(desired["zones"]),"policies":sorted(desired["policies"]),"rules":desired["raw"]}

def plan_firewall(service_id: str, service: dict[str, Any]) -> dict[str, Any]:
    return {"service":service_id,"zone":zone_name(service_id),"network":service.get("network",{}),"endpoints":list((service.get("endpoints") or {}).keys())}
def apply_firewall(service_id: str, service: dict[str, Any], *, dry_run: bool=False) -> dict[str, Any]:
    if dry_run:return plan_firewall(service_id,service)
    effective={"services":{service_id:service},"endpoints":{f"{service_id}:{eid}":{**ep,"serviceId":service_id,"runtimeType":service.get("runtime",{}).get("type"),"available":bool(service.get("enabled")),"builtin":False} for eid,ep in (service.get("endpoints") or {}).items()}}
    return apply_effective(effective)
def remove_firewall(service_id: str, *, dry_run: bool=False) -> None:
    if dry_run:return
    state=_read_state();spec=state.get("spec") if isinstance(state.get("spec"),dict) else {"zones":{},"policies":{},"raw":[]};z=zone_name(service_id);desired={"zones":{k:v for k,v in spec.get("zones",{}).items() if k!=z},"policies":{k:v for k,v in spec.get("policies",{}).items() if v.get("ingress")!=z and v.get("egress")!=z},"raw":list(spec.get("raw",[]))};_apply_spec(desired,spec);_write_state({"schemaVersion":3,"spec":desired})
