#!/usr/bin/env python3
"""libvirt/QEMU adapter with one NAS-managed NIC and virtiofs shares."""
from __future__ import annotations
import hashlib, os, pathlib, re, xml.etree.ElementTree as ET
from typing import Any
from nas_common import run_command

BDF_RE=re.compile(r"(?i)^([0-9a-f]{4}):([0-9a-f]{2}):([0-9a-f]{2})\.([0-7])$")

def _run(argv:list[str],check:bool=True):
    r=run_command(argv,timeout_seconds=300,max_output_bytes=512*1024)
    if check and r.returncode: raise RuntimeError((r.stderr or r.stdout or "virsh command failed")[:1000])
    return r
def vm_name(sid:str,svc:dict[str,Any])->str:return str(svc.get("runtime",{}).get("name") or f"nas-{sid}")
def network_name(sid:str)->str:return f"nas-{sid}"
def bridge_name(sid:str)->str:return "nv"+hashlib.sha256(sid.encode()).hexdigest()[:10]
def _network_exists(sid:str)->bool:return _run(["virsh","net-info",network_name(sid)],False).returncode==0

def _network_xml(sid:str,svc:dict[str,Any])->str:
    net=svc["network"]; import ipaddress
    network=ipaddress.ip_network(net["vmSubnet"],strict=True); gateway=str(network.network_address+1)
    root=ET.Element("network"); ET.SubElement(root,"name").text=network_name(sid); ET.SubElement(root,"forward",{"mode":"open"}); ET.SubElement(root,"bridge",{"name":bridge_name(sid),"stp":"on","delay":"0","zone":"nas-"+hashlib.sha256(sid.encode()).hexdigest()[:10]})
    ip=ET.SubElement(root,"ip",{"address":gateway,"prefix":str(network.prefixlen)}); dhcp=ET.SubElement(ip,"dhcp"); ET.SubElement(dhcp,"range",{"start":str(network.network_address+10),"end":str(network.broadcast_address-2)}); ET.SubElement(dhcp,"host",{"mac":net["vmMac"],"name":sid,"ip":net["vmAddress"]})
    return ET.tostring(root,encoding="unicode")+"\n"
def ensure_network(sid:str,svc:dict[str,Any])->None:
    root=pathlib.Path(os.environ.get("NAS_MANAGED_APP_ROOT","/var/lib/nas-control/apps"))/sid; root.mkdir(parents=True,exist_ok=True); xml=root/"network.generated.xml"; xml.write_text(_network_xml(sid,svc),encoding="utf-8"); os.chmod(xml,0o600)
    if not _network_exists(sid): _run(["virsh","net-define",str(xml)])
    _run(["virsh","net-autostart",network_name(sid)],False); _run(["virsh","net-start",network_name(sid)],False)
def remove_network(sid:str)->None:
    _run(["virsh","net-destroy",network_name(sid)],False); _run(["virsh","net-undefine",network_name(sid)],False)

def _gpu_hostdev(devices:ET.Element,bdf:str)->None:
    m=BDF_RE.fullmatch(bdf)
    if m is None: raise RuntimeError(f"invalid GPU PCI BDF {bdf}")
    class_path=pathlib.Path("/sys/bus/pci/devices")/bdf.lower()/"class"
    if class_path.exists() and not class_path.read_text(encoding="ascii").strip().lower().startswith("0x03"): raise RuntimeError(f"{bdf} is not a display controller")
    hostdev=ET.SubElement(devices,"hostdev",{"mode":"subsystem","type":"pci","managed":"yes"}); source=ET.SubElement(hostdev,"source"); ET.SubElement(source,"address",{"domain":f"0x{m.group(1)}","bus":f"0x{m.group(2)}","slot":f"0x{m.group(3)}","function":f"0x{m.group(4)}"})
def render_domain(sid:str,svc:dict[str,Any])->pathlib.Path:
    source=pathlib.Path(svc["runtime"]["source"])
    try:root=ET.parse(source).getroot()
    except (OSError,ET.ParseError) as exc: raise RuntimeError(f"unable to read VM domain XML: {exc}") from exc
    if root.tag!="domain": raise RuntimeError("VM source must be a libvirt domain")
    devices=root.find("devices")
    if devices is None: devices=ET.SubElement(root,"devices")
    if any(x.tag=="hostdev" for x in list(devices)): raise RuntimeError("unmanaged hostdev passthrough is forbidden; declare display GPUs through NAS resources")
    for item in list(devices):
        if item.tag in {"interface","filesystem"}: devices.remove(item)
    name=root.find("name")
    if name is None:name=ET.SubElement(root,"name")
    name.text=vm_name(sid,svc)
    resources=svc.get("resources") or {}; memory=root.find("memory")
    if memory is None:memory=ET.SubElement(root,"memory",{"unit":"B"})
    memory.set("unit","B"); memory.text=str(int(resources.get("memoryBytes",2147483648)))
    vcpu=root.find("vcpu")
    if vcpu is None:vcpu=ET.SubElement(root,"vcpu")
    vcpu.text=str(max(1,int(float(resources.get("cpus",2)))))
    metadata=root.find("metadata")
    if metadata is None:metadata=ET.SubElement(root,"metadata")
    owned=ET.SubElement(metadata,"{https://nixos-nas.local/service}service"); ET.SubElement(owned,"{https://nixos-nas.local/service}id").text=sid; ET.SubElement(owned,"{https://nixos-nas.local/service}generation").text=str(svc.get("generation",1))
    interface=ET.SubElement(devices,"interface",{"type":"network"}); ET.SubElement(interface,"mac",{"address":svc["network"]["vmMac"]}); ET.SubElement(interface,"source",{"network":network_name(sid)}); ET.SubElement(interface,"model",{"type":"virtio"})
    for index,mount in enumerate(svc.get("storage",[]) or []):
        fs=ET.SubElement(devices,"filesystem",{"type":"mount","accessmode":"passthrough"}); ET.SubElement(fs,"driver",{"type":"virtiofs"}); ET.SubElement(fs,"source",{"dir":mount["hostPath"]}); ET.SubElement(fs,"target",{"dir":f"nas{index}"})
        if mount["mode"]=="ro": ET.SubElement(fs,"readonly")
    for bdf in resources.get("gpus",[]) or []:_gpu_hostdev(devices,str(bdf))
    ET.indent(root,space="  "); target=source.parent/"domain.generated.xml"; target.write_text(ET.tostring(root,encoding="unicode")+"\n",encoding="utf-8"); os.chmod(target,0o600); return target

def plan_libvirt(sid:str,svc:dict[str,Any])->dict[str,Any]:return {"service":sid,"runtime":"vm","domain":vm_name(sid,svc),"network":network_name(sid),"address":svc.get("network",{}).get("vmAddress")}
def apply_libvirt(sid:str,svc:dict[str,Any],*,dry_run:bool=False)->dict[str,Any]:
    plan=plan_libvirt(sid,svc)
    if dry_run:return plan
    name=vm_name(sid,svc)
    if not svc.get("enabled") or svc["runtime"].get("startPolicy")=="disabled": _run(["virsh","shutdown",name],False); remove_network(sid); return {**plan,"state":"disabled"}
    ensure_network(sid,svc); xml=render_domain(sid,svc); _run(["virsh","define",str(xml)])
    if svc["runtime"].get("startPolicy")=="boot": _run(["virsh","autostart",name],False); _run(["virsh","start",name],False)
    else:_run(["virsh","autostart","--disable",name],False)
    return {**plan,"state":status_libvirt(sid,svc)["state"],"xml":str(xml)}
def remove_libvirt(sid:str,svc:dict[str,Any]|None=None,*,dry_run:bool=False)->None:
    if dry_run:return
    name=vm_name(sid,svc or {"runtime":{}}); _run(["virsh","destroy",name],False); r=_run(["virsh","undefine",name,"--nvram"],False)
    if r.returncode:_run(["virsh","undefine",name],False)
    remove_network(sid)
def action_libvirt(sid:str,svc:dict[str,Any],action:str)->dict[str,Any]:
    name=vm_name(sid,svc); cmd={"start":"start","stop":"shutdown","restart":"reboot"}.get(action)
    if cmd is None:raise RuntimeError("invalid VM action")
    if action=="start":ensure_network(sid,svc)
    _run(["virsh",cmd,name]);return {"runtime":"vm","action":action,"state":status_libvirt(sid,svc)["state"]}
def status_libvirt(sid:str,svc:dict[str,Any])->dict[str,Any]:
    name=vm_name(sid,svc);r=_run(["virsh","domstate",name],False);return {"runtime":"vm","name":name,"state":r.stdout.strip().lower() if r.returncode==0 else "absent"}
