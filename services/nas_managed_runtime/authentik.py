#!/usr/bin/env python3
"""Authentik integration contract for managed services.

Identity remains Authentik-owned. Runtime forward-auth endpoints reuse the
existing appliance proxy outpost and the NAS authorization gate, so no per-app
Authentik object is needed. Native authentication is app-owned. Native OIDC is
intentionally rejected until client-secret provisioning can participate in the
same journaled transaction as runtime/Caddy/firewall changes.
"""
from __future__ import annotations
from typing import Any

class AuthentikError(RuntimeError):
    pass

def plan_authentik(service_id: str, service: dict[str, Any]) -> dict[str, Any]:
    actions=[]
    for eid,ep in (service.get("endpoints") or {}).items():
        mode=(ep.get("auth") or {}).get("mode","public")
        if mode=="forward-auth": actions.append({"type":"shared-forward-auth","endpoint":f"{service_id}:{eid}","provision":False})
        elif mode in {"public","native"}: actions.append({"type":mode,"endpoint":f"{service_id}:{eid}","provision":False})
        elif mode=="oidc": raise AuthentikError("native OIDC provisioning is not yet transaction-safe; use forward-auth or native app authentication")
        else: raise AuthentikError(f"unsupported authentication mode {mode!r}")
    return {"service":service_id,"actions":actions}
def apply_authentik(service_id: str, service: dict[str, Any], *, dry_run: bool=False) -> dict[str, Any]:
    return plan_authentik(service_id,service)
def remove_authentik(service_id: str, *, dry_run: bool=False) -> None:
    return None
