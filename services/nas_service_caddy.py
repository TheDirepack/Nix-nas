#!/usr/bin/env python3
"""Caddyfile renderer for NAS-managed service endpoints.

The renderer deliberately emits Caddyfile fragments instead of attempting to
hand-author Caddy's native JSON. The fragments are imported by the existing
Nix-owned Caddy configuration, so managed routes share the appliance's existing
TLS and Authentik trust boundary without adding a daemon or a second proxy.
"""
from __future__ import annotations
import json, ipaddress, os, pathlib, re, tempfile, shutil
from typing import Any
from nas_common import run_command
HOSTNAME_RE=re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",re.IGNORECASE)
PORT_RE=re.compile(r"^[0-9]+$")
class CaddyError(ValueError,RuntimeError): pass
PATH_FRAGMENT=pathlib.Path(os.environ.get("NAS_CADDY_MANAGED_PATHS","/run/nas-control/caddy-managed-paths.caddy"))
HOST_FRAGMENT=pathlib.Path(os.environ.get("NAS_CADDY_MANAGED_HOSTS","/run/nas-control/caddy-managed-hosts.caddy"))
def _validate_exposure(exposure:dict[str,Any])->None:
    typ=exposure.get("type")
    if typ is None: raise CaddyError("exposure.type is mandatory")
    if typ=="none": raise CaddyError("exposure type 'none' must not produce a route")
    if typ not in {"hostname","dns","port","path"}: raise CaddyError(f"Invalid exposure type {typ!r}")
    val=exposure.get("value","")
    if val is None or val=="": raise CaddyError(f"exposure value is required for type {typ!r}")
    if typ in {"hostname","dns"}:
        if not isinstance(val,str) or len(val)>253 or not HOSTNAME_RE.fullmatch(val): raise CaddyError(f"Invalid hostname {val!r}")
    elif typ=="port":
        if isinstance(val,bool) or not PORT_RE.fullmatch(str(val)) or not 1<=int(val)<=65535: raise CaddyError(f"Invalid port {val!r}")
    elif typ=="path":
        if not isinstance(val,str) or not val.startswith("/") or ".." in pathlib.PurePosixPath(val).parts: raise CaddyError(f"Invalid path {val!r}")
def _token(value:str)->str:return json.dumps(str(value),ensure_ascii=True)
def _authentik_lines(*,authentik_port:int,authentik_path:str)->list[str]:
    path="/"+authentik_path.strip("/")+"/"
    return ["request_header -Remote-User","request_header -Remote-Groups","request_header -Remote-Name","request_header -Remote-Email","request_header -Remote-UID","request_header -Remote-Role","request_header -X-Authentik-Username","request_header -X-Authentik-Groups","request_header -X-Authentik-Name","request_header -X-Authentik-Email","request_header -X-Authentik-Uid",f"forward_auth 127.0.0.1:{authentik_port} {{",f"  uri {path}outpost.goauthentik.io/auth/caddy","  copy_headers X-Authentik-Username X-Authentik-Groups X-Authentik-Name X-Authentik-Email X-Authentik-Uid","}","@nasManagedMissingIdentity not header X-Authentik-Username *","respond @nasManagedMissingIdentity 403","request_header Remote-User {http.request.header.X-Authentik-Username}","request_header Remote-Groups {http.request.header.X-Authentik-Groups}","request_header Remote-Name {http.request.header.X-Authentik-Name}","request_header Remote-Email {http.request.header.X-Authentik-Email}","request_header Remote-UID {http.request.header.X-Authentik-Uid}"]
def _upstream(endpoint:dict[str,Any])->str:
    host=str(endpoint.get("targetHost") or "127.0.0.1")
    try:
        address=ipaddress.ip_address(host); host_token=f"[{host}]" if address.version==6 else host
    except ValueError:
        if len(host)>253 or HOSTNAME_RE.fullmatch(host) is None: raise CaddyError(f"Invalid upstream host {host!r}")
        host_token=host
    port=int(endpoint["hostPort"] if endpoint.get("hostPort") else endpoint["targetPort"])
    if not 1<=port<=65535: raise CaddyError(f"Invalid upstream port {port!r}")
    return ("https://" if endpoint.get("transport")=="https" else "")+f"{host_token}:{port}"
def _proxy_lines(endpoint:dict[str,Any])->list[str]:
    lines=[f"reverse_proxy {_upstream(endpoint)} {{"]
    if endpoint.get("transport")=="https" and endpoint.get("upstreamTlsInsecure") is True: lines.extend(["  transport http {","    tls_insecure_skip_verify","  }"])
    if endpoint.get("exposure",{}).get("type")=="path": lines.append(f"  header_up X-Forwarded-Prefix {_token(str(endpoint['exposure']['value']).rstrip('/') or '/')}")
    lines.extend(["  header_up X-Forwarded-Proto https","  header_up Remote-User {http.request.header.Remote-User}","  header_up Remote-Groups {http.request.header.Remote-Groups}","  header_up Remote-Name {http.request.header.Remote-Name}","  header_up Remote-Email {http.request.header.Remote-Email}","  header_up Remote-UID {http.request.header.Remote-UID}","}"]);return lines
def _secured_proxy_lines(key:str,endpoint:dict[str,Any],*,authentik_port:int,authentik_path:str,admin_group:str,gate_socket:str)->list[str]:
    del admin_group; mode=str((endpoint.get("auth") or {"mode":"public"}).get("mode") or "public")
    if mode in {"public","native"}: return _proxy_lines(endpoint)
    if mode!="forward-auth": return ["respond 403"]
    lines=_authentik_lines(authentik_port=authentik_port,authentik_path=authentik_path);scope=f"service:{key}"
    lines.extend([f"forward_auth unix/{gate_socket} {{",f"  uri /authorize?scope={scope}","  header_up Remote-User {http.request.header.Remote-User}","  header_up Remote-Groups {http.request.header.Remote-Groups}","  header_up Remote-Name {http.request.header.Remote-Name}","  header_up Remote-Email {http.request.header.Remote-Email}","  header_up Remote-UID {http.request.header.Remote-UID}","}"]);lines.extend(_proxy_lines(endpoint));return lines
def _indent(lines:list[str],amount:int=2)->list[str]:
    prefix=" "*amount;return [prefix+line if line else "" for line in lines]
def _path_route(key:str,endpoint:dict[str,Any],*,authentik_port:int,authentik_path:str,admin_group:str,gate_socket:str)->list[str]:
    value=str(endpoint["exposure"]["value"]);base=value.rstrip("/") or "/";strip=endpoint.get("exposure",{}).get("stripPrefix",True) is not False and base!="/";lines=[]
    if base!="/": lines.extend([f"redir {_token(base)} {_token(base+'/')} 308"]);matcher=base+"/*"
    else: matcher="/*"
    directive="handle_path" if strip else "handle";lines.extend([f"{directive} {_token(matcher)} {{","  route {"]);lines.extend(_indent(_secured_proxy_lines(key,endpoint,authentik_port=authentik_port,authentik_path=authentik_path,admin_group=admin_group,gate_socket=gate_socket),4));lines.extend(["  }","}"]);return lines
def _outpost_lines(*,authentik_port:int,authentik_path:str)->list[str]:
    path="/"+authentik_path.strip("/")+"/";return ["@nasManagedAuthentikOutpost path /outpost.goauthentik.io/*","handle @nasManagedAuthentikOutpost {",f"  uri replace /outpost.goauthentik.io {path}outpost.goauthentik.io",f"  reverse_proxy 127.0.0.1:{authentik_port} {{","    header_up Host {http.request.host}","    header_up X-Forwarded-Proto https","    header_up X-Forwarded-For {remote_host}","  }","}"]
def _site_route(key:str,endpoint:dict[str,Any],*,address:str,local_tls:bool,authentik_port:int,authentik_path:str,admin_group:str,gate_socket:str)->list[str]:
    lines=[f"{address} {{"]
    if local_tls: lines.append("  tls internal")
    lines.extend(["  encode zstd gzip","  header {","    -Server",'    X-Content-Type-Options "nosniff"','    Referrer-Policy "no-referrer"','    Permissions-Policy "camera=(), microphone=(), geolocation=()"',"  }"])
    if (endpoint.get("auth") or {}).get("mode")!="public": lines.extend(_indent(_outpost_lines(authentik_port=authentik_port,authentik_path=authentik_path),2))
    lines.append("  route {");lines.extend(_indent(_secured_proxy_lines(key,endpoint,authentik_port=authentik_port,authentik_path=authentik_path,admin_group=admin_group,gate_socket=gate_socket),4));lines.extend(["  }","}",""]);return lines
def generate_caddy_fragments(effective:dict[str,Any],*,lan_host:str="nas.local",authentik_port:int=9000,authentik_path:str="/identity/",admin_group:str="nas_admin",gate_socket:str="/run/nas-on-demand/gate.sock")->dict[str,str]:
    path_lines=["# Generated by nas-managed-service. Do not edit."];host_lines=["# Generated by nas-managed-service. Do not edit."];seen_paths=set();seen_sites=set()
    for key,endpoint in sorted((effective.get("endpoints") or {}).items()):
        if endpoint.get("builtin") is True or "publicPath" in endpoint: continue
        if endpoint.get("transport") not in {"http","https","ws"}: continue
        exposure=endpoint.get("exposure") or {"type":"none"};typ=exposure.get("type")
        if typ in {None,"none"} or endpoint.get("available") is False: continue
        _validate_exposure(exposure)
        if typ=="path":
            value=str(exposure["value"]).rstrip("/") or "/"
            if value in seen_paths: raise ValueError(f"Duplicate managed path exposure {value!r}")
            seen_paths.add(value);path_lines.extend(_path_route(key,endpoint,authentik_port=authentik_port,authentik_path=authentik_path,admin_group=admin_group,gate_socket=gate_socket));path_lines.append("");continue
        if typ in {"hostname","dns"}: address=str(exposure["value"]);local_tls=typ=="hostname" or address.endswith(".local")
        elif typ=="port": address=f"https://{lan_host}:{int(exposure['value'])}";local_tls=True
        else: continue
        if address in seen_sites: raise ValueError(f"Duplicate managed site exposure {address!r}")
        seen_sites.add(address);host_lines.extend(_site_route(key,endpoint,address=address,local_tls=local_tls,authentik_port=authentik_port,authentik_path=authentik_path,admin_group=admin_group,gate_socket=gate_socket))
    return {"paths":"\n".join(path_lines).rstrip()+"\n","hosts":"\n".join(host_lines).rstrip()+"\n"}
def _atomic_write(path:pathlib.Path,content:str,mode:int=0o644)->bool:
    path.parent.mkdir(parents=True,exist_ok=True)
    try:
        if path.read_text(encoding="utf-8")==content:return False
    except FileNotFoundError:pass
    fd,name=tempfile.mkstemp(prefix=f".{path.name}.",dir=path.parent);replaced=False
    try:
        with os.fdopen(fd,"w",encoding="utf-8") as h:h.write(content);h.flush();os.fsync(h.fileno())
        os.chmod(name,mode);os.replace(name,path);replaced=True;dfd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(dfd)
        finally:os.close(dfd)
    finally:
        if not replaced:pathlib.Path(name).unlink(missing_ok=True)
    return True
def write_caddy_fragments(effective:dict[str,Any],*,path_fragment:pathlib.Path=PATH_FRAGMENT,host_fragment:pathlib.Path=HOST_FRAGMENT,lan_host:str|None=None,authentik_port:int|None=None,authentik_path:str|None=None,admin_group:str|None=None,gate_socket:str|None=None)->dict[str,Any]:
    rendered=generate_caddy_fragments(effective,lan_host=lan_host or os.environ.get("NAS_LAN_HOST","nas.local"),authentik_port=authentik_port or int(os.environ.get("NAS_AUTHENTIK_PORT","9000")),authentik_path=authentik_path or os.environ.get("NAS_AUTHENTIK_PATH","/identity/"),admin_group=admin_group or os.environ.get("NAS_IDENTITY_ADMIN_GROUP","nas_admin"),gate_socket=gate_socket or os.environ.get("NAS_ON_DEMAND_SOCKET","/run/nas-on-demand/gate.sock"));changed=_atomic_write(path_fragment,rendered["paths"]) or _atomic_write(host_fragment,rendered["hosts"])
    if changed:
        config=pathlib.Path(os.environ.get("NAS_CADDY_CONFIG","/etc/caddy/caddy_config"));caddy=shutil.which("caddy")
        if caddy and config.exists() and os.environ.get("NAS_SKIP_CADDY_VALIDATE")!="1":
            check=run_command([caddy,"validate","--config",str(config),"--adapter","caddyfile"],timeout_seconds=60,max_output_bytes=512*1024)
            if check.returncode: raise RuntimeError(f"generated Caddy configuration is invalid: {(check.stderr or check.stdout)[:1000]}")
        if os.environ.get("NAS_SKIP_CADDY_RELOAD")!="1":
            active=run_command(["systemctl","is-active","--quiet","caddy.service"],timeout_seconds=15,max_output_bytes=64*1024)
            if active.returncode==0:
                rr=run_command(["systemctl","reload","caddy.service"],timeout_seconds=60,max_output_bytes=256*1024)
                if rr.returncode: raise RuntimeError(f"unable to reload Caddy: {(rr.stderr or rr.stdout)[:1000]}")
    return {"changed":changed,"pathFragment":str(path_fragment),"hostFragment":str(host_fragment)}
def _compat_routes(effective:dict[str,Any])->list[dict[str,Any]]:
    routes=[]
    for key,endpoint in (effective.get("endpoints") or {}).items():
        if endpoint.get("transport") not in {None,"http","https","ws"} or "publicPath" in endpoint: continue
        exposure=endpoint.get("exposure")
        if not isinstance(exposure,dict): raise CaddyError(f"Endpoint {key!r}: exposure is mandatory")
        _validate_exposure(exposure);auth=endpoint.get("auth")
        if not isinstance(auth,dict): raise CaddyError(f"Endpoint {key!r}: auth is mandatory for HTTP endpoints")
        if auth.get("mode") not in {"public","forward-auth","native"}: raise CaddyError(f"Endpoint {key!r}: unknown auth mode {auth.get('mode')!r} — failing closed")
        try:target_port=int(endpoint["targetPort"])
        except (KeyError,TypeError,ValueError) as exc: raise CaddyError(f"Endpoint {key!r}: targetPort is mandatory") from exc
        if not 1<=target_port<=65535: raise CaddyError(f"Endpoint {key!r}: invalid targetPort")
        typ=exposure["type"];value=exposure.get("value");routes.append({"id":f"nas-managed-{key.replace(':','-')}","key":key,"host":value if typ in {"hostname","dns"} else None,"path":value if typ=="path" else None,"path_prefix":bool(exposure.get("prefix",True)),"port":int(value) if typ=="port" else None,"targetPort":target_port,"auth":auth,"exposure":exposure})
    routes.sort(key=lambda r:r["id"]);seen=set()
    for route in routes:
        marker=(route["host"],route["path"],route["port"])
        if marker in seen: raise CaddyError(f"Duplicate exposure {marker} for route {route['id']}")
        seen.add(marker)
    return routes
def generate_caddy_fragment(effective:dict[str,Any]|None=None)->dict[str,Any]:
    if effective is None:
        import nas_managed_service as msvc;effective=msvc.effective_registry()
    return {"routes":_compat_routes(effective)}
def generate_caddyfile(effective:dict[str,Any]|None=None)->str:
    if effective is None:
        import nas_managed_service as msvc;effective=msvc.effective_registry()
    rendered=generate_caddy_fragments(effective);return rendered["paths"]+"\n"+rendered["hosts"]
def write_caddy_fragment(path:pathlib.Path|None=None)->dict[str,Any]:
    import nas_managed_service as msvc;effective=msvc.effective_registry();fragment=generate_caddy_fragment(effective);target=path or pathlib.Path("/run/nas-control/caddy-managed.conf");_atomic_write(target,generate_caddyfile(effective));return fragment
