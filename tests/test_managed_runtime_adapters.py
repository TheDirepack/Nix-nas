from __future__ import annotations

import pathlib
import tempfile
import unittest
import xml.etree.ElementTree as ET
from unittest import mock

import sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))

from dataclasses import dataclass
import types

@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str

def _placeholder_run_command(*_args, **_kwargs):
    return CommandResult(0, "", "")

sys.modules.setdefault("nas_common", types.SimpleNamespace(CommandResult=CommandResult, run_command=_placeholder_run_command))

class _Journal:
    @classmethod
    def open(cls, *_args, **_kwargs): return cls()
    def start_step(self, *_args, **_kwargs): pass
    def complete_step(self, *_args, **_kwargs): pass
    def complete(self, *_args, **_kwargs): pass
    def fail(self, *_args, **_kwargs): pass

class _OpCtx:
    def __enter__(self): return self
    def __exit__(self, *_args): return False

sys.modules.setdefault("nas_operation_journal", types.SimpleNamespace(OperationJournal=_Journal, JournalError=RuntimeError, atomic_write_json=lambda *_a, **_k: None))
sys.modules.setdefault("nas_operation_lock", types.SimpleNamespace(OperationBusyError=RuntimeError, acquire_operation=lambda *_a, **_k: _OpCtx()))

import nas_managed_service as msvc
import nas_service_caddy as caddy
from nas_managed_runtime import compose, firewall, libvirt, podman


def result(rc: int = 0, out: str = "", err: str = "") -> CommandResult:
    return CommandResult(rc, out, err)


def service(runtime: str = "container") -> dict:
    rt = {"type": runtime, "startPolicy": "manual"}
    if runtime == "container":
        rt["image"] = "docker.io/library/nginx:latest"
    return {
        "label": "App",
        "enabled": True,
        "runtime": rt,
        "storage": [],
        "endpoints": {
            "web": {
                "transport": "http",
                "targetPort": 8080,
                "exposure": {"type": "path", "value": "/apps/app/"},
                "auth": {"mode": "forward-auth", "allow": "groups", "groups": ["family"]},
                "portal": {"visible": True},
            }
        },
        "network": {"outboundDefault": "allow", "lanAccess": False, "hostAccess": False},
    }


class ManagedRuntimeAdapterTests(unittest.TestCase):
    def test_podman_web_port_is_loopback_only(self):
        svc = msvc.normalize_service("app", service())
        svc["endpoints"]["web"]["hostPort"] = 20001
        calls: list[list[str]] = []
        def run(argv, **_kwargs):
            calls.append(list(argv))
            if list(argv)[:3] == ["podman", "network", "exists"]:
                return result(1)
            if list(argv)[:2] == ["podman", "inspect"]:
                return result(1)
            return result()
        with mock.patch.object(podman, "run_command", side_effect=run):
            podman.apply_podman("app", svc)
        create = next(argv for argv in calls if argv[:2] == ["podman", "create"])
        self.assertIn("127.0.0.1:20001:8080/tcp", create)

    def test_compose_rejects_privilege_and_generates_managed_network(self):
        with self.assertRaises(RuntimeError):
            compose.validate_compose_text("services:\n  web:\n    image: nginx\n    privileged: true\n")
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "app"; root.mkdir()
            source = root / "compose.yaml"; source.write_text("services:\n  web:\n    image: nginx\n", encoding="utf-8")
            svc = service("compose"); svc["runtime"]["source"] = str(source); svc["endpoints"]["web"]["targetService"] = "web"
            with mock.patch.object(msvc, "APP_ROOT", pathlib.Path(tmp)), mock.patch.dict("os.environ", {"NAS_MANAGED_APP_ROOT": tmp}):
                svc = msvc.normalize_service("app", svc); svc["endpoints"]["web"]["hostPort"] = 20002
                generated = compose.render_generated("app", svc)
            text = generated.read_text(encoding="utf-8")
            self.assertIn("nas-managed", text)
            self.assertIn("127.0.0.1:20002:8080/tcp", text)

    def test_libvirt_never_deletes_guest_storage_and_replaces_nics(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = pathlib.Path(tmp) / "app"; app.mkdir()
            source = app / "domain.xml"; source.write_text("<domain type='kvm'><name>old</name><devices><interface type='bridge'/></devices></domain>", encoding="utf-8")
            svc = service("vm"); svc["runtime"]["source"] = str(source)
            with mock.patch.object(msvc, "APP_ROOT", pathlib.Path(tmp)):
                svc = msvc.normalize_service("app", svc)
            svc["network"].update({"vmSubnet":"10.240.1.0/24","vmAddress":"10.240.1.10","vmMac":"52:54:00:00:00:10"})
            generated = libvirt.render_domain("app", svc)
            tree = ET.parse(generated)
            self.assertEqual(len(tree.findall("./devices/interface")), 1)
            calls = []
            with mock.patch.object(libvirt, "run_command", side_effect=lambda argv, **kw: calls.append(list(argv)) or result(1)):
                libvirt.remove_libvirt("app", svc)
            self.assertFalse(any("--remove-all-storage" in arg for argv in calls for arg in argv))

    def test_firewall_renders_workload_zone_and_app_policy(self):
        a = msvc.normalize_service("a", {**service(), "label":"A"})
        b = msvc.normalize_service("b", {**service(), "label":"B"})
        a["network"]["allowedServices"] = [{"service":"b","ports":[8080],"protocol":"tcp"}]
        docs = firewall._documents({"services":{"a":a,"b":b},"endpoints":{}})
        names = {path.name for path in docs}
        self.assertTrue(any(name.startswith("nas-") for name in names))
        self.assertTrue(any(name.startswith("nap") for name in names))

    def test_caddy_uses_existing_authentik_and_dynamic_gate(self):
        ep = service()["endpoints"]["web"]
        ep["hostPort"] = 20000; ep.update({"serviceId":"app","endpointId":"web","available":True,"builtin":False})
        rendered = caddy.generate_caddy_fragments({"endpoints":{"app:web":ep}})["paths"]
        self.assertIn("outpost.goauthentik.io/auth/caddy", rendered)
        self.assertIn("scope=service:app:web", rendered)
        self.assertIn("127.0.0.1:20000", rendered)

    def test_caddy_writes_path_and_host_fragments(self):
        path_ep = service()["endpoints"]["web"]
        path_ep["hostPort"] = 20000
        path_ep.update({"serviceId":"app","endpointId":"web","available":True,"builtin":False})
        host_ep = service()["endpoints"]["web"]
        host_ep["hostPort"] = 20001
        host_ep["exposure"] = {"type":"hostname","value":"photos.local"}
        host_ep.update({"serviceId":"photos","endpointId":"web","available":True,"builtin":False})
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict("os.environ", {"NAS_SKIP_CADDY_VALIDATE":"1","NAS_SKIP_CADDY_RELOAD":"1"}):
            paths = pathlib.Path(tmp) / "paths.caddy"
            hosts = pathlib.Path(tmp) / "hosts.caddy"
            result_value = caddy.write_caddy_fragments({"endpoints":{"app:web":path_ep,"photos:web":host_ep}}, path_fragment=paths, host_fragment=hosts)
            self.assertTrue(result_value["changed"])
            self.assertIn("/apps/app", paths.read_text(encoding="utf-8"))
            self.assertIn("photos.local", hosts.read_text(encoding="utf-8"))

    def test_caddy_restores_fragments_when_validation_fails(self):
        ep = service()["endpoints"]["web"]
        ep["hostPort"] = 20000
        ep.update({"serviceId":"app","endpointId":"web","available":True,"builtin":False})
        with tempfile.TemporaryDirectory() as tmp:
            paths = pathlib.Path(tmp) / "paths.caddy"
            hosts = pathlib.Path(tmp) / "hosts.caddy"
            config = pathlib.Path(tmp) / "Caddyfile"
            paths.write_text("old paths\n", encoding="utf-8")
            hosts.write_text("old hosts\n", encoding="utf-8")
            config.write_text("{}\n", encoding="utf-8")
            with mock.patch.object(caddy.shutil, "which", return_value="/bin/caddy"), mock.patch.object(caddy, "run_command", return_value=result(1, err="bad config")), mock.patch.dict("os.environ", {"NAS_CADDY_CONFIG":str(config),"NAS_SKIP_CADDY_RELOAD":"1"}):
                with self.assertRaises(RuntimeError):
                    caddy.write_caddy_fragments({"endpoints":{"app:web":ep}}, path_fragment=paths, host_fragment=hosts)
            self.assertEqual(paths.read_text(encoding="utf-8"), "old paths\n")
            self.assertEqual(hosts.read_text(encoding="utf-8"), "old hosts\n")

    def test_runtime_address_allocation_is_deterministic_and_conflict_checked(self):
        store = {"schemaVersion":2,"generation":1,"services":{"app":msvc.normalize_service("app", service())}}
        msvc.allocate_runtime_addresses(store)
        self.assertGreaterEqual(store["services"]["app"]["endpoints"]["web"]["hostPort"], 20000)
        effective = {"services":store["services"],"endpoints":{}}
        for sid, svc in store["services"].items():
            for eid, ep in svc["endpoints"].items():
                effective["endpoints"][f"{sid}:{eid}"] = {**ep,"serviceId":sid,"builtin":False}
        msvc.validate_conflicts(effective)


if __name__ == "__main__":
    unittest.main()
