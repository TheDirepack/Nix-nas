"""Gap-closure tests for uncovered V2 functions — deterministic, <0.1s each."""
from __future__ import annotations

import hashlib
import json
import pathlib
import sys
import tempfile
import unittest
import unittest.mock as mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
SCHEMA = ROOT / "schemas" / "managed-services-v3.schema.json"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_apply as apply_mod  # noqa: E402
import nas_v2_backup as backup  # noqa: E402
import nas_v2_bootstrap as bootstrap  # noqa: E402
import nas_v2_caddy as caddy  # noqa: E402
import nas_v2_network as net  # noqa: E402
import nas_v2_session as sess  # noqa: E402
import nas_v2_spec as spec  # noqa: E402
import nas_v2_systemd as sysd  # noqa: E402
import nas_v2_systemd_reconcile as recon  # noqa: E402
from nas_v2_accelerator import enabled_capabilities, is_cdi_selector, load_platform_inventory  # noqa: E402


def _effective_for(service_id="demo", service_extra=None, resources=None, credentials=None):
    schema = spec.load_schema(SCHEMA)
    svc = {
        "name": "Demo",
        "workload": {"kind": "daemon", "activation": "persistent"},
        "runtime": {"type": "systemd", "unit": "demo.service"},
    }
    if service_extra:
        svc.update(service_extra)
    doc = {"schemaVersion": 3, "services": {service_id: svc}}
    if resources:
        doc["storageResources"] = resources
    if credentials:
        doc["credentials"] = credentials
    return spec.compile_document(doc, schema)


class SpecGapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = spec.load_schema(SCHEMA)

    def test_json_path_and_plain(self):
        self.assertEqual(spec._json_path(["a", 0, "b"]), "$.a[0].b")
        self.assertEqual(spec._plain({"x": 1}), {"x": 1})
        with self.assertRaises(spec.ManagedServicesV2Error):
            spec._plain({1: object()})  # non-JSON type

    def test_yaml_files_in_dir_and_merge(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = pathlib.Path(tmp)
            (d / "a.yaml").write_text("schemaVersion: 3\nservices: {}\n", encoding="utf-8")
            (d / "b.yml").write_text("storageResources: {}\n", encoding="utf-8")
            files = spec._yaml_files_in_dir(d)
            self.assertEqual(len(files), 2)
            merged = spec._merge_documents([{"a": {"x": 1}}, {"a": {"y": 2}, "b": 3}])
            self.assertEqual(merged, {"a": {"x": 1, "y": 2}, "b": 3})
            with self.assertRaises(spec.ManagedServicesV2Error):
                spec._merge_documents([])
            with self.assertRaises(spec.ManagedServicesV2Error):
                spec._yaml_files_in_dir(d / "nonexistent")

    def test_is_directory_authority_and_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = pathlib.Path(tmp) / "dir"
            d.mkdir()
            self.assertTrue(spec.is_directory_authority(d))
            self.assertFalse(spec.is_directory_authority(d / "missing"))
            # hash empty dir fails
            with self.assertRaises(spec.ManagedServicesV2Error):
                spec.hash_authority(d)
            (d / "00.yaml").write_text("schemaVersion: 3\nservices: {}\n", encoding="utf-8")
            h = spec.hash_authority(d)
            self.assertEqual(len(h), 64)
            # single file hash
            hf = spec.hash_authority(d / "00.yaml")
            self.assertEqual(hf, hashlib.sha256((d / "00.yaml").read_bytes()).hexdigest())
            # parse_yaml directory + file
            parsed = spec.parse_yaml(d)
            self.assertIn("schemaVersion", parsed)
            parsed2 = spec.parse_yaml(d / "00.yaml")
            self.assertEqual(parsed, parsed2)

    def test_hash_authority_io_error(self):
        with mock.patch("pathlib.Path.read_bytes", side_effect=OSError("boom")):
            with tempfile.TemporaryDirectory() as tmp:
                d = pathlib.Path(tmp) / "dir"
                d.mkdir()
                (d / "a.yaml").write_text("x: 1", encoding="utf-8")
                # read_bytes patched will trigger io-read
                with self.assertRaises(spec.ManagedServicesV2Error):
                    spec.hash_authority(d)

    def test_load_schema_invalid_and_validate(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = pathlib.Path(tmp) / "bad.json"
            bad.write_text("not json", encoding="utf-8")
            with self.assertRaises(spec.ManagedServicesV2Error):
                spec.load_schema(bad)
            bad2 = pathlib.Path(tmp) / "bad2.json"
            bad2.write_text('{"type": "invalid"}', encoding="utf-8")
            # not object schema check
            with self.assertRaises(spec.ManagedServicesV2Error):
                spec.load_schema(bad2)
            # validate_schema success
            doc = {"schemaVersion": 3, "services": {}}
            spec.validate_schema(doc, spec.load_schema(SCHEMA))
            # fail
            with self.assertRaises(spec.ManagedServicesV2Error):
                spec.validate_schema({"schemaVersion": 99}, spec.load_schema(SCHEMA))

    def test_safe_absolute_path_controls(self):
        with self.assertRaises(spec.ManagedServicesV2Error):
            spec._safe_absolute_path("relative/path", path="$.x")
        with self.assertRaises(spec.ManagedServicesV2Error):
            spec._safe_absolute_path("/tmp/../etc", path="$.x")
        with self.assertRaises(spec.ManagedServicesV2Error):
            spec._safe_absolute_path("/tmp/\x00bad", path="$.x")
        self.assertTrue(spec._under(pathlib.PurePosixPath("/a/b"), pathlib.PurePosixPath("/a/b/c")))
        self.assertFalse(spec._under(pathlib.PurePosixPath("/a/b"), pathlib.PurePosixPath("/a/c")))

    def test_normalize_network_and_runtime(self):
        doc = {"schemaVersion": 3, "services": {"s": {"name": "S", "workload": {"kind": "daemon", "activation": "persistent"}, "runtime": {"type": "python", "entrypoint": {"module": "m"}}}}}
        norm = spec.normalize(doc)
        self.assertEqual(norm["services"]["s"]["runtime"]["interpreter"], "/run/current-system/sw/bin/python3")
        # exec runtime
        doc2 = {"schemaVersion": 3, "services": {"s": {"name": "S", "workload": {"kind": "daemon", "activation": "persistent"}, "runtime": {"type": "exec", "command": ["/bin/sh"]}}}}
        spec.normalize(doc2)

    def test_validate_runtime_paths_and_dependency_graph(self):
        # valid
        svc = {"name": "X", "workload": {"kind": "daemon", "activation": "persistent"}, "runtime": {"type": "exec", "command": ["/bin/true"]}, "sandbox": {"mode": "inherit"}, "resources": {"accelerators": []}, "storage": [], "credentials": [], "routes": {}, "listeners": {}, "dependencies": [], "authorization": {"capabilities": []}}
        spec._validate_runtime_paths("x", {**svc, "runtime": {"type": "exec", "command": ["/bin/true"]}})
        with self.assertRaises(spec.ManagedServicesV2Error):
            spec._validate_runtime_paths("x", {**svc, "runtime": {"type": "exec", "command": ["relative"]}})
        with self.assertRaises(spec.ManagedServicesV2Error):
            spec._validate_runtime_paths("x", {**svc, "runtime": {"type": "exec", "command": ["/"]}})
        with self.assertRaises(spec.ManagedServicesV2Error):
            spec._validate_runtime_paths("x", {**svc, "runtime": {"type": "systemd", "unit": "bad"}})
        # dependency graph cycle
        services = {"a": {"dependencies": [{"service": "b"}]}, "b": {"dependencies": [{"service": "a"}]}}
        with self.assertRaises(spec.ManagedServicesV2Error):
            spec._validate_dependency_graph(services)

    def test_listener_ports_routes_conflict(self):
        self.assertEqual(list(spec._listener_ports({"port": 80})), [80])
        self.assertEqual(list(spec._listener_ports({"start": 80, "end": 81})), [80, 81])
        self.assertTrue(spec._routes_conflict("/api", "/api/users"))
        self.assertTrue(spec._routes_conflict("/", "/anything"))
        self.assertFalse(spec._routes_conflict("/api/v1", "/api/v2"))

    def test_semantic_validate_branches(self):
        # user scope requires template
        doc = {"schemaVersion": 3, "storageResources": {"r": {"path": "/srv/r", "stateClass": "authoritative", "scope": "user", "backup": {"enabled": False, "consistency": "filesystem"}}}, "credentials": {}, "networkProfiles": {}, "services": {}}
        with self.assertRaises(spec.ManagedServicesV2Error):
            spec.semantic_validate(spec.normalize(doc))
        # vlan requires isolated
        doc2 = spec.normalize({"schemaVersion": 3, "networkProfiles": {"p": {"mode": "host", "vlanId": 10, "vlanParent": "eth0"}}, "services": {}})
        with self.assertRaises(spec.ManagedServicesV2Error):
            spec.semantic_validate(doc2)

    def test_build_effective_and_load_platform(self):
        doc = spec.normalize({"schemaVersion": 3, "services": {"s": {"name": "S", "workload": {"kind": "daemon", "activation": "persistent"}, "runtime": {"type": "systemd", "unit": "s.service"}}}})
        eff = spec.build_effective(doc)
        self.assertIn("derived", eff)
        with tempfile.TemporaryDirectory() as tmp:
            p = pathlib.Path(tmp) / "cap.json"
            p.write_text(json.dumps({"capabilities": {"kvm": True, "gpu": False}}), encoding="utf-8")
            caps = spec.load_platform_capabilities(p)
            self.assertIn("kvm", caps)
            self.assertNotIn("gpu", caps)
            p2 = pathlib.Path(tmp) / "cap2.json"
            p2.write_text(json.dumps({"capabilities": ["kvm"]}), encoding="utf-8")
            self.assertEqual(spec.load_platform_capabilities(p2), {"kvm"})
            p3 = pathlib.Path(tmp) / "bad.json"
            p3.write_text(json.dumps({"capabilities": {"bad": "nope"}}), encoding="utf-8")
            # string array vs object handling - list with bool? should fail if not string array
            p3.write_text(json.dumps({"capabilities": 123}), encoding="utf-8")
            with self.assertRaises(spec.ManagedServicesV2Error):
                spec.load_platform_capabilities(p3)

    def test_as_dict_and_load_and_compile(self):
        e = spec.ManagedServicesV2Error("msg", path="$.x", code="test")
        self.assertEqual(e.as_dict(), {"code": "test", "path": "$.x", "message": "msg"})
        with tempfile.TemporaryDirectory() as tmp:
            d = pathlib.Path(tmp) / "svc.yaml"
            d.write_text("schemaVersion: 3\nservices: {}\n", encoding="utf-8")
            # load_and_compile without platform
            eff = spec.load_and_compile(d, SCHEMA, platform_path=None)
            self.assertEqual(eff["schemaVersion"], 3)


class CaddyGapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = spec.load_schema(SCHEMA)

    def _eff(self, service):
        return spec.compile_document({"schemaVersion": 3, "services": {"demo": service}}, self.schema)

    def test_header_name_and_matcher(self):
        self.assertEqual(caddy._header_name("X-Custom"), "X-Custom")
        with self.assertRaises(caddy.CaddyProjectionError):
            caddy._header_name("Bad Header")
        self.assertEqual(caddy._matcher("a-b", "c", "x"), "v2_a_b_c_x")

    def test_safe_posix_and_path_patterns(self):
        self.assertEqual(str(caddy._safe_posix("/ok/path", "msg")), "/ok/path")
        with self.assertRaises(caddy.CaddyProjectionError):
            caddy._safe_posix("relative", "msg")
        with self.assertRaises(caddy.CaddyProjectionError):
            caddy._safe_posix("/bad{brace", "msg")
        self.assertEqual(caddy._path_patterns("/"), ("/*",))
        self.assertEqual(caddy._path_patterns("/api/"), ("/api/", "/api/*"))
        self.assertEqual(caddy._path_patterns("/api"), ("/api", "/api/*"))
        with self.assertRaises(caddy.CaddyProjectionError):
            caddy._path_patterns("no-slash")

    def test_q_control_rejection(self):
        with self.assertRaises(caddy.CaddyProjectionError):
            caddy._q("bad\x00")

    def test_render_wake_and_identity(self):
        svc = {"name": "Demo", "workload": {"kind": "daemon", "activation": "on-demand", "idleSeconds": 30}, "runtime": {"type": "systemd", "unit": "demo.service"}, "routes": {"w": {"target": {"type": "http", "port": 80}, "exposure": {"type": "path", "paths": ["/w"]}, "auth": {"mode": "public"}}}}
        eff = self._eff(svc)
        with self.assertRaises(caddy.CaddyProjectionError):
            caddy.generate_caddyfile(eff, wake_socket=None)
        # upstream wake fails
        svc2 = {"name": "Demo", "workload": {"kind": "daemon", "activation": "on-demand", "idleSeconds": 30}, "runtime": {"type": "systemd", "unit": "demo.service"}, "routes": {"w": {"target": {"type": "http", "port": 80}, "exposure": {"type": "path", "paths": ["/w"]}, "auth": {"mode": "upstream"}}}}
        eff2 = self._eff(svc2)
        with self.assertRaises(caddy.CaddyProjectionError):
            caddy.generate_caddyfile(eff2, wake_socket="/run/wake.sock")

    def test_generate_caddyfile_hostname_validation(self):
        svc = {"name": "D", "workload": {"kind": "daemon", "activation": "persistent"}, "runtime": {"type": "systemd", "unit": "demo.service"}, "routes": {"w": {"target": {"type": "http", "port": 80}, "exposure": {"type": "path", "paths": ["/x"]}, "auth": {"mode": "public"}}}}
        eff = self._eff(svc)
        with self.assertRaises(caddy.CaddyProjectionError):
            caddy.generate_caddyfile(eff, lan_host="bad host!")
        with self.assertRaises(caddy.CaddyProjectionError):
            # invalid hostname in route
            svc_bad = {"name": "D", "workload": {"kind": "daemon", "activation": "persistent"}, "runtime": {"type": "systemd", "unit": "demo.service"}, "routes": {"w": {"target": {"type": "http", "port": 80}, "exposure": {"type": "hostname", "hostnames": ["bad host"]}, "auth": {"mode": "public"}}}}
            eff_bad = self._eff(svc_bad)
            caddy.generate_caddyfile(eff_bad)

    def test_portal_bytes_and_compile(self):
        # portal_bytes success + fail
        svc = {"name": "Demo", "workload": {"kind": "daemon", "activation": "persistent"}, "runtime": {"type": "systemd", "unit": "demo.service"}, "routes": {"w": {"target": {"type": "http", "port": 80}, "exposure": {"type": "path", "paths": ["/x"]}, "auth": {"mode": "public"}, "portal": {"visible": True, "title": "Demo"}}}}
        eff = self._eff(svc)
        data = caddy.portal_bytes(eff)
        self.assertIn(b"Demo", data)
        # _route_url explicit
        self.assertEqual(caddy._route_url({"type": "path", "paths": ["/a"]}, {"url": "/custom"}), "/custom")
        with self.assertRaises(caddy.PortalProjectionError):
            caddy.compile_portal_projection({"schemaVersion": 2, "services": {}})
        with self.assertRaises(caddy.PortalProjectionError):
            caddy._access("s", {})
        self.assertEqual(caddy._access("s", {"auth": {"mode": "public"}})["mode"], "public")

    def test_validate_caddyfile_requires_binary(self):
        # fake caddy that fails validation
        with tempfile.TemporaryDirectory() as tmp:
            fake = pathlib.Path(tmp) / "fake-caddy"
            fake.write_text("#!/bin/sh\necho 'bad' >&2; exit 1\n", encoding="utf-8")
            fake.chmod(0o755)
            with self.assertRaises(caddy.CaddyProjectionError):
                caddy.validate_caddyfile("xxx", caddy_bin=str(fake))
        # missing binary auto-detect
        with mock.patch("shutil.which", return_value=None):
            with self.assertRaises(caddy.CaddyProjectionError):
                caddy.validate_caddyfile("xxx")


class SystemdGapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = spec.load_schema(SCHEMA)

    def test_attachment_lines_variants(self):
        # storage read success, write requires existing identity
        eff = spec.compile_document({"schemaVersion": 3, "storageResources": {"data": {"path": "/srv/data", "stateClass": "authoritative"}}, "services": {"demo": {"name": "D", "workload": {"kind": "daemon", "activation": "persistent"}, "runtime": {"type": "systemd", "unit": "demo.service"}, "storage": [{"resource": "data", "mountPath": "/data", "access": "read"}]}}}, self.schema)
        svc = eff["services"]["demo"]
        lines = sysd.attachment_lines(eff, svc)
        self.assertTrue(any("BindReadOnlyPaths" in l for l in lines))
        # credential environment-file
        eff2 = spec.compile_document({"schemaVersion": 3, "credentials": {"sec": {"path": "/run/nas-secrets/sec"}}, "services": {"demo": {"name": "D", "workload": {"kind": "daemon", "activation": "persistent"}, "runtime": {"type": "systemd", "unit": "demo.service"}, "credentials": [{"credential": "sec", "use": "environment-file"}]}}}, self.schema)
        self.assertIn("EnvironmentFile", sysd.attachment_lines(eff2, eff2["services"]["demo"])[0])
        # duplicate mount rejected
        eff_dup = spec.compile_document({"schemaVersion": 3, "credentials": {"a": {"path": "/run/nas-secrets/a"}, "b": {"path": "/run/nas-secrets/b"}}, "services": {"demo": {"name": "D", "workload": {"kind": "daemon", "activation": "persistent"}, "runtime": {"type": "systemd", "unit": "demo.service"}, "credentials": [{"credential": "a", "use": "file", "mountPath": "/same"}, {"credential": "b", "use": "file", "mountPath": "/same"}]}}}, self.schema)
        with self.assertRaises(sysd.SystemdAttachmentError):
            sysd.attachment_lines(eff_dup, eff_dup["services"]["demo"])

    def test_generate_projection_exec_and_systemd(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp) / "out"
            eff = spec.compile_document({"schemaVersion": 3, "services": {"demo": {"name": "D", "workload": {"kind": "daemon", "activation": "persistent"}, "runtime": {"type": "exec", "command": ["/bin/true"]}}}}, self.schema)
            # ensure source_dir exists for exec runner reference
            src = pathlib.Path(tmp) / "src"
            src.mkdir()
            (src / "nas_v2_exec_runner.py").write_text("# stub", encoding="utf-8")
            files, manifest = sysd.generate_projection(eff, output_dir=out, python_bin="/run/current-system/sw/bin/python3", source_dir=src, systemctl_bin="/bin/systemctl", uv_bin="/bin/uv")
            self.assertIn("demo.service", str(files))
            # systemd runtime dropin
            eff2 = spec.compile_document({"schemaVersion": 3, "services": {"demo": {"name": "D", "workload": {"kind": "daemon", "activation": "persistent"}, "runtime": {"type": "systemd", "unit": "demo.service"}}}}, self.schema)
            files2, _ = sysd.generate_projection(eff2, output_dir=out, python_bin="/bin/python3", source_dir=src, systemctl_bin="/bin/systemctl", uv_bin="/bin/uv")
            self.assertIn("manifest.json", str(list(files2.keys())[0]) if files2 else "")

    def test_generate_projection_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp)
            # storage attachment with existing resource but colliding mount
            eff = spec.compile_document({"schemaVersion": 3, "storageResources": {"data": {"path": "/srv/data", "stateClass": "authoritative"}}, "services": {"demo": {"name": "D", "workload": {"kind": "daemon", "activation": "persistent"}, "runtime": {"type": "exec", "command": ["/bin/true"]}, "storage": [{"resource": "data", "mountPath": "/data", "access": "write"}]}}}, self.schema)
            # force fail via dynamic user writable bind: patch runtime identity to dynamic
            eff["services"]["demo"]["runtime"]["identity"] = {"mode": "dynamic"}
            src = pathlib.Path(tmp) / "src"
            src.mkdir()
            with self.assertRaises(sysd.SystemdProjectionError):
                sysd.generate_projection(eff, output_dir=out, python_bin="/bin/python3", source_dir=src, systemctl_bin="/bin/systemctl", uv_bin="/bin/uv")

    def test_quote_and_protect_conflicts(self):
        with self.assertRaises(sysd.SystemdAttachmentError):
            sysd._quote_attachment("bad\n")
        with self.assertRaises(sysd.SystemdAttachmentError):
            sysd._bind_path("/bad:colon", field="test")

    def test_validate_projection_no_files(self):
        # empty is no-op
        sysd.validate_projection({}, systemd_analyze_bin="/bin/true")


class BackupGapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = spec.load_schema(SCHEMA)

    def test_absolute_source_and_runtime_safe(self):
        self.assertIsNotNone(backup._absolute_source("/ok", label="x"))
        with self.assertRaises(backup.BackupVerificationError):
            backup._absolute_source("relative", label="x")
        with self.assertRaises(backup.BackupRuntimeError):
            backup._runtime_safe_absolute_path("relative", label="x")

    def test_compile_backup_projection_native_dump(self):
        # need effective with native-dump graph
        doc = {
            "schemaVersion": 3,
            "storageResources": {
                "src": {"path": "/srv/src", "stateClass": "authoritative", "scope": "system", "backup": {"enabled": True, "consistency": "native-dump"}},
                "art": {"path": "/srv/art", "stateClass": "derived", "scope": "system", "backup": {"enabled": False, "consistency": "filesystem"}},
            },
            "services": {
                "prep": {"name": "P", "workload": {"kind": "job"}, "runtime": {"type": "systemd", "unit": "prep.service"}, "storage": [{"resource": "src", "mountPath": "/in", "access": "read"}, {"resource": "art", "mountPath": "/out", "access": "write"}]},
            },
        }
        eff = spec.compile_document(doc, self.schema)
        inv, paths = backup.compile_backup_projection(eff)
        self.assertIn(b"nativeDump", inv)
        # duplicate path fails
        doc2 = {"schemaVersion": 3, "storageResources": {"a": {"path": "/same", "stateClass": "authoritative", "backup": {"enabled": True, "consistency": "filesystem"}}, "b": {"path": "/same", "stateClass": "authoritative", "backup": {"enabled": True, "consistency": "filesystem"}}}, "services": {}, "derived": {"backupResources": ["a", "b"]}}
        # manually inject derived
        eff2 = spec.normalize(doc2)
        eff2["derived"] = {"backupResources": ["a", "b"], "authorization": {}, "runtime": {}, "routes": []}
        eff2["schemaVersion"] = 3
        with self.assertRaises(backup.BackupProjectionError):
            backup.compile_backup_projection(eff2)

    def test_resolve_native_dump_failures(self):
        with self.assertRaises(backup.NativeDumpProjectionError):
            backup.resolve_native_dump({}, "missing")
        with self.assertRaises(backup.NativeDumpProjectionError):
            backup.resolve_native_dump({"storageResources": {"x": {"path": "/x", "stateClass": "authoritative", "backup": {"enabled": False}}}, "services": {}}, "x")

    def test_prepare_cleanup_verify(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = pathlib.Path(tmp)
            inv = t / "inv.json"
            paths = t / "paths"
            state = t / "state.json"
            # empty inventory fails schema
            inv.write_text(json.dumps({"schemaVersion": 99, "resources": []}), encoding="utf-8")
            with self.assertRaises(backup.BackupRuntimeError):
                backup.prepare(inventory_path=inv, paths_path=paths, state_path=state, zfs_bin="true", systemctl_bin="true")
            # cleanup with no state is ok
            state.unlink(missing_ok=True)
            res = backup.cleanup(state_path=state, paths_path=paths, zfs_bin="true")
            self.assertEqual(res["destroyed"], [])
            # verify helpers
            inv.write_text(json.dumps({"schemaVersion": 1, "resources": [{"id": "r", "path": "/srv/r", "consistency": "filesystem"}]}), encoding="utf-8")
            root = t / "restore"
            # missing restore root fails
            with self.assertRaises(backup.BackupVerificationError):
                backup.verify(inventory_path=inv, restore_root=root, pg_restore_bin="true")
            root.mkdir()
            # missing resource file fails
            with self.assertRaises(backup.BackupVerificationError):
                backup.verify(inventory_path=inv, restore_root=root, pg_restore_bin="true")
            # create file then verify succeeds
            (root / "srv" / "r").mkdir(parents=True)
            (root / "srv" / "r" / "file").write_text("data", encoding="utf-8")
            # actually resource path is /srv/r -> restored path is root/srv/r
            # verify checks candidates exist — for filesystem, candidate is root/srv/r itself
            # So need to ensure that candidate exists as directory
            res2 = backup.verify(inventory_path=inv, restore_root=root, pg_restore_bin="true")
            self.assertEqual(res2["schemaVersion"], 1)
            # build parsers
            self.assertIsNotNone(backup.build_verify_parser())
            self.assertIsNotNone(backup.build_parser())
            # _has_prefix and _verify_sqlite
            f = t / "test.txt"
            f.write_bytes(b"hello")
            self.assertTrue(backup._has_prefix(f, b"hel", restore_root=t))
            self.assertFalse(backup._has_prefix(f, b"world", restore_root=t))
            # verify_main failure path
            rc = backup.verify_main(["--inventory", str(inv), "--restore-root", str(t / "nonexistent")])
            self.assertEqual(rc, 2)
            # main prepare with mocked run
            inv2 = t / "inv2.json"
            inv2.write_text(json.dumps({"schemaVersion": 1, "resources": []}), encoding="utf-8")
            with mock.patch("nas_v2_backup._run", return_value="ok"):
                out_paths = t / "out_paths"
                out_state = t / "out_state"
                # empty resources should produce empty runtime paths
                result = backup.prepare(inventory_path=inv2, paths_path=out_paths, state_path=out_state, zfs_bin="true", systemctl_bin="true")
                self.assertEqual(result["paths"], [])


class NetworkGapTests(unittest.TestCase):
    def test_bridge_and_policy_names(self):
        self.assertTrue(net.bridge_interface_name("svc").startswith("nv2"))
        for fn in (net.zone_name, net.host_policy_name, net.lan_policy_name, net.world_policy_name, net.route_policy_name, net.listener_policy_name):
            self.assertTrue(fn("svc").startswith("nv2"))
        self.assertEqual(net.network_policy({}, {}), {"mode": "host", "outboundDefault": "allow", "lanAccess": False, "allowedHostPorts": [], "allowedEgress": []})
        self.assertIsNone(net.vlan_binding({}))
        with self.assertRaises(net.PodmanNetworkProjectionError):
            net.vlan_binding({"vlanId": 10})  # missing parent
        with self.assertRaises(net.PodmanNetworkProjectionError):
            net.vlan_binding({"vlanId": 9999, "vlanParent": "eth0"})
        self.assertFalse(net.requires_firewalld({"services": {"a": {"enabled": False, "network": {"mode": "host"}}}}))
        self.assertEqual(net.quadlet_network_reference({"services": {}}, "s", {"network": {"mode": "host"}}), "host")
        self.assertEqual(net.quadlet_network_reference({"services": {}}, "s", {"network": {"mode": "none"}}), "none")
        with self.assertRaises(net.PodmanNetworkProjectionError):
            net.quadlet_network_reference({"services": {}}, "s", {"network": {"mode": "none"}, "listeners": {"x": {}}})
        # compile_projection empty is no-op
        files, manifest = net.compile_projection({"services": {}}, lan_zone="trusted")
        self.assertEqual(files, {})
        with self.assertRaises(net.FirewalldProjectionError):
            net.compile_projection({"services": {}}, lan_zone="bad zone!")

    def test_augment_projection_noop(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp)
            files = {}
            manifest = {"quadletLinks": [], "links": [], "ownedUnits": []}
            net.augment_projection({"services": {}}, output_dir=out, files=files, manifest=manifest)
            self.assertEqual(files, {})

    def test_reconcile_requires_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = pathlib.Path(tmp)
            # missing manifest fails
            with self.assertRaises(net.FirewalldReconcileError):
                net.reconcile(manifest_path=t / "missing.json", projection_root=t, system_config=t / "sys", firewall_cmd="true", firewall_offline_cmd="true")
            # safe target rejects outside namespace
            with self.assertRaises(net.FirewalldReconcileError):
                net._safe_target("zones/bad.xml")


class BootstrapGapTests(unittest.TestCase):
    def test_is_seed_stub_and_yaml_files(self):
        from ruamel.yaml.comments import CommentedMap
        stub = CommentedMap()
        stub["schemaVersion"] = 3
        stub["services"] = CommentedMap()
        self.assertTrue(bootstrap._is_seed_stub(stub))
        stub["extra"] = 1
        self.assertFalse(bootstrap._is_seed_stub(stub))
        with tempfile.TemporaryDirectory() as tmp:
            d = pathlib.Path(tmp)
            self.assertEqual(bootstrap._yaml_files(d), [])
            (d / "a.yaml").write_text("x: 1", encoding="utf-8")
            self.assertEqual(len(bootstrap._yaml_files(d)), 1)
            self.assertTrue(bootstrap._is_directory_desired(d))
            self.assertFalse(bootstrap._is_directory_desired(d / "a.yaml"))

    def test_atomic_dump_and_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = pathlib.Path(tmp)
            p = d / "svc.yaml"
            from ruamel.yaml.comments import CommentedMap
            cm = CommentedMap()
            cm["schemaVersion"] = 3
            cm["services"] = CommentedMap()
            bootstrap._atomic_dump(p, cm)
            self.assertTrue(p.exists())
            marker = d / "marker"
            marker.write_text("", encoding="utf-8")
            bootstrap._clear_marker(marker)
            self.assertFalse(marker.exists())
            bootstrap._clear_marker(marker)  # noop

    def test_migrate_no_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = pathlib.Path(tmp)
            desired = d / "desired.yaml"
            seed = d / "seed.yaml"
            marker = d / "marker"
            seed.write_text("schemaVersion: 3\nservices: {}\n", encoding="utf-8")
            desired.write_text("schemaVersion: 3\nservices: {}\n", encoding="utf-8")
            # no marker => unchanged
            res = bootstrap.migrate(desired=desired, seed=seed, marker=marker, schema=SCHEMA, platform=None)
            self.assertFalse(res["changed"])


class ApplyGapTests(unittest.TestCase):
    def test_yaml_files_and_desired_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = pathlib.Path(tmp)
            self.assertEqual(apply_mod._yaml_files(d), [])
            (d / "a.yaml").write_text("x", encoding="utf-8")
            self.assertEqual(len(apply_mod._yaml_files(d)), 1)
            target = apply_mod._desired_target(d)
            self.assertTrue(str(target).endswith(".yaml"))
            # is_intended_directory
            self.assertTrue(apply_mod._is_intended_directory(d))
            self.assertFalse(apply_mod._is_intended_directory(d / "a.yaml"))
            self.assertTrue(apply_mod._is_intended_directory(d / "newdir"))

    def test_bind_platform_vlan_parent(self):
        eff = {"services": {"s": {"managed": True, "enabled": True, "network": {"vlanId": 10}, "networkProfile": None}}, "networkProfiles": {}}
        # missing vlanParent env -> error
        with self.assertRaises(sysd.SystemdProjectionError):
            apply_mod._bind_platform_vlan_parent(eff, None)
        bound = apply_mod._bind_platform_vlan_parent(eff, "eth0")
        self.assertEqual(bound["services"]["s"]["network"]["vlanParent"], "eth0")
        # no vlan -> unchanged
        eff2 = {"services": {"s": {"managed": True, "enabled": True, "network": {"mode": "host"}}}, "networkProfiles": {}}
        self.assertEqual(apply_mod._bind_platform_vlan_parent(eff2, "eth0"), eff2)

    def test_service_storage_dirs_and_ensure(self):
        eff = {"services": {"demo": {"managed": True, "enabled": True, "runtime": {"type": "exec", "command": ["/bin/true"]}}}}
        dirs = apply_mod._service_storage_dirs(eff)
        self.assertTrue(any("demo" in str(d) for d in dirs))
        # ensure does not raise
        apply_mod._ensure_service_dirs(eff)

    def test_stale_and_replace_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            # create stale candidate
            p = root / "units" / "nas-v2-demo.service"
            p.parent.mkdir(parents=True)
            p.write_text("old", encoding="utf-8")
            cur = {p}
            stale = apply_mod._projection_stale_files(root, cur)
            self.assertEqual(stale, set())
            # new stale file not in current
            extra = root / "units" / "nas-v2-extra.service"
            extra.write_text("extra", encoding="utf-8")
            stale2 = apply_mod._projection_stale_files(root, cur)
            self.assertIn(extra, stale2)
            # replace bundle
            dest = root / "out.json"
            changed = apply_mod._replace_bundle([(dest, b"hello", 0o644)])
            self.assertIn(dest, changed)
            # second call no change
            changed2 = apply_mod._replace_bundle([(dest, b"hello", 0o644)])
            self.assertEqual(changed2, set())


class SessionGapTests(unittest.TestCase):
    def test_validate_and_unit_names(self):
        self.assertEqual(sess.validate_service_id("my-service"), "my-service")
        with self.assertRaises(sess.SessionError):
            sess.validate_service_id("Bad")
        self.assertEqual(sess.validate_instance_id("abc-123"), "abc-123")
        with self.assertRaises(sess.SessionError):
            sess.validate_instance_id("Bad!")
        self.assertEqual(sess.validate_user_id("alice@example.com"), "alice@example.com")
        with self.assertRaises(sess.SessionError):
            sess.validate_user_id("..")
        self.assertTrue(sess.unit_name("demo", "inst").endswith(".service"))
        self.assertIn("u", sess.unit_name("demo", "inst", user_id="alice"))
        self.assertTrue(sess.container_name("demo", "inst").startswith("nas-v2-session"))

    def test_safe_path_and_storage(self):
        with self.assertRaises(sess.SessionError):
            sess._safe_path("relative", field="test")
        with self.assertRaises(sess.SessionError):
            sess._safe_path("/bad:colon", field="test")
        self.assertFalse(is_cdi_selector("/dev/nvidia0"))
        self.assertTrue(is_cdi_selector("nvidia.com/gpu=0"))

    def test_accelerator_helpers(self):
        inv = {"schemaVersion": 1, "devices": [], "cdi": {"nvidia.com/gpu": ["0"]}, "capabilities": {"accelerator:nvidia.com/gpu": True}}
        caps = enabled_capabilities(inv)
        self.assertIsInstance(caps, set)
        with tempfile.TemporaryDirectory() as tmp:
            p = pathlib.Path(tmp) / "inv.json"
            p.write_text(json.dumps({"schemaVersion": 1, "devices": [{"path": "/dev/dri/card0"}], "capabilities": {"kvm": True}}), encoding="utf-8")
            inv2 = load_platform_inventory(p)
            self.assertIsInstance(inv2, dict)


class ReconcileGapTests(unittest.TestCase):
    def test_safe_targets_and_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "proj"
            runtime = pathlib.Path(tmp) / "run"
            root.mkdir()
            runtime.mkdir()
            # source file
            src = root / "demo.service"
            src.write_text("content", encoding="utf-8")
            # safe target valid
            p, name = recon._safe_target(runtime, "demo.service")
            self.assertEqual(name, "demo.service")
            with self.assertRaises(recon.SystemdReconcileError):
                recon._safe_target(runtime, "../escape.service")
            # quadlet target
            pq, _ = recon._safe_quadlet_target(runtime, "nas-v2-demo.container")
            self.assertTrue(str(pq).endswith(".container"))
            with self.assertRaises(recon.SystemdReconcileError):
                recon._safe_quadlet_target(runtime, "bad.container")
            # source_under success
            res = recon._source_under(root, str(src))
            self.assertEqual(res, src.resolve())
            with self.assertRaises(recon.SystemdReconcileError):
                recon._source_under(root, "/etc/passwd")


if __name__ == "__main__":
    unittest.main()
