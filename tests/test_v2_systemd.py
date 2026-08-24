from __future__ import annotations

import json
import pathlib
import stat
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
SCHEMA = ROOT / "schemas" / "managed-services-v3.schema.json"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_spec as v2  # noqa: E402
import nas_v2_systemd as systemd  # noqa: E402
import nas_v2_systemd_attachments as attachments  # noqa: E402


class V2SystemdProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = v2.load_schema(SCHEMA)

    def compile(
        self,
        services: dict,
        *,
        storage: dict | None = None,
        credentials: dict | None = None,
    ) -> dict:
        document: dict = {"schemaVersion": 3, "services": services}
        if storage is not None:
            document["storageResources"] = storage
        if credentials is not None:
            document["credentials"] = credentials
        return v2.compile_document(document, self.schema)

    def generate(self, effective: dict, output: pathlib.Path) -> tuple[dict[pathlib.Path, bytes], dict]:
        return systemd.generate_projection(
            effective,
            output_dir=output,
            python_bin="/run/current-system/sw/bin/python3",
            source_dir=pathlib.Path("/nix/store/v2/services"),
            systemctl_bin="/run/current-system/sw/bin/systemctl",
            uv_bin="/nix/store/uv/bin/uv",
        )

    @staticmethod
    def route(port: int = 8080) -> dict:
        return {
            "web": {
                "target": {"type": "http", "port": port},
                "exposure": {"type": "path", "paths": ["/demo/"]},
                "auth": {"mode": "public"},
            }
        }

    def test_exec_daemon_is_shell_free_hardened_and_resource_limited(self):
        effective = self.compile(
            {
                "demo": {
                    "name": "Demo",
                    "workload": {"kind": "daemon", "activation": "persistent"},
                    "runtime": {
                        "type": "exec",
                        "command": ["/bin/echo", "hello; not-a-shell"],
                        "environment": {"DEMO": "hello world"},
                    },
                    "resources": {
                        "cpuQuotaPercent": 75,
                        "memoryMaxBytes": 1048576,
                        "pidsMax": 32,
                    },
                }
            }
        )
        files, manifest = self.generate(effective, pathlib.Path("/run/nas-control/systemd"))
        unit = files[pathlib.Path("/run/nas-control/systemd/units/nas-v2-demo.service")].decode()
        descriptor = json.loads(files[pathlib.Path("/run/nas-control/systemd/descriptors/demo.exec.json")])

        self.assertIn("DynamicUser=yes", unit)
        self.assertIn("ProtectSystem=strict", unit)
        self.assertIn("CPUQuota=75%", unit)
        self.assertIn("MemoryMax=1048576", unit)
        self.assertIn("TasksMax=32", unit)
        self.assertIn("nas_v2_exec_runner.py", unit)
        self.assertNotIn("hello; not-a-shell", unit)
        self.assertEqual(descriptor["command"][1], "hello; not-a-shell")
        self.assertEqual(manifest["startUnits"], ["nas-v2-demo.service"])

    def test_python_runtime_delegates_environment_and_dependencies_to_uv(self):
        with tempfile.TemporaryDirectory() as tmp:
            app_root = pathlib.Path(tmp) / "apps"
            service_root = app_root / "demo"
            service_root.mkdir(parents=True)
            requirements = service_root / "requirements.lock"
            requirements.write_text("example==1.0 --hash=sha256:" + "1" * 64 + "\n", encoding="utf-8")
            with (
                mock.patch.object(v2, "APP_ROOT", pathlib.PurePosixPath(str(app_root))),
                mock.patch.object(systemd, "APP_ROOT", app_root),
            ):
                effective = self.compile(
                    {
                        "demo": {
                            "name": "Demo Python",
                            "workload": {"kind": "daemon", "activation": "persistent"},
                            "runtime": {
                                "type": "python",
                                "interpreter": "/run/current-system/sw/bin/python3",
                                "dependencies": {
                                    "requirementsFile": str(requirements),
                                    "requireHashes": True,
                                },
                                "entrypoint": {"module": "demo.server", "args": ["--serve"]},
                            },
                        }
                    }
                )
                files, manifest = self.generate(effective, pathlib.Path("/run/nas-control/systemd"))

        unit_path = pathlib.Path("/run/nas-control/systemd/units/nas-v2-demo.service")
        unit = files[unit_path].decode()
        self.assertIn('ExecStart="/nix/store/uv/bin/uv" "run"', unit)
        self.assertIn('"--with-requirements"', unit)
        self.assertIn(f'"{requirements}"', unit)
        self.assertIn('"-m" "demo.server" "--serve"', unit)
        self.assertIn("DynamicUser=yes", unit)
        self.assertIn("CacheDirectory=nas-v2-uv/demo", unit)
        self.assertIn('Environment="UV_CACHE_DIR=/var/cache/nas-v2-uv/demo"', unit)
        self.assertIn("Environment=UV_REQUIRE_HASHES=1", unit)
        self.assertNotIn("nas_v2_python_prepare.py", unit)
        self.assertNotIn("nas_v2_exec_runner.py", unit)
        self.assertNotIn("StateDirectory=nas-control/venvs/demo", unit)
        self.assertFalse(any("python-env" in str(path) or "python-exec" in str(path) for path in files))
        self.assertIn("nas-v2-demo.service", manifest["startUnits"])

    def test_python_requirements_content_changes_owner_fingerprint(self):
        with tempfile.TemporaryDirectory() as tmp:
            app_root = pathlib.Path(tmp) / "apps"
            service_root = app_root / "demo"
            service_root.mkdir(parents=True)
            requirements = service_root / "requirements.lock"
            requirements.write_text("example==1.0\n", encoding="utf-8")
            service = {
                "demo": {
                    "name": "Demo Python",
                    "workload": {"kind": "daemon", "activation": "persistent"},
                    "runtime": {
                        "type": "python",
                        "dependencies": {"requirementsFile": str(requirements), "requireHashes": False},
                        "entrypoint": {"module": "demo.server"},
                    },
                }
            }
            with (
                mock.patch.object(v2, "APP_ROOT", pathlib.PurePosixPath(str(app_root))),
                mock.patch.object(systemd, "APP_ROOT", app_root),
            ):
                effective = self.compile(service)
                _files1, manifest1 = self.generate(effective, pathlib.Path("/run/nas-control/systemd"))
                requirements.write_text("example==2.0\n", encoding="utf-8")
                _files2, manifest2 = self.generate(effective, pathlib.Path("/run/nas-control/systemd"))

        self.assertNotEqual(
            manifest1["fingerprints"]["nas-v2-demo.service"],
            manifest2["fingerprints"]["nas-v2-demo.service"],
        )

    def test_on_demand_daemon_gets_native_socket_proxy_and_no_lease_timer(self):
        effective = self.compile(
            {
                "demo": {
                    "name": "Demo",
                    "workload": {"kind": "daemon", "activation": "on-demand", "idleSeconds": 90},
                    "runtime": {"type": "exec", "command": ["/bin/true"]},
                    "readiness": {"probes": [{"type": "path", "path": "/run/demo.ready"}]},
                    "routes": self.route(),
                }
            }
        )
        files, manifest = self.generate(effective, pathlib.Path("/run/nas-control/systemd"))
        owner = files[pathlib.Path("/run/nas-control/systemd/units/nas-v2-demo.service")].decode()
        socket = files[pathlib.Path("/run/nas-control/systemd/units/nas-v2-activate-demo-web.socket")].decode()
        proxy = files[pathlib.Path("/run/nas-control/systemd/units/nas-v2-activate-demo-web.service")].decode()

        self.assertIn("StopWhenUnneeded=yes", owner)
        self.assertIn("ListenStream=/run/nas-control/activate/demo-web.sock", socket)
        self.assertIn("SocketUser=caddy", socket)
        self.assertIn("Requires=nas-v2-demo.service nas-v2-activate-demo-web.socket nas-v2-ready-demo.service", proxy)
        self.assertIn("--exit-idle-time=90s", proxy)
        self.assertIn("nas-v2-activate-demo-web.socket", manifest["startUnits"])
        self.assertNotIn("nas-v2-demo.service", manifest["startUnits"])
        self.assertFalse(any("nas-v2-lease-" in unit or "nas-v2-idle-" in unit for unit in manifest["ownedUnits"]))

    def test_ready_dependency_uses_transient_gate(self):
        effective = self.compile(
            {
                "backend": {
                    "name": "Backend",
                    "workload": {"kind": "daemon", "activation": "persistent"},
                    "runtime": {"type": "systemd", "unit": "backend.service"},
                    "readiness": {"probes": [{"type": "tcp", "port": 8080}]},
                },
                "frontend": {
                    "name": "Frontend",
                    "workload": {"kind": "daemon", "activation": "persistent"},
                    "runtime": {"type": "exec", "command": ["/bin/true"]},
                    "dependencies": [{"service": "backend", "condition": "ready"}],
                },
            }
        )
        files, _manifest = self.generate(effective, pathlib.Path("/run/nas-control/systemd"))
        frontend = files[pathlib.Path("/run/nas-control/systemd/units/nas-v2-frontend.service")].decode()
        gate = files[pathlib.Path("/run/nas-control/systemd/units/nas-v2-ready-backend.service")].decode()

        self.assertIn("Requires=backend.service nas-v2-ready-backend.service", frontend)
        self.assertIn("PartOf=backend.service", gate)
        self.assertNotIn("RemainAfterExit=yes", gate)

    def test_job_schedule_becomes_native_timer(self):
        effective = self.compile(
            {
                "verify": {
                    "name": "Verify",
                    "workload": {
                        "kind": "job",
                        "schedules": [
                            {"calendar": "daily", "randomizedDelaySeconds": 900, "persistent": True}
                        ],
                    },
                    "runtime": {"type": "exec", "command": ["/bin/true"]},
                }
            }
        )
        files, manifest = self.generate(effective, pathlib.Path("/run/nas-control/systemd"))
        timer = files[pathlib.Path("/run/nas-control/systemd/units/nas-v2-timer-verify-0.timer")].decode()

        self.assertIn("OnCalendar=daily", timer)
        self.assertIn("RandomizedDelaySec=900s", timer)
        self.assertIn("Persistent=true", timer)
        self.assertIn("nas-v2-timer-verify-0.timer", manifest["startUnits"])
        self.assertNotIn("nas-v2-verify.service", manifest["startUnits"])

    def test_existing_systemd_runtime_gets_only_explicit_dropin_policy(self):
        effective = self.compile(
            {
                "demo": {
                    "name": "Demo",
                    "workload": {"kind": "daemon", "activation": "persistent"},
                    "runtime": {"type": "systemd", "unit": "demo.service"},
                    "resources": {"memoryHighBytes": 4096},
                }
            }
        )
        files, manifest = self.generate(effective, pathlib.Path("/run/nas-control/systemd"))
        dropin_path = pathlib.Path("/run/nas-control/systemd/units/demo.service.d/50-nas-v2.conf")
        dropin = files[dropin_path].decode()

        self.assertIn("MemoryHigh=4096", dropin)
        self.assertNotIn("ProtectSystem", dropin)
        self.assertIn({"target": "demo.service.d/50-nas-v2.conf", "source": str(dropin_path)}, manifest["links"])

    def test_read_only_storage_is_lowered_directly_into_generated_owner(self):
        effective = self.compile(
            {
                "demo": {
                    "name": "Demo",
                    "workload": {"kind": "daemon", "activation": "persistent"},
                    "runtime": {"type": "exec", "command": ["/bin/true"]},
                    "storage": [{"resource": "media", "mountPath": "/media", "access": "read"}],
                }
            },
            storage={"media": {"path": "/tank/media", "stateClass": "authoritative"}},
        )
        files, _manifest = self.generate(effective, pathlib.Path("/run/nas-control/systemd"))
        unit = files[pathlib.Path("/run/nas-control/systemd/units/nas-v2-demo.service")].decode()
        self.assertIn('BindReadOnlyPaths="/tank/media:/media"', unit)

    def test_dynamic_generated_runtime_refuses_writable_host_storage(self):
        effective = self.compile(
            {
                "demo": {
                    "name": "Demo",
                    "workload": {"kind": "daemon", "activation": "persistent"},
                    "runtime": {"type": "exec", "command": ["/bin/true"]},
                    "storage": [{"resource": "data", "mountPath": "/data", "access": "write"}],
                }
            },
            storage={"data": {"path": "/tank/data", "stateClass": "authoritative"}},
        )
        with self.assertRaisesRegex(systemd.SystemdProjectionError, "DynamicUser writable bind"):
            self.generate(effective, pathlib.Path("/run/nas-control/systemd"))

    def test_existing_identity_and_native_systemd_can_receive_writable_storage(self):
        generated = self.compile(
            {
                "demo": {
                    "name": "Demo",
                    "workload": {"kind": "daemon", "activation": "persistent"},
                    "runtime": {
                        "type": "exec",
                        "command": ["/bin/true"],
                        "identity": {"mode": "existing", "user": "demo"},
                    },
                    "storage": [{"resource": "data", "mountPath": "/data", "access": "write"}],
                }
            },
            storage={"data": {"path": "/tank/data", "stateClass": "authoritative"}},
        )
        generated_files, _manifest = self.generate(generated, pathlib.Path("/run/nas-control/systemd"))
        generated_unit = generated_files[pathlib.Path("/run/nas-control/systemd/units/nas-v2-demo.service")].decode()
        self.assertIn('BindPaths="/tank/data:/data"', generated_unit)

        native = self.compile(
            {
                "demo": {
                    "name": "Demo",
                    "workload": {"kind": "daemon", "activation": "persistent"},
                    "runtime": {"type": "systemd", "unit": "demo.service"},
                    "storage": [{"resource": "data", "mountPath": "/data", "access": "write"}],
                }
            },
            storage={"data": {"path": "/tank/data", "stateClass": "authoritative"}},
        )
        native_files, _manifest = self.generate(native, pathlib.Path("/run/nas-control/systemd"))
        dropin = native_files[pathlib.Path("/run/nas-control/systemd/units/demo.service.d/50-nas-v2.conf")].decode()
        self.assertIn('BindPaths="/tank/data:/data"', dropin)

    def test_environment_file_and_native_reference_credentials_are_native_directives(self):
        effective = self.compile(
            {
                "demo": {
                    "name": "Demo",
                    "workload": {"kind": "daemon", "activation": "persistent"},
                    "runtime": {"type": "exec", "command": ["/bin/true"]},
                    "credentials": [
                        {"credential": "env", "use": "environment-file"},
                        {"credential": "token", "use": "native-reference"},
                    ],
                }
            },
            credentials={
                "env": {"path": "/run/nas-secrets/demo/app.env", "required": False},
                "token": {"path": "/run/nas-secrets/demo/token", "required": True},
            },
        )
        files, _manifest = self.generate(effective, pathlib.Path("/run/nas-control/systemd"))
        unit = files[pathlib.Path("/run/nas-control/systemd/units/nas-v2-demo.service")].decode()

        self.assertIn('EnvironmentFile=-"/run/nas-secrets/demo/app.env"', unit)
        self.assertIn('LoadCredential="token:/run/nas-secrets/demo/token"', unit)
        self.assertNotIn("super-secret-value", unit)

    def test_file_credential_use_projects_fixed_read_only_mount(self):
        effective = self.compile(
            {
                "demo": {
                    "name": "Demo",
                    "workload": {"kind": "daemon", "activation": "persistent"},
                    "runtime": {"type": "exec", "command": ["/bin/true"]},
                    "credentials": [{"credential": "token", "use": "file", "mountPath": "/run/app/token"}],
                }
            },
            credentials={"token": {"path": "/run/nas-secrets/demo/token", "required": True}},
        )
        files, _manifest = self.generate(effective, pathlib.Path("/run/nas-control/systemd"))
        unit = files[pathlib.Path("/run/nas-control/systemd/units/nas-v2-demo.service")].decode()
        self.assertIn('BindReadOnlyPaths="/run/nas-secrets/demo/token:/run/app/token"', unit)

    def test_strict_sandbox_refuses_storage_destination_hidden_by_protect_home(self):
        effective = self.compile(
            {
                "demo": {
                    "name": "Demo",
                    "workload": {"kind": "daemon", "activation": "persistent"},
                    "runtime": {"type": "exec", "command": ["/bin/true"]},
                    "storage": [{"resource": "home", "mountPath": "/home/demo/data", "access": "read"}],
                }
            },
            storage={"home": {"path": "/tank/home", "stateClass": "authoritative"}},
        )
        with self.assertRaisesRegex(systemd.SystemdProjectionError, "ProtectHome"):
            self.generate(effective, pathlib.Path("/run/nas-control/systemd"))

    def test_attachment_change_changes_owner_fingerprint(self):
        effective = self.compile(
            {
                "demo": {
                    "name": "Demo",
                    "workload": {"kind": "daemon", "activation": "persistent"},
                    "runtime": {"type": "systemd", "unit": "demo.service"},
                }
            }
        )
        _files1, manifest1 = self.generate(effective, pathlib.Path("/run/nas-control/systemd"))
        effective["storageResources"] = {"media": {"path": "/tank/media"}}
        effective["services"]["demo"]["storage"] = [
            {"resource": "media", "mountPath": "/media", "access": "read"}
        ]
        _files2, manifest2 = self.generate(effective, pathlib.Path("/run/nas-control/systemd"))
        self.assertNotEqual(
            manifest1["fingerprints"]["demo.service"],
            manifest2["fingerprints"]["demo.service"],
        )

    def test_attachment_helper_is_pure_and_does_not_read_secret_contents(self):
        service = {
            "runtime": {"type": "exec", "identity": {"mode": "dynamic"}},
            "sandbox": {"mode": "strict"},
            "storage": [],
            "credentials": [{"credential": "token", "use": "native-reference"}],
        }
        effective = {
            "storageResources": {},
            "credentials": {"token": {"path": "/run/nas-secrets/demo/token", "required": True}},
        }
        self.assertEqual(
            attachments.attachment_lines(effective, service),
            ['LoadCredential="token:/run/nas-secrets/demo/token"'],
        )

    def test_exec_environment_emitted_via_unit_not_persisted(self):
        effective = self.compile(
            {
                "demo": {
                    "name": "Demo",
                    "workload": {"kind": "daemon", "activation": "persistent"},
                    "runtime": {
                        "type": "exec",
                        "command": ["/bin/true"],
                        "environment": {"SECRET_TOKEN": "super-secret-value", "NORMAL": "hello world"},
                    },
                }
            }
        )
        files, _manifest = self.generate(effective, pathlib.Path("/run/nas-control/systemd"))
        unit = files[pathlib.Path("/run/nas-control/systemd/units/nas-v2-demo.service")].decode()
        descriptor = json.loads(files[pathlib.Path("/run/nas-control/systemd/descriptors/demo.exec.json")].decode())
        self.assertNotIn("environment", descriptor)
        self.assertNotIn("super-secret-value", json.dumps(descriptor))
        self.assertIn('Environment="NORMAL=hello world"', unit)
        self.assertIn('Environment="SECRET_TOKEN=super-secret-value"', unit)

    def test_python_environment_is_emitted_directly_without_custom_descriptor(self):
        effective = self.compile(
            {
                "demo": {
                    "name": "Demo Python",
                    "workload": {"kind": "daemon", "activation": "persistent"},
                    "runtime": {
                        "type": "python",
                        "interpreter": "/run/current-system/sw/bin/python3",
                        "dependencies": {"requireHashes": False},
                        "entrypoint": {"module": "demo.server"},
                        "environment": {"SECRET": "s3cr3t"},
                    },
                }
            }
        )
        files, _manifest = self.generate(effective, pathlib.Path("/run/nas-control/systemd"))
        unit = files[pathlib.Path("/run/nas-control/systemd/units/nas-v2-demo.service")].decode()
        self.assertIn('Environment="SECRET=s3cr3t"', unit)
        self.assertIn('ExecStart="/nix/store/uv/bin/uv" "run"', unit)
        self.assertFalse(any("python-exec" in str(path) or "python-env" in str(path) for path in files))

    def test_on_demand_daemon_forces_restart_no(self):
        for runtime in [
            {"type": "exec", "command": ["/bin/true"], "restart": "always"},
            {"type": "exec", "command": ["/bin/true"], "restart": "on-failure"},
        ]:
            effective = self.compile(
                {
                    "demo": {
                        "name": "Demo",
                        "workload": {"kind": "daemon", "activation": "on-demand", "idleSeconds": 30},
                        "runtime": runtime,
                        "routes": self.route(),
                    }
                }
            )
            files, _manifest = self.generate(effective, pathlib.Path("/run/nas-control/systemd"))
            unit = files[pathlib.Path("/run/nas-control/systemd/units/nas-v2-demo.service")].decode()
            self.assertNotIn("Restart=always", unit)
            self.assertNotIn("Restart=on-failure", unit)
            self.assertNotIn("Restart=", unit)
        effective = self.compile(
            {
                "demo": {
                    "name": "Demo Python",
                    "workload": {"kind": "daemon", "activation": "on-demand", "idleSeconds": 45},
                    "runtime": {
                        "type": "python",
                        "interpreter": "/run/current-system/sw/bin/python3",
                        "dependencies": {"requireHashes": False},
                        "entrypoint": {"module": "demo.server"},
                        "restart": "always",
                    },
                    "routes": self.route(),
                }
            }
        )
        files, _manifest = self.generate(effective, pathlib.Path("/run/nas-control/systemd"))
        unit = files[pathlib.Path("/run/nas-control/systemd/units/nas-v2-demo.service")].decode()
        self.assertNotIn("Restart=always", unit)
        self.assertNotIn("Restart=", unit)
        effective = self.compile(
            {
                "demo": {
                    "name": "Demo",
                    "workload": {"kind": "daemon", "activation": "persistent"},
                    "runtime": {"type": "exec", "command": ["/bin/true"], "restart": "always"},
                }
            }
        )
        files, _manifest = self.generate(effective, pathlib.Path("/run/nas-control/systemd"))
        unit = files[pathlib.Path("/run/nas-control/systemd/units/nas-v2-demo.service")].decode()
        self.assertIn("Restart=always", unit)

    def test_environment_file_credential_references_secret_path_not_value(self):
        effective = self.compile(
            {
                "demo": {
                    "name": "Demo",
                    "workload": {"kind": "daemon", "activation": "persistent"},
                    "runtime": {"type": "exec", "command": ["/bin/true"]},
                    "credentials": [{"credential": "env", "use": "environment-file"}],
                }
            },
            credentials={"env": {"path": "/run/nas-secrets/demo/app.env", "required": True}},
        )
        files, _manifest = self.generate(effective, pathlib.Path("/run/nas-control/systemd"))
        unit = files[pathlib.Path("/run/nas-control/systemd/units/nas-v2-demo.service")].decode()
        self.assertIn('EnvironmentFile="/run/nas-secrets/demo/app.env"', unit)
        self.assertNotIn("super-secret-value", unit)
        for line in unit.splitlines():
            if "app.env" in line:
                self.assertIn("EnvironmentFile=", line)
                self.assertNotIn("Environment=", line.replace("EnvironmentFile=", ""))

    def test_systemd_analyze_validation_failure_is_fatal(self):
        effective = self.compile(
            {
                "demo": {
                    "name": "Demo",
                    "workload": {"kind": "daemon", "activation": "persistent"},
                    "runtime": {"type": "exec", "command": ["/bin/true"]},
                }
            }
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            files, _manifest = self.generate(effective, root / "projection")
            validator = root / "systemd-analyze"
            validator.write_text("#!/bin/sh\nexit 7\n", encoding="utf-8")
            validator.chmod(validator.stat().st_mode | stat.S_IXUSR)
            with self.assertRaisesRegex(systemd.SystemdProjectionError, "rejected"):
                systemd.validate_projection(files, systemd_analyze_bin=str(validator))


if __name__ == "__main__":
    unittest.main()
