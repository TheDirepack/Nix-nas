from __future__ import annotations

import os
import pathlib
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
SCHEMA = ROOT / "schemas" / "managed-services-v3.schema.json"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_accelerator as accelerator  # noqa: E402
import nas_v2_quadlet as quadlet  # noqa: E402
import nas_v2_spec as v2  # noqa: E402
import nas_v2_systemd_native as systemd  # noqa: E402


class V2QuadletTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = v2.load_schema(SCHEMA)

    def compile_service(self, service: dict, **top_level: dict) -> tuple[dict, dict]:
        document = {"schemaVersion": 3, "services": {"demo": service}, **top_level}
        effective = v2.compile_document(document, self.schema)
        return effective, effective["services"]["demo"]

    def render(self, effective: dict, service: dict) -> str:
        return quadlet.render_quadlet(
            effective,
            "demo",
            service,
            unit_lines=["Description=Demo"],
            service_lines=["MemoryMax=1048576"],
        ).decode()

    def test_oci_renders_native_image_pull_exec_and_strict_sandbox(self):
        effective, service = self.compile_service(
            {
                "name": "Demo",
                "workload": {"kind": "daemon", "activation": "persistent"},
                "runtime": {
                    "type": "oci",
                    "image": "docker.io/library/nginx:stable",
                    "pull": "missing",
                    "command": ["nginx", "-g", "daemon off;"],
                },
            }
        )
        rendered = self.render(effective, service)
        self.assertIn('[Container]\nImage="docker.io/library/nginx:stable"', rendered)
        self.assertIn("Pull=missing", rendered)
        self.assertIn('Exec="nginx" "-g" "daemon off;"', rendered)
        self.assertIn("Network=host", rendered)
        self.assertIn("ReadOnly=true", rendered)
        self.assertIn("NoNewPrivileges=true", rendered)
        self.assertIn("[Service]\nMemoryMax=1048576", rendered)

    def test_oci_storage_and_required_credentials_use_native_container_mounts(self):
        effective, service = self.compile_service(
            {
                "name": "Demo",
                "workload": {"kind": "daemon", "activation": "persistent"},
                "runtime": {"type": "oci", "image": "example.invalid/demo:1"},
                "storage": [
                    {"resource": "media", "mountPath": "/media", "access": "read"},
                    {"resource": "state", "mountPath": "/state", "access": "write"},
                ],
                "credentials": [
                    {"credential": "env", "use": "environment-file"},
                    {"credential": "token", "use": "file", "mountPath": "/run/secrets/token"},
                ],
            },
            storageResources={
                "media": {"path": "/tank/media", "stateClass": "authoritative"},
                "state": {"path": "/tank/state", "stateClass": "authoritative"},
            },
            credentials={
                "env": {"path": "/run/nas-secrets/demo/app.env", "required": True},
                "token": {"path": "/run/nas-secrets/demo/token", "required": True},
            },
        )
        rendered = self.render(effective, service)
        self.assertIn("Volume=/tank/media:/media:ro", rendered)
        self.assertIn("Volume=/tank/state:/state:rw", rendered)
        self.assertIn('EnvironmentFile="/run/nas-secrets/demo/app.env"', rendered)
        self.assertIn("Volume=/run/nas-secrets/demo/token:/run/secrets/token:ro", rendered)

    def test_verbatim_podman_keys_are_unquoted_and_percent_escaped(self):
        # Quadlet forwards Volume/Tmpfs without unquoting, so quotes
        # would reach Podman literally. Whitespace is escaped by Quadlet, and a
        # doubled percent survives systemd specifier expansion as one percent.
        effective, service = self.compile_service(
            {
                "name": "Demo",
                "workload": {"kind": "daemon", "activation": "persistent"},
                "runtime": {"type": "oci", "image": "example.invalid/demo:1"},
                "storage": [{"resource": "state", "mountPath": "/srv/my state", "access": "write"}],
                "sandbox": {"tmpfs": [{"path": "/tmp", "sizeBytes": 1024}]},
                "resources": {
                    "accelerators": [
                        {
                            "kind": "gpu",
                            "vendor": "AMD",
                            "device": "/dev/dri/renderD128",
                            "target": "/dev/dri/renderD128",
                            "required": True,
                        }
                    ]
                },
            },
            storageResources={"state": {"path": "/tank/100%state", "stateClass": "authoritative"}},
        )
        rendered = self.render(effective, service)
        self.assertIn("Volume=/tank/100%%state:/srv/my state:rw", rendered)
        self.assertIn("Tmpfs=/tmp:size=1024", rendered)
        self.assertNotIn('Volume="', rendered)
        self.assertNotIn('Tmpfs="', rendered)
        self.assertIn('AddDevice="/dev/dri/renderD128:/dev/dri/renderD128:rw"', rendered)

    def test_optional_or_native_reference_container_credentials_fail_closed(self):
        for credential, attachment, expected in (
            (
                {"path": "/run/nas-secrets/demo/env", "required": False},
                {"credential": "secret", "use": "environment-file"},
                "optional OCI environment credential",
            ),
            (
                {"path": "/run/nas-secrets/demo/token", "required": True},
                {"credential": "secret", "use": "native-reference"},
                "Podman secret reconciliation",
            ),
        ):
            with self.subTest(attachment=attachment):
                effective, service = self.compile_service(
                    {
                        "name": "Demo",
                        "workload": {"kind": "daemon", "activation": "persistent"},
                        "runtime": {"type": "oci", "image": "example.invalid/demo:1"},
                        "credentials": [attachment],
                    },
                    credentials={"secret": credential},
                )
                with self.assertRaisesRegex(quadlet.QuadletProjectionError, expected):
                    self.render(effective, service)

    def test_real_generator_preserves_attachment_arguments(self):
        generator = os.environ.get("NAS_V2_QUADLET_GENERATOR_BIN") or shutil.which("podman-system-generator")
        if not generator:
            generator = next(
                (
                    path
                    for path in (
                        "/usr/lib/systemd/system-generators/podman-system-generator",
                        "/usr/lib/podman/quadlet",
                    )
                    if os.access(path, os.X_OK)
                ),
                None,
            )
        if generator is None:
            self.skipTest("Podman Quadlet generator not available")
        effective, service = self.compile_service(
            {
                "name": "Demo",
                "workload": {"kind": "daemon", "activation": "persistent"},
                "runtime": {"type": "oci", "image": "example.invalid/demo:1", "pull": "never"},
                "storage": [{"resource": "state", "mountPath": "/srv/my state", "access": "write"}],
                "credentials": [{"credential": "token", "use": "file", "mountPath": "/run/secrets/token"}],
                "sandbox": {"tmpfs": [{"path": "/tmp/100% scratch", "sizeBytes": 1024}]},
                "resources": {
                    "accelerators": [
                        {
                            "kind": "gpu",
                            "vendor": "AMD",
                            "device": "/dev/dri/render 100% 'single' \"quoted\"\\tail",
                            "target": "/dev/dri/renderD128",
                            "required": True,
                        }
                    ]
                },
            },
            storageResources={"state": {"path": '/tank/100% state "quoted"\\tail', "stateClass": "authoritative"}},
            credentials={"token": {"path": "/run/nas-secrets/demo/token", "required": True}},
        )
        with tempfile.TemporaryDirectory(prefix="nas-test-quadlet-") as directory:
            (pathlib.Path(directory) / "demo.container").write_text(self.render(effective, service))
            result = subprocess.run(
                [generator, "--dryrun"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                env={**os.environ, "QUADLET_UNIT_DIRS": directory},
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        commands = [
            line.removeprefix("ExecStart=") for line in result.stdout.splitlines() if line.startswith("ExecStart=")
        ]
        self.assertEqual(len(commands), 1, result.stdout)
        # Inspect Quadlet's serialized arguments, not runtime systemd expansion:
        # C-style whitespace escapes and doubled specifiers must remain intact.
        arguments = shlex.split(commands[0])
        self.assertEqual(
            [arguments[i + 1] for i, value in enumerate(arguments) if value == "-v"],
            [
                r'/tank/100%%\x20state\x20"quoted"\tail:/srv/my\x20state:rw',
                "/run/nas-secrets/demo/token:/run/secrets/token:ro",
            ],
        )
        self.assertEqual(arguments[arguments.index("--tmpfs") + 1], r"/tmp/100%%\x20scratch:size=1024")
        self.assertEqual(
            [arguments[i + 1] for i, value in enumerate(arguments) if value == "--device"],
            [r"""/dev/dri/render\x20100%%\x20'single'\x20"quoted"\tail:/dev/dri/renderD128:rw"""],
        )

    def test_shell_supplies_the_pinned_quadlet_generator(self):
        self.assertTrue(
            'NAS_V2_QUADLET_GENERATOR_BIN = "${pkgs.podman}/lib/systemd/system-generators/podman-system-generator";'
            in (ROOT / "flake.nix").read_text(),
            "the Nix test shell must run the native regression against its pinned Podman generator",
        )

    def test_explicit_shared_device_maps_and_unresolved_required_gpu_fails(self):
        effective, _service = self.compile_service(
            {
                "name": "Demo",
                "workload": {"kind": "daemon", "activation": "persistent"},
                "runtime": {"type": "oci", "image": "example.invalid/demo:1"},
                "resources": {
                    "accelerators": [
                        {
                            "kind": "gpu",
                            "vendor": "AMD",
                            "device": "/dev/dri/renderD128",
                            "target": "/dev/dri/renderD128",
                            "required": True,
                        }
                    ]
                },
            }
        )
        inventory = {"schemaVersion": 1, "capabilities": {}, "accelerators": {}}
        effective = accelerator.resolve_effective(effective, inventory)
        rendered = self.render(effective, effective["services"]["demo"])
        self.assertIn('AddDevice="/dev/dri/renderD128:/dev/dri/renderD128:rw"', rendered)

        unresolved, _unresolved_service = self.compile_service(
            {
                "name": "Demo",
                "workload": {"kind": "daemon", "activation": "persistent"},
                "runtime": {"type": "oci", "image": "example.invalid/demo:1"},
                "resources": {"accelerators": [{"kind": "gpu", "vendor": "AMD", "required": True}]},
            }
        )
        with self.assertRaisesRegex(accelerator.AcceleratorResolutionError, "requires unavailable GPU request"):
            accelerator.resolve_effective(unresolved, inventory)

    def test_optional_unresolved_gpu_is_removed_before_quadlet_projection(self):
        effective, _service = self.compile_service(
            {
                "name": "Demo",
                "workload": {"kind": "daemon", "activation": "persistent"},
                "runtime": {"type": "oci", "image": "example.invalid/demo:1"},
                "resources": {"accelerators": [{"kind": "gpu", "vendor": "AMD", "required": False}]},
            }
        )
        inventory = {"schemaVersion": 1, "capabilities": {}, "accelerators": {}}
        effective = accelerator.resolve_effective(effective, inventory)
        service = effective["services"]["demo"]
        self.assertEqual(service["resources"]["accelerators"], [])
        rendered = self.render(effective, service)
        self.assertNotIn("AddDevice=", rendered)
        self.assertNotIn("/dev/dri", rendered)

    def test_isolated_network_uses_native_network_adapter(self):
        effective, service = self.compile_service(
            {
                "name": "Demo",
                "workload": {"kind": "daemon", "activation": "persistent"},
                "runtime": {"type": "oci", "image": "example.invalid/demo:1"},
                "network": {"mode": "isolated"},
            }
        )
        rendered = self.render(effective, service)
        self.assertIn("Network=nas-v2-net-demo.network", rendered)

    def test_raw_quadlet_source_rejects_install_and_service_name_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            app_root = pathlib.Path(tmp) / "apps"
            service_root = app_root / "demo"
            service_root.mkdir(parents=True)
            source = service_root / "demo.container"
            for content, expected in (
                ("[Container]\nImage=example.invalid/demo:1\n[Install]\nWantedBy=default.target\n", "Install"),
                ("[Container]\nImage=example.invalid/demo:1\nServiceName=evil\n", "ServiceName"),
            ):
                source.write_text(content, encoding="utf-8")
                with mock.patch.object(v2, "APP_ROOT", pathlib.PurePosixPath(str(app_root))):
                    effective, service = self.compile_service(
                        {
                            "name": "Demo",
                            "workload": {"kind": "daemon", "activation": "persistent"},
                            "runtime": {"type": "quadlet", "source": str(source)},
                        }
                    )
                with self.subTest(content=content), self.assertRaisesRegex(quadlet.QuadletProjectionError, expected):
                    self.render(effective, service)

    def test_unified_systemd_projection_stages_quadlet_and_owns_generated_service(self):
        effective, _service = self.compile_service(
            {
                "name": "Demo",
                "workload": {"kind": "daemon", "activation": "persistent"},
                "runtime": {"type": "oci", "image": "example.invalid/demo:1"},
                "resources": {"memoryMaxBytes": 1048576},
            }
        )
        output = pathlib.Path("/run/nas-control/systemd")
        files, manifest = systemd.generate_projection(
            effective,
            output_dir=output,
            python_bin="/run/current-system/sw/bin/python3",
            source_dir=pathlib.Path("/nix/store/v2/services"),
            systemctl_bin="/run/current-system/sw/bin/systemctl",
            uv_bin="/nix/store/uv/bin/uv",
        )
        source = output / "quadlet" / "nas-v2-demo.container"
        self.assertIn(source, files)
        rendered = files[source].decode()
        self.assertIn("MemoryMax=1048576", rendered)
        self.assertEqual(
            manifest["quadletLinks"],
            [{"target": "nas-v2-demo.container", "source": str(source)}],
        )
        self.assertIn("nas-v2-demo.service", manifest["ownedUnits"])
        self.assertIn("nas-v2-demo.service", manifest["startUnits"])
        self.assertFalse(any(item["target"] == "nas-v2-demo.service" for item in manifest["links"]))

    def test_real_projection_validation_resolves_quadlet_readiness_dependencies(self):
        generator = os.environ.get("NAS_V2_QUADLET_GENERATOR_BIN") or next(
            (
                path
                for path in (
                    "/usr/lib/systemd/system-generators/podman-system-generator",
                    "/usr/lib/podman/quadlet",
                )
                if os.access(path, os.X_OK)
            ),
            None,
        )
        analyzer = shutil.which("systemd-analyze")
        if not generator or not analyzer:
            self.skipTest("Podman generator and systemd-analyze are required")
        files = {
            pathlib.Path(
                "/projection/quadlet/nas-v2-demo.container"
            ): b"[Container]\nImage=example.invalid/demo:1\nPull=never\n",
            pathlib.Path(
                "/projection/units/nas-v2-ready-demo.service"
            ): b"[Unit]\nRequires=nas-v2-demo.service\nAfter=nas-v2-demo.service\n"
            b"[Service]\nType=oneshot\nExecStart=/bin/true\n",
        }
        before = files.copy()
        systemd.validate_projection(files, systemd_analyze_bin=analyzer, quadlet_generator_bin=generator)
        self.assertEqual(files, before)
        conflicting = {
            **files,
            pathlib.Path("/projection/units/nas-v2-demo.service"): b"[Service]\nExecStart=/bin/true\n",
        }
        with self.assertRaisesRegex(systemd.SystemdProjectionError, "conflicts with Quadlet output"):
            systemd.validate_projection(conflicting, systemd_analyze_bin=analyzer, quadlet_generator_bin=generator)
        files[pathlib.Path("/projection/quadlet/nas-v2-demo.container")] = (
            b"[Unit]\nRequires=nas-v2-nonexistent.service\n[Container]\nImage=example.invalid/demo:1\nPull=never\n"
        )
        with self.assertRaisesRegex(systemd.SystemdProjectionError, "nas-v2-nonexistent.service"):
            systemd.validate_projection(files, systemd_analyze_bin=analyzer, quadlet_generator_bin=generator)

    def test_quadlet_generator_validation_failure_is_fatal(self):
        files = {pathlib.Path("/projection/quadlet/nas-v2-demo.container"): b"[Container]\nImage=x\n"}
        with tempfile.TemporaryDirectory() as tmp:
            generator = pathlib.Path(tmp) / "podman-system-generator"
            generator.write_text("#!/bin/sh\nexit 17\n", encoding="utf-8")
            generator.chmod(generator.stat().st_mode | stat.S_IXUSR)
            with self.assertRaisesRegex(quadlet.QuadletProjectionError, "rejected"):
                quadlet.validate_quadlets(files, generator_bin=str(generator))

    def test_systemd_projection_requires_quadlet_generator_when_container_sources_exist(self):
        effective, _service = self.compile_service(
            {
                "name": "Demo",
                "workload": {"kind": "daemon", "activation": "persistent"},
                "runtime": {"type": "oci", "image": "example.invalid/demo:1"},
            }
        )
        files, _manifest = systemd.generate_projection(
            effective,
            output_dir=pathlib.Path("/run/nas-control/systemd"),
            python_bin="/run/current-system/sw/bin/python3",
            source_dir=pathlib.Path("/nix/store/v2/services"),
            systemctl_bin="/run/current-system/sw/bin/systemctl",
            uv_bin="/nix/store/uv/bin/uv",
        )
        with self.assertRaisesRegex(systemd.SystemdProjectionError, "generator binary"):
            systemd.validate_projection(files, systemd_analyze_bin="systemd-analyze")

    def test_strict_sandbox_rejects_privileged_volume_seccomp_rootfs_and_service_keys(self):
        cases = [
            ("Privileged", "[Container]\nImage=example.invalid/demo:1\nPrivileged=true\n"),
            ("Volume", "[Container]\nImage=example.invalid/demo:1\nVolume=/data:/data\n"),
            ("SeccompProfile", "[Container]\nImage=example.invalid/demo:1\nSeccompProfile=/tmp/seccomp.json\n"),
            ("Rootfs", "[Container]\nImage=example.invalid/demo:1\nRootfs=/\n"),
            ("ProtectSystem", "[Container]\nImage=example.invalid/demo:1\n[Service]\nProtectSystem=strict\n"),
            ("PrivateTmp", "[Container]\nImage=example.invalid/demo:1\n[Service]\nPrivateTmp=yes\n"),
            (
                "RestrictAddressFamilies",
                "[Container]\nImage=example.invalid/demo:1\n[Service]\nRestrictAddressFamilies=AF_INET\n",
            ),
            ("DeviceAllow", "[Container]\nImage=example.invalid/demo:1\n[Service]\nDeviceAllow=/dev/null r\n"),
            ("LimitNOFILE", "[Container]\nImage=example.invalid/demo:1\n[Service]\nLimitNOFILE=1024\n"),
            ("SecurityOpt", "[Container]\nImage=example.invalid/demo:1\nSecurityOpt=label=disable\n"),
            ("UsernsMode", "[Container]\nImage=example.invalid/demo:1\nUsernsMode=keep-id\n"),
            ("Mount", "[Container]\nImage=example.invalid/demo:1\nMount=type=bind,src=/,dst=/\n"),
            ("Init", "[Container]\nImage=example.invalid/demo:1\nInit=true\n"),
            ("LabelDisable", "[Container]\nImage=example.invalid/demo:1\nLabelDisable=true\n"),
            ("SecurityLabelDisable", "[Container]\nImage=example.invalid/demo:1\nSecurityLabelDisable=true\n"),
        ]
        for label, content in cases:
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as tmp:
                    app_root = pathlib.Path(tmp) / "apps"
                    service_root = app_root / "demo"
                    service_root.mkdir(parents=True)
                    source = service_root / "demo.container"
                    source.write_text(content, encoding="utf-8")
                    with mock.patch.object(v2, "APP_ROOT", pathlib.PurePosixPath(str(app_root))):
                        with mock.patch.object(quadlet, "APP_ROOT", pathlib.Path(str(app_root))):
                            effective, service = self.compile_service(
                                {
                                    "name": "Demo",
                                    "workload": {"kind": "daemon", "activation": "persistent"},
                                    "runtime": {"type": "quadlet", "source": str(source)},
                                    "sandbox": {"mode": "strict"},
                                }
                            )
                            with self.assertRaisesRegex(quadlet.QuadletProjectionError, "strict sandbox"):
                                self.render(effective, service)

    def test_inherit_sandbox_allows_security_keys(self):
        cases = [
            "[Container]\nImage=example.invalid/demo:1\nPrivileged=true\n",
            "[Container]\nImage=example.invalid/demo:1\nVolume=/data:/data\n",
            "[Container]\nImage=example.invalid/demo:1\nSeccompProfile=/tmp/seccomp.json\n",
            "[Container]\nImage=example.invalid/demo:1\nRootfs=/\n",
            "[Container]\nImage=example.invalid/demo:1\n[Service]\nProtectSystem=strict\n",
            "[Container]\nImage=example.invalid/demo:1\n[Service]\nPrivateTmp=yes\n",
            "[Container]\nImage=example.invalid/demo:1\n[Service]\nDeviceAllow=/dev/null r\n",
            "[Container]\nImage=example.invalid/demo:1\n[Service]\nLimitNOFILE=1024\n",
        ]
        for content in cases:
            with self.subTest(content=content[:30]):
                with tempfile.TemporaryDirectory() as tmp:
                    app_root = pathlib.Path(tmp) / "apps"
                    service_root = app_root / "demo"
                    service_root.mkdir(parents=True)
                    source = service_root / "demo.container"
                    source.write_text(content, encoding="utf-8")
                    with mock.patch.object(v2, "APP_ROOT", pathlib.PurePosixPath(str(app_root))):
                        with mock.patch.object(quadlet, "APP_ROOT", pathlib.Path(str(app_root))):
                            effective, service = self.compile_service(
                                {
                                    "name": "Demo",
                                    "workload": {"kind": "daemon", "activation": "persistent"},
                                    "runtime": {"type": "quadlet", "source": str(source)},
                                    "sandbox": {"mode": "inherit"},
                                }
                            )
                            rendered = self.render(effective, service)
                            self.assertIn("Image=", rendered)

    def test_render_time_symlink_escape_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            app_root = pathlib.Path(tmp) / "apps"
            service_root = app_root / "demo"
            service_root.mkdir(parents=True)
            source = service_root / "demo.container"
            source.write_text("[Container]\nImage=example.invalid/demo:1\n", encoding="utf-8")
            with mock.patch.object(v2, "APP_ROOT", pathlib.PurePosixPath(str(app_root))):
                with mock.patch.object(quadlet, "APP_ROOT", pathlib.Path(str(app_root))):
                    effective, service = self.compile_service(
                        {
                            "name": "Demo",
                            "workload": {"kind": "daemon", "activation": "persistent"},
                            "runtime": {"type": "quadlet", "source": str(source)},
                            "sandbox": {"mode": "inherit"},
                        }
                    )
                    # TOCTOU: replace file with symlink escaping app root after compile
                    evil_target = pathlib.Path(tmp) / "evil.container"
                    evil_target.write_text("[Container]\nImage=example.invalid/demo:1\n", encoding="utf-8")
                    source.unlink()
                    source.symlink_to(evil_target)
                    with self.assertRaisesRegex(quadlet.QuadletProjectionError, "escapes"):
                        self.render(effective, service)

    def test_render_time_out_of_root_allowed_via_option_b(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Source lives outside the default APP_ROOT; compile validates via mocked v2 APP_ROOT
            # but render with default quadlet APP_ROOT should still allow it (Option B).
            alt_root = pathlib.Path(tmp) / "alt" / "apps"
            alt_service_root = alt_root / "demo"
            alt_service_root.mkdir(parents=True)
            outside = alt_service_root / "demo.container"
            outside.write_text("[Container]\nImage=example.invalid/demo:1\n", encoding="utf-8")
            with mock.patch.object(v2, "APP_ROOT", pathlib.PurePosixPath(str(alt_root))):
                effective, service = self.compile_service(
                    {
                        "name": "Demo",
                        "workload": {"kind": "daemon", "activation": "persistent"},
                        "runtime": {"type": "quadlet", "source": str(outside)},
                        "sandbox": {"mode": "inherit"},
                    }
                )
                # quadlet APP_ROOT remains default /var/lib/nas-control/apps, nominal is outside -> no containment check
                rendered = self.render(effective, service)
                self.assertIn("Image=", rendered)


if __name__ == "__main__":
    unittest.main()
