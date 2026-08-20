from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
SCHEMA = ROOT / "schemas" / "managed-services-v3.schema.json"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_compose as compose  # noqa: E402
import nas_v2_spec as v2  # noqa: E402
import nas_v2_systemd as systemd  # noqa: E402


class V2ComposeSystemdTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = v2.load_schema(SCHEMA)

    def fixture(self, root: pathlib.Path, *, activation: str = "persistent") -> tuple[dict, pathlib.Path]:
        app_root = root / "apps"
        service_root = app_root / "demo"
        service_root.mkdir(parents=True)
        source = service_root / "compose.yaml"
        source.write_text(
            """services:
  web:
    image: example.invalid/web:1
""",
            encoding="utf-8",
        )
        workload: dict[str, object] = {"kind": "daemon", "activation": activation}
        if activation == "on-demand":
            workload["idleSeconds"] = 120
        document = {
            "schemaVersion": 3,
            "services": {
                "demo": {
                    "name": "Demo Compose",
                    "workload": workload,
                    "runtime": {"type": "compose", "source": str(source)},
                }
            },
        }
        with mock.patch.object(v2, "APP_ROOT", pathlib.PurePosixPath(str(app_root))):
            effective = v2.compile_document(document, self.schema)
        return effective, source

    def generate(self, effective: dict, output: pathlib.Path) -> tuple[dict[pathlib.Path, bytes], dict]:
        return systemd.generate_projection(
            effective,
            output_dir=output,
            python_bin="/run/current-system/sw/bin/python3",
            source_dir=pathlib.Path("/nix/store/v2/services"),
            systemctl_bin="/run/current-system/sw/bin/systemctl",
            uv_bin="/nix/store/uv/bin/uv",
            podman_bin="/nix/store/podman/bin/podman",
            compose_provider_bin="/nix/store/podman-compose/bin/podman-compose",
        )

    def test_compose_project_is_owned_by_finite_systemd_wrapper(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            effective, source = self.fixture(root)
            output = root / "projection"
            with mock.patch.object(compose, "APP_ROOT", root / "apps"):
                files, manifest = self.generate(effective, output)

            unit = files[output / "units/nas-v2-demo.service"].decode()
            override = files[output / "compose/demo.override.yaml"].decode()

        self.assertIn("Type=oneshot", unit)
        self.assertIn("RemainAfterExit=yes", unit)
        self.assertIn('Environment="PODMAN_COMPOSE_PROVIDER=/nix/store/podman-compose/bin/podman-compose"', unit)
        self.assertIn('"/nix/store/podman/bin/podman" compose', unit)
        self.assertIn(f'--file "{source.resolve()}"', unit)
        self.assertIn(f'--file "{output / "compose/demo.override.yaml"}"', unit)
        self.assertIn("up --detach --remove-orphans", unit)
        self.assertIn("down --remove-orphans", unit)
        self.assertEqual(override, '{\n  "services": {}\n}\n')
        self.assertIn("nas-v2-demo.service", manifest["ownedUnits"])
        self.assertIn("nas-v2-demo.service", manifest["startUnits"])

    def test_on_demand_compose_uses_same_native_lease_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            effective, _source = self.fixture(root, activation="on-demand")
            output = root / "projection"
            with mock.patch.object(compose, "APP_ROOT", root / "apps"):
                files, manifest = self.generate(effective, output)
            unit = files[output / "units/nas-v2-demo.service"].decode()

        self.assertIn("StopWhenUnneeded=yes", unit)
        self.assertNotIn("nas-v2-demo.service", manifest["startUnits"])
        self.assertIn("nas-v2-lease-demo.target", manifest["ownedUnits"])
        self.assertIn("nas-v2-idle-demo.timer", manifest["ownedUnits"])

    def test_compose_source_content_changes_owner_fingerprint(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            effective, source = self.fixture(root)
            output = root / "projection"
            with mock.patch.object(compose, "APP_ROOT", root / "apps"):
                _files1, manifest1 = self.generate(effective, output)
                source.write_text(
                    """services:
  web:
    image: example.invalid/web:2
""",
                    encoding="utf-8",
                )
                _files2, manifest2 = self.generate(effective, output)

        self.assertNotEqual(
            manifest1["fingerprints"]["nas-v2-demo.service"],
            manifest2["fingerprints"]["nas-v2-demo.service"],
        )

    def test_compose_runtime_requires_absolute_runtime_binaries(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            effective, _source = self.fixture(root)
            with (
                mock.patch.object(compose, "APP_ROOT", root / "apps"),
                self.assertRaisesRegex(systemd.SystemdProjectionError, "Podman binary must be an absolute safe path"),
            ):
                systemd.generate_projection(
                    effective,
                    output_dir=root / "projection",
                    python_bin="/run/current-system/sw/bin/python3",
                    source_dir=pathlib.Path("/nix/store/v2/services"),
                    systemctl_bin="/run/current-system/sw/bin/systemctl",
                    uv_bin="/nix/store/uv/bin/uv",
                    podman_bin="podman",
                    compose_provider_bin="podman-compose",
                )

    def test_nix_runtime_module_pins_podman_and_provider_store_paths(self):
        module = (ROOT / "modules/nas/config/managed-services.nix").read_text(encoding="utf-8")

        self.assertIn('"${pkgs.podman}/bin/podman"', module)
        self.assertIn('"${pkgs.podman-compose}/bin/podman-compose"', module)
        self.assertIn('"--podman-bin"', module)
        self.assertIn('"--compose-provider-bin"', module)


if __name__ == "__main__":
    unittest.main()
