from __future__ import annotations

import os
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
        service: dict[str, object] = {
            "name": "Demo Compose",
            "workload": workload,
            "runtime": {"type": "compose", "source": str(source)},
        }
        if activation == "on-demand":
            workload["idleSeconds"] = 120
            service["routes"] = {
                "web": {
                    "target": {"type": "http", "port": 8080},
                    "exposure": {"type": "path", "paths": ["/demo/"]},
                    "auth": {"mode": "public"},
                }
            }
        document = {"schemaVersion": 3, "services": {"demo": service}}
        with mock.patch.object(v2, "APP_ROOT", pathlib.PurePosixPath(str(app_root))):
            effective = v2.compile_document(document, self.schema)
        return effective, source

    def fake_tools(self, root: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
        provider = root / "podman-compose"
        provider.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        provider.chmod(0o755)

        podman = root / "podman"
        podman.write_text(
            """#!/bin/sh
source_file=""
want_file=0
for arg in "$@"; do
  if [ "$want_file" = 1 ]; then
    if [ -z "$source_file" ]; then source_file="$arg"; fi
    want_file=0
    continue
  fi
  if [ "$arg" = "--file" ]; then want_file=1; fi
done
[ -n "$source_file" ] || exit 2
cat "$source_file"
""",
            encoding="utf-8",
        )
        podman.chmod(0o755)

        podlet = root / "podlet"
        podlet.write_text(
            """#!/bin/sh
out=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --file|-f) out="$2"; shift 2 ;;
    compose) shift; break ;;
    *) shift ;;
  esac
done
[ -n "$out" ] || exit 2
mkdir -p "$out"
printf '%s\n' '# FileName=web' '[Container]' 'Image=example.invalid/web:imported' > "$out/web.container"
if [ -n "${NAS_V2_PODLET_COUNT_FILE:-}" ]; then printf '1\n' >> "$NAS_V2_PODLET_COUNT_FILE"; fi
""",
            encoding="utf-8",
        )
        podlet.chmod(0o755)
        return podman, provider, podlet

    def generate(
        self,
        effective: dict,
        output: pathlib.Path,
        *,
        app_root: pathlib.Path,
        tools_root: pathlib.Path,
        count_file: pathlib.Path | None = None,
    ) -> tuple[dict[pathlib.Path, bytes], dict]:
        podman, provider, podlet = self.fake_tools(tools_root)
        env = {"NAS_V2_PODLET_BIN": str(podlet)}
        if count_file is not None:
            env["NAS_V2_PODLET_COUNT_FILE"] = str(count_file)
        with (
            mock.patch.object(systemd, "APP_ROOT", app_root),
            mock.patch.object(compose, "APP_ROOT", app_root),
            mock.patch.dict(os.environ, env, clear=False),
        ):
            return systemd.generate_projection(
                effective,
                output_dir=output,
                python_bin="/run/current-system/sw/bin/python3",
                source_dir=pathlib.Path("/nix/store/v2/services"),
                systemctl_bin="/run/current-system/sw/bin/systemctl",
                uv_bin="/nix/store/uv/bin/uv",
                podman_bin=str(podman),
                compose_provider_bin=str(provider),
            )

    def test_compose_is_imported_to_native_quadlet_and_aggregate_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            effective, _source = self.fixture(root)
            output = root / "projection"
            files, manifest = self.generate(
                effective,
                output,
                app_root=root / "apps",
                tools_root=root / "tools",
            )

            owner = files[output / "units/nas-v2-demo.service"].decode()
            quadlet = files[output / "quadlet/nas-v2-demo-web.container"].decode()

        self.assertIn("Type=oneshot", owner)
        self.assertIn("Requires=nas-v2-demo-web.service", owner)
        self.assertIn("After=nas-v2-demo-web.service", owner)
        self.assertNotIn("podman compose", owner)
        self.assertNotIn("PODMAN_COMPOSE_PROVIDER", owner)
        self.assertIn("PartOf=nas-v2-demo.service", quadlet)
        self.assertIn("nas-v2-demo.service", manifest["ownedUnits"])
        self.assertIn("nas-v2-demo-web.service", manifest["ownedUnits"])
        self.assertIn("nas-v2-demo.service", manifest["startUnits"])
        self.assertIn("nas-v2-demo-web.container", {entry["target"] for entry in manifest["quadletLinks"]})

    def test_on_demand_compose_keeps_native_socket_activation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            effective, _source = self.fixture(root, activation="on-demand")
            output = root / "projection"
            files, manifest = self.generate(
                effective,
                output,
                app_root=root / "apps",
                tools_root=root / "tools",
            )
            owner = files[output / "units/nas-v2-demo.service"].decode()
            socket = files[output / "units/nas-v2-activate-demo-web.socket"].decode()
            proxy = files[output / "units/nas-v2-activate-demo-web.service"].decode()

        self.assertIn("StopWhenUnneeded=yes", owner)
        self.assertIn("ListenStream=/run/nas-control/activate/demo-web.sock", socket)
        self.assertIn("systemd-socket-proxyd", proxy)
        self.assertIn("--exit-idle-time=120s", proxy)
        self.assertNotIn("nas-v2-demo.service", manifest["startUnits"])
        self.assertIn("nas-v2-activate-demo-web.socket", manifest["ownedUnits"])

    def test_unchanged_compose_reuses_cached_podlet_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            effective, _source = self.fixture(root)
            count = root / "podlet-count"
            self.generate(
                effective,
                root / "projection-1",
                app_root=root / "apps",
                tools_root=root / "tools-1",
                count_file=count,
            )
            # Tool paths are part of the import fingerprint, so use the same
            # fake tools for the second projection.
            tools = root / "shared-tools"
            tools.mkdir()
            podman, provider, podlet = self.fake_tools(tools)
            env = {
                "NAS_V2_PODLET_BIN": str(podlet),
                "NAS_V2_PODLET_COUNT_FILE": str(count),
            }
            with (
                mock.patch.object(systemd, "APP_ROOT", root / "apps"),
                mock.patch.object(compose, "APP_ROOT", root / "apps"),
                mock.patch.dict(os.environ, env, clear=False),
            ):
                systemd.generate_projection(
                    effective,
                    output_dir=root / "projection-2",
                    python_bin="/run/current-system/sw/bin/python3",
                    source_dir=pathlib.Path("/nix/store/v2/services"),
                    systemctl_bin="/run/current-system/sw/bin/systemctl",
                    uv_bin="/nix/store/uv/bin/uv",
                    podman_bin=str(podman),
                    compose_provider_bin=str(provider),
                )
                before = len(count.read_text(encoding="utf-8").splitlines()) if count.exists() else 0
                systemd.generate_projection(
                    effective,
                    output_dir=root / "projection-3",
                    python_bin="/run/current-system/sw/bin/python3",
                    source_dir=pathlib.Path("/nix/store/v2/services"),
                    systemctl_bin="/run/current-system/sw/bin/systemctl",
                    uv_bin="/nix/store/uv/bin/uv",
                    podman_bin=str(podman),
                    compose_provider_bin=str(provider),
                )
                after = len(count.read_text(encoding="utf-8").splitlines())
            self.assertEqual(before, after)

    def test_compose_source_content_changes_owner_fingerprint(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            effective, source = self.fixture(root)
            tools = root / "tools"
            podman, provider, podlet = self.fake_tools(tools)
            env = {"NAS_V2_PODLET_BIN": str(podlet)}
            with (
                mock.patch.object(systemd, "APP_ROOT", root / "apps"),
                mock.patch.object(compose, "APP_ROOT", root / "apps"),
                mock.patch.dict(os.environ, env, clear=False),
            ):
                _files1, manifest1 = systemd.generate_projection(
                    effective,
                    output_dir=root / "projection-1",
                    python_bin="/run/current-system/sw/bin/python3",
                    source_dir=pathlib.Path("/nix/store/v2/services"),
                    systemctl_bin="/run/current-system/sw/bin/systemctl",
                    uv_bin="/nix/store/uv/bin/uv",
                    podman_bin=str(podman),
                    compose_provider_bin=str(provider),
                )
                source.write_text("services:\n  web:\n    image: example.invalid/web:2\n", encoding="utf-8")
                _files2, manifest2 = systemd.generate_projection(
                    effective,
                    output_dir=root / "projection-2",
                    python_bin="/run/current-system/sw/bin/python3",
                    source_dir=pathlib.Path("/nix/store/v2/services"),
                    systemctl_bin="/run/current-system/sw/bin/systemctl",
                    uv_bin="/nix/store/uv/bin/uv",
                    podman_bin=str(podman),
                    compose_provider_bin=str(provider),
                )
        self.assertNotEqual(
            manifest1["fingerprints"]["nas-v2-demo.service"],
            manifest2["fingerprints"]["nas-v2-demo.service"],
        )

    def test_compose_import_requires_absolute_podlet_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            effective, _source = self.fixture(root)
            podman, provider, _podlet = self.fake_tools(root / "tools")
            with (
                mock.patch.object(systemd, "APP_ROOT", root / "apps"),
                mock.patch.object(compose, "APP_ROOT", root / "apps"),
                mock.patch.dict(os.environ, {"NAS_V2_PODLET_BIN": "podlet"}, clear=False),
                self.assertRaisesRegex(systemd.SystemdProjectionError, "Podlet binary must be an absolute safe path"),
            ):
                systemd.generate_projection(
                    effective,
                    output_dir=root / "projection",
                    python_bin="/run/current-system/sw/bin/python3",
                    source_dir=pathlib.Path("/nix/store/v2/services"),
                    systemctl_bin="/run/current-system/sw/bin/systemctl",
                    uv_bin="/nix/store/uv/bin/uv",
                    podman_bin=str(podman),
                    compose_provider_bin=str(provider),
                )

    def test_nix_runtime_module_pins_podlet_store_path(self):
        module = (ROOT / "modules/nas/config/managed-services-compose-import.nix").read_text(encoding="utf-8")
        self.assertIn('"${pkgs.podlet}/bin/podlet"', module)


if __name__ == "__main__":
    unittest.main()
