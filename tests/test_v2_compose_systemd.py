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
import nas_v2_compose_import as compose_import  # noqa: E402
import nas_v2_spec as v2  # noqa: E402
import nas_v2_systemd_native as systemd  # noqa: E402


class V2ComposeSystemdTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = v2.load_schema(SCHEMA)

    def fixture(self, root: pathlib.Path, *, on_demand: bool = False) -> tuple[dict, pathlib.Path]:
        app_root = root / "apps"
        service_root = app_root / "demo"
        service_root.mkdir(parents=True)
        source = service_root / "compose.yaml"
        source.write_text("services:\n  web:\n    image: example.invalid/web:1\n", encoding="utf-8")
        workload: dict[str, object] = {"kind": "daemon", "activation": "persistent"}
        service: dict[str, object] = {
            "name": "Demo Compose",
            "workload": workload,
            "runtime": {"type": "compose", "source": str(source)},
        }
        if on_demand:
            workload.update({"activation": "on-demand", "idleSeconds": 120})
            service["routes"] = {
                "web": {
                    "target": {"type": "http", "port": 8080},
                    "exposure": {"type": "path", "paths": ["/demo/"]},
                    "auth": {"mode": "public"},
                }
            }
        with mock.patch.object(v2, "APP_ROOT", pathlib.PurePosixPath(str(app_root))):
            effective = v2.compile_document({"schemaVersion": 3, "services": {"demo": service}}, self.schema)
        return effective, source

    def fake_tools(self, root: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
        root.mkdir(parents=True, exist_ok=True)
        provider = root / "podman-compose"
        provider.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        provider.chmod(0o755)

        podman = root / "podman"
        podman.write_text(
            """#!/bin/sh
source_file=""
next_file=0
for arg in "$@"; do
  if [ "$next_file" = 1 ]; then
    if [ -z "$source_file" ]; then source_file="$arg"; fi
    next_file=0
  elif [ "$arg" = "--file" ]; then
    next_file=1
  fi
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
        root: pathlib.Path,
        *,
        count_file: pathlib.Path | None = None,
    ) -> tuple[dict[pathlib.Path, bytes], dict]:
        podman, provider, podlet = self.fake_tools(root / "tools")
        env = {"NAS_V2_PODLET_BIN": str(podlet)}
        if count_file is not None:
            env["NAS_V2_PODLET_COUNT_FILE"] = str(count_file)
        with (
            mock.patch.object(systemd, "APP_ROOT", root / "apps"),
            mock.patch.object(compose, "APP_ROOT", root / "apps"),
            mock.patch.object(compose_import, "APP_ROOT", root / "apps"),
            mock.patch.dict(os.environ, env, clear=False),
        ):
            return systemd.generate_projection(
                effective,
                output_dir=root / "projection",
                python_bin="/run/current-system/sw/bin/python3",
                source_dir=pathlib.Path("/nix/store/v2/services"),
                systemctl_bin="/run/current-system/sw/bin/systemctl",
                uv_bin="/nix/store/uv/bin/uv",
                podman_bin=str(podman),
                compose_provider_bin=str(provider),
            )

    def test_compose_runtime_is_quadlet_not_podman_compose(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            effective, _source = self.fixture(root)
            files, manifest = self.generate(effective, root)
            owner = files[root / "projection/units/nas-v2-demo.target"].decode()
            quadlet = files[root / "projection/quadlet/nas-v2-demo-web.container"].decode()
        self.assertIn("Requires=nas-v2-demo-web.service", owner)
        self.assertNotIn("podman compose", owner)
        self.assertIn("PartOf=nas-v2-demo.target", quadlet)
        self.assertIn("nas-v2-demo-web.service", manifest["ownedUnits"])
        self.assertIn("nas-v2-demo.target", manifest["startUnits"])

    def test_import_uses_compiled_owner_unit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            effective, _source = self.fixture(root)
            effective["derived"]["runtime"]["demo"]["ownerUnit"] = "compiled-compose-owner.service"
            podman, provider, podlet = self.fake_tools(root / "tools")
            with (
                mock.patch.object(compose, "APP_ROOT", root / "apps"),
                mock.patch.object(compose_import, "APP_ROOT", root / "apps"),
            ):
                bundle, _manifest = compose_import.import_compose(
                    effective,
                    "demo",
                    effective["services"]["demo"],
                    podlet_bin=str(podlet),
                    podman_bin=str(podman),
                    compose_provider_bin=str(provider),
                )
        self.assertIn("PartOf=compiled-compose-owner.service", bundle["nas-v2-demo-web.container"].decode())

    def test_on_demand_import_uses_socket_activation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            effective, _source = self.fixture(root, on_demand=True)
            files, manifest = self.generate(effective, root)
            owner = files[root / "projection/units/nas-v2-demo.target"].decode()
            proxy = files[root / "projection/units/nas-v2-activate-demo-web.service"].decode()
        self.assertIn("StopWhenUnneeded=yes", owner)
        self.assertIn("systemd-socket-proxyd", proxy)
        self.assertIn("--exit-idle-time=120s", proxy)
        self.assertNotIn("nas-v2-demo.target", manifest["startUnits"])

    def test_unchanged_import_reuses_podlet_cache(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            effective, _source = self.fixture(root)
            count = root / "podlet-count"
            self.generate(effective, root, count_file=count)
            first = len(count.read_text(encoding="utf-8").splitlines())
            self.generate(effective, root, count_file=count)
            second = len(count.read_text(encoding="utf-8").splitlines())
        self.assertEqual(first, second)

    def test_source_change_invalidates_import_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            effective, source = self.fixture(root)
            _files1, manifest1 = self.generate(effective, root)
            source.write_text("services:\n  web:\n    image: example.invalid/web:2\n", encoding="utf-8")
            _files2, manifest2 = self.generate(effective, root)
        self.assertNotEqual(
            manifest1["fingerprints"]["nas-v2-demo.target"],
            manifest2["fingerprints"]["nas-v2-demo.target"],
        )

    def test_compose_namespacing_rewrites_relationship_fields_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            generated = pathlib.Path(tmp) / "quadlet"
            generated.mkdir()
            (generated / "web.container").write_text(
                """[Container]
Image=example.invalid/web:1
Network=default.network
Volume=data.volume:/srv/data
Environment=CONFIG_URL=https://example/default.network/config
Environment=IMAGE_TAG=data.volume
Exec=tool --path=/srv/web.container/cache
Description=web.container is a literal value
""",
                encoding="utf-8",
            )
            (generated / "default.network").write_text(
                """[Network]
NetworkName=default.network
""",
                encoding="utf-8",
            )
            (generated / "data.volume").write_text(
                """[Volume]
VolumeName=data.volume
""",
                encoding="utf-8",
            )

            files, entry_units = compose_import._namespace_bundle("demo", generated, owner_unit="nas-v2-demo.target")

        rendered = files["nas-v2-demo-web.container"].decode()
        self.assertIn("Network=nas-v2-demo-default.network", rendered)
        self.assertIn("Volume=nas-v2-demo-data.volume:/srv/data", rendered)
        self.assertIn("CONFIG_URL=https://example/default.network/config", rendered)
        self.assertIn("IMAGE_TAG=data.volume", rendered)
        self.assertIn("--path=/srv/web.container/cache", rendered)
        self.assertIn("Description=web.container is a literal value", rendered)
        self.assertEqual(entry_units, ["nas-v2-demo-web.service"])
        self.assertIn("NetworkName=default.network", files["nas-v2-demo-default.network"].decode())

    def test_nix_module_pins_podlet(self) -> None:
        module = (ROOT / "modules/nas/config/managed-services-compose-import.nix").read_text(encoding="utf-8")
        self.assertIn('"${pkgs.podlet}/bin/podlet"', module)


if __name__ == "__main__":
    unittest.main()
