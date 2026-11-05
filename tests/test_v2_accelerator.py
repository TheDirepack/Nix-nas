from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from typing import cast
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))

import nas_v2_accelerator as accelerator  # noqa: E402
import nas_v2_platform_probe as platform_probe  # noqa: E402
import nas_v2_quadlet as quadlet  # noqa: E402
from nas_v2_systemd_attachments import SystemdAttachmentError  # noqa: E402
from nas_v2_systemd_native import attachment_lines  # noqa: E402


def service(runtime_type: str, request: dict[str, object]) -> dict[str, object]:
    runtime: dict[str, object]
    if runtime_type == "compose":
        runtime = {"type": "compose", "source": "/var/lib/nas-control/apps/test/compose.yaml"}
    elif runtime_type == "vm":
        runtime = {"type": "vm", "source": "/var/lib/nas-control/apps/test/domain.xml"}
    elif runtime_type == "systemd":
        runtime = {"type": "systemd", "unit": "test.service"}
    elif runtime_type in {"exec", "python"}:
        runtime = {"type": runtime_type, "identity": {"mode": "existing", "user": "test"}}
    else:
        runtime = {"type": runtime_type, "image": "example.invalid/test:latest"}
    return {
        "name": "test",
        "managed": True,
        "workload": {"kind": "daemon", "activation": "persistent"},
        "runtime": runtime,
        "resources": {"accelerators": [request]},
        "storage": [],
        "credentials": [],
        "sandbox": {"mode": "inherit"},
    }


def inventory() -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "capabilities": {
            "gpu-nvidia": True,
            "gpu-nvidia-cdi": True,
            "gpu-amd": True,
            "gpu-intel": False,
        },
        "accelerators": {
            "NVIDIA": {
                "configured": True,
                "selectors": [
                    {"type": "devices", "values": ["/dev/nvidia0", "/dev/nvidiactl", "/dev/nvidia-uvm"]},
                    {"type": "cdi", "value": "nvidia.com/gpu=0"},
                ],
                "allSelector": {"type": "cdi", "value": "nvidia.com/gpu=all"},
            },
            "AMD": {
                "configured": True,
                "selectors": [{"type": "devices", "values": ["/dev/dri/renderD128"]}],
            },
            "Intel": {"configured": False, "selectors": []},
        },
    }


class PlatformProbeTests(unittest.TestCase):
    def test_probe_discovers_drm_nvidia_device_set_and_cdi(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            sys_drm = root / "sys-class-drm"
            dev = root / "dev"
            render = sys_drm / "renderD128" / "device"
            render.mkdir(parents=True)
            (render / "vendor").write_text("0x1002\n", encoding="ascii")
            (dev / "dri").mkdir(parents=True)
            (dev / "dri" / "renderD128").touch()
            (dev / "nvidia0").touch()
            (dev / "nvidiactl").touch()
            (dev / "nvidia-uvm").touch()
            proc = root / "proc-nvidia-gpus" / "0000:01:00.0"
            proc.mkdir(parents=True)
            uuid = "GPU-12345678-1234-1234-1234-123456789abc"
            (proc / "information").write_text(f"GPU UUID: {uuid}\nDevice Minor: 0\n", encoding="ascii")
            base = {
                "schemaVersion": 1,
                "capabilities": {
                    "gpu-amd": True,
                    "gpu-intel": False,
                    "gpu-nvidia": True,
                    "gpu-nvidia-cdi": True,
                },
            }
            result = platform_probe.probe_inventory(
                base,
                sys_class_drm=sys_drm,
                dev_root=dev,
                proc_nvidia_gpus=proc.parent,
                cdi_device_names={f"nvidia.com/gpu={uuid}", "nvidia.com/gpu=all"},
            )
            self.assertEqual(
                [{"type": "devices", "values": [str(dev / "dri" / "renderD128")]}],
                result["accelerators"]["AMD"]["selectors"],
            )
            self.assertIn(
                {
                    "type": "devices",
                    "values": [str(dev / "nvidia0"), str(dev / "nvidiactl"), str(dev / "nvidia-uvm")],
                },
                result["accelerators"]["NVIDIA"]["selectors"],
            )
            self.assertIn(
                {"type": "cdi", "value": f"nvidia.com/gpu={uuid}"},
                result["accelerators"]["NVIDIA"]["selectors"],
            )
            self.assertEqual(
                {"type": "cdi", "value": "nvidia.com/gpu=all"},
                result["accelerators"]["NVIDIA"]["allSelector"],
            )

    def test_duplicate_nvidia_device_names_are_deduplicated_before_selection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dev = pathlib.Path(temporary) / "dev"
            dev.mkdir()
            (dev / "nvidia0").touch()
            (dev / "nvidia00").touch()
            result = platform_probe.probe_inventory(
                {"schemaVersion": 1, "capabilities": {"gpu-nvidia": True, "gpu-nvidia-cdi": True}},
                sys_class_drm=pathlib.Path(temporary) / "empty-drm",
                dev_root=dev,
                cdi_device_names={"nvidia.com/gpu=0"},
            )
            self.assertEqual(
                result["accelerators"]["NVIDIA"]["selectors"],
                [
                    {"type": "devices", "values": [str(dev / "nvidia0")]},
                    {"type": "cdi", "value": "nvidia.com/gpu=0"},
                ],
            )

    def test_probe_prefers_uuid_cdi_names_and_records_the_physical_identity_map(self) -> None:
        # Non-contiguous driver minors: the toolkit's enumeration index is not
        # the driver minor, so the UUID name is the only stable selector.
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            dev = root / "dev"
            dev.mkdir()
            (dev / "nvidia0").touch()
            (dev / "nvidia2").touch()
            proc = root / "nvidia-gpus"
            first = proc / "0000:01:00.0"
            second = proc / "0000:02:00.0"
            first.mkdir(parents=True)
            second.mkdir(parents=True)
            uuid_a = "GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
            uuid_b = "GPU-bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
            (first / "information").write_text(f"GPU UUID: {uuid_a}\nDevice Minor: 2\n", encoding="ascii")
            (second / "information").write_text(f"GPU UUID: {uuid_b}\nDevice Minor: 0\n", encoding="ascii")
            result = platform_probe.probe_inventory(
                {"capabilities": {"gpu-nvidia": True, "gpu-nvidia-cdi": True}},
                sys_class_drm=root / "no-drm",
                dev_root=dev,
                proc_nvidia_gpus=proc,
                cdi_device_names={
                    "nvidia.com/gpu=0",
                    "nvidia.com/gpu=1",
                    f"nvidia.com/gpu={uuid_a}",
                    f"nvidia.com/gpu={uuid_b}",
                    "nvidia.com/gpu=all",
                },
            )
            nvidia = result["accelerators"]["NVIDIA"]
            self.assertEqual(
                [entry["value"] for entry in nvidia["selectors"] if entry["type"] == "cdi"],
                [f"nvidia.com/gpu={uuid_b}", f"nvidia.com/gpu={uuid_a}"],
            )
            self.assertEqual(
                [entry["values"][0] for entry in nvidia["selectors"] if entry["type"] == "devices"],
                [str(dev / "nvidia0"), str(dev / "nvidia2")],
            )
            self.assertEqual(nvidia["minorByUuid"], {uuid_a: 2, uuid_b: 0})

    def test_probe_falls_back_to_the_index_name_when_the_driver_uuid_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            dev = root / "dev"
            dev.mkdir()
            (dev / "nvidia3").touch()
            result = platform_probe.probe_inventory(
                {"capabilities": {"gpu-nvidia": True, "gpu-nvidia-cdi": True}},
                sys_class_drm=root / "no-drm",
                dev_root=dev,
                proc_nvidia_gpus=root / "missing-proc",
                cdi_device_names={"nvidia.com/gpu=3", "nvidia.com/gpu=all"},
            )
            nvidia = result["accelerators"]["NVIDIA"]
            self.assertEqual(
                nvidia["selectors"],
                [
                    {"type": "devices", "values": [str(dev / "nvidia3")]},
                    {"type": "cdi", "value": "nvidia.com/gpu=3"},
                ],
            )
            self.assertNotIn("minorByUuid", nvidia)
            self.assertEqual({"type": "cdi", "value": "nvidia.com/gpu=all"}, nvidia["allSelector"])

    def test_malformed_driver_uuid_falls_back_to_the_index_name(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            dev = root / "dev"
            dev.mkdir()
            (dev / "nvidia3").touch()
            proc = root / "proc"
            info = proc / "0000:03:00.0"
            info.mkdir(parents=True)
            (info / "information").write_text("GPU UUID: GPU-not-a-uuid\nDevice Minor: 3\n", encoding="ascii")
            result = platform_probe.probe_inventory(
                {"capabilities": {"gpu-nvidia": True, "gpu-nvidia-cdi": True}},
                sys_class_drm=root / "no-drm",
                dev_root=dev,
                proc_nvidia_gpus=proc,
                cdi_device_names={"nvidia.com/gpu=3", "nvidia.com/gpu=all"},
            )
            nvidia = result["accelerators"]["NVIDIA"]
            self.assertEqual(
                [entry["value"] for entry in nvidia["selectors"] if entry["type"] == "cdi"],
                ["nvidia.com/gpu=3"],
            )
            self.assertNotIn("minorByUuid", nvidia)

    def test_probe_falls_back_to_the_index_name_when_only_index_names_are_published(self) -> None:
        # A host whose generator still publishes index names only must keep
        # working; the fallback is a deliberate part of the naming contract.
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            dev = root / "dev"
            dev.mkdir()
            (dev / "nvidia3").touch()
            proc = root / "proc"
            info = proc / "0000:03:00.0"
            info.mkdir(parents=True)
            uuid = "GPU-cccccccc-cccc-cccc-cccc-cccccccccccc"
            (info / "information").write_text(f"GPU UUID: {uuid}\nDevice Minor: 3\n", encoding="ascii")
            result = platform_probe.probe_inventory(
                {"capabilities": {"gpu-nvidia": True, "gpu-nvidia-cdi": True}},
                sys_class_drm=root / "no-drm",
                dev_root=dev,
                proc_nvidia_gpus=proc,
                cdi_device_names={"nvidia.com/gpu=3", "nvidia.com/gpu=all"},
            )
            nvidia = result["accelerators"]["NVIDIA"]
            self.assertEqual(
                [entry["value"] for entry in nvidia["selectors"] if entry["type"] == "cdi"],
                ["nvidia.com/gpu=3"],
            )
            self.assertEqual(nvidia["minorByUuid"], {uuid: 3})

    def test_gpu_without_a_published_name_keeps_its_device_selector(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            dev = root / "dev"
            dev.mkdir()
            (dev / "nvidia3").touch()
            proc = root / "proc"
            info = proc / "0000:03:00.0"
            info.mkdir(parents=True)
            uuid = "GPU-cccccccc-cccc-cccc-cccc-cccccccccccc"
            (info / "information").write_text(f"GPU UUID: {uuid}\nDevice Minor: 3\n", encoding="ascii")
            result = platform_probe.probe_inventory(
                {"capabilities": {"gpu-nvidia": True, "gpu-nvidia-cdi": True}},
                sys_class_drm=root / "no-drm",
                dev_root=dev,
                proc_nvidia_gpus=proc,
                cdi_device_names={"nvidia.com/gpu=9", "nvidia.com/gpu=all"},
            )
            nvidia = result["accelerators"]["NVIDIA"]
            self.assertEqual(
                nvidia["selectors"],
                [{"type": "devices", "values": [str(dev / "nvidia3")]}],
            )
            self.assertEqual({"type": "cdi", "value": "nvidia.com/gpu=all"}, nvidia["allSelector"])

    def test_probe_emits_preferred_names_when_the_provider_cannot_be_queried(self) -> None:
        # main tolerated a missing toolkit by publishing selectors anyway; that
        # must not regress into silently dropping every CDI name.
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            dev = root / "dev"
            dev.mkdir()
            (dev / "nvidia0").touch()
            proc = root / "proc"
            info = proc / "0000:00:00.0"
            info.mkdir(parents=True)
            uuid = "GPU-dddddddd-dddd-dddd-dddd-dddddddddddd"
            (info / "information").write_text(f"GPU UUID: {uuid}\nDevice Minor: 0\n", encoding="ascii")
            result = platform_probe.probe_inventory(
                {"capabilities": {"gpu-nvidia": True, "gpu-nvidia-cdi": True}},
                sys_class_drm=root / "no-drm",
                dev_root=dev,
                proc_nvidia_gpus=proc,
                cdi_device_names=set(),
            )
            nvidia = result["accelerators"]["NVIDIA"]
            self.assertIn({"type": "cdi", "value": f"nvidia.com/gpu={uuid}"}, nvidia["selectors"])
            self.assertEqual({"type": "cdi", "value": "nvidia.com/gpu=all"}, nvidia["allSelector"])

    def test_cdi_names_must_be_reported_by_toolkit(self) -> None:
        good = subprocess.CompletedProcess(
            args=["nvidia-ctk", "cdi", "list"],
            returncode=0,
            stdout=(
                "INFO NVIDIA devices\n"
                "nvidia.com/gpu=0\n"
                "nvidia.com/gpu=GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\n"
                "nvidia.com/gpu=all\n"
            ),
            stderr="",
        )
        with mock.patch.object(platform_probe.subprocess, "run", return_value=good) as run:
            listed = platform_probe._listed_nvidia_cdi_devices("nvidia-ctk")
        self.assertIn("nvidia.com/gpu=all", listed)
        self.assertIn("nvidia.com/gpu=GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", listed)
        self.assertNotIn("INFO NVIDIA devices", listed)
        run.assert_called_once_with(
            ["nvidia-ctk", "cdi", "list"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )

        failed = subprocess.CompletedProcess(args=[], returncode=1, stdout="nvidia.com/gpu=all", stderr="error")
        with mock.patch.object(platform_probe.subprocess, "run", return_value=failed):
            self.assertEqual(platform_probe._listed_nvidia_cdi_devices("nvidia-ctk"), set())
        with mock.patch.object(platform_probe.subprocess, "run", side_effect=FileNotFoundError()):
            self.assertEqual(platform_probe._listed_nvidia_cdi_devices("nvidia-ctk"), set())
        timeout = subprocess.TimeoutExpired(cmd=["nvidia-ctk", "cdi", "list"], timeout=10)
        with mock.patch.object(platform_probe.subprocess, "run", side_effect=timeout):
            self.assertEqual(platform_probe._listed_nvidia_cdi_devices("nvidia-ctk"), set())

    def test_cli_accepts_the_toolkit_binary_and_environment_default(self) -> None:
        parser = platform_probe.build_parser()
        explicit = parser.parse_args(
            ["--base", "base.json", "--output", "out.json", "--nvidia-ctk-bin", "/run/nix-ctk"]
        )
        self.assertEqual("/run/nix-ctk", explicit.nvidia_ctk_bin)
        with mock.patch.dict(os.environ, {"NAS_V2_NVIDIA_CTK_BIN": "/env/nvidia-ctk"}, clear=False):
            from_environment = platform_probe.build_parser().parse_args(["--base", "base.json", "--output", "out.json"])
        self.assertEqual("/env/nvidia-ctk", from_environment.nvidia_ctk_bin)

    def _probe_with_driver_identities(self, identity_files: dict[str, str]) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            dev = root / "dev"
            dev.mkdir()
            (dev / "nvidia0").touch()
            proc = root / "proc"
            for device, information in identity_files.items():
                info = proc / device
                info.mkdir(parents=True)
                (info / "information").write_text(information, encoding="ascii")
            return platform_probe.probe_inventory(
                {"capabilities": {"gpu-nvidia": True, "gpu-nvidia-cdi": True}},
                sys_class_drm=root / "no-drm",
                dev_root=dev,
                proc_nvidia_gpus=proc,
                cdi_device_names={"nvidia.com/gpu=0", "nvidia.com/gpu=all"},
            )

    def test_duplicate_driver_minor_fails_closed(self) -> None:
        # Distinct UUIDs, same minor: only the duplicate-minor check can reject this.
        with self.assertRaisesRegex(platform_probe.PlatformProbeError, "duplicate NVIDIA GPU minor"):
            self._probe_with_driver_identities(
                {
                    "0000:01:00.0": "GPU UUID: GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\nDevice Minor: 0\n",
                    "0000:02:00.0": "GPU UUID: GPU-bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb\nDevice Minor: 0\n",
                }
            )

    def test_duplicate_driver_uuid_fails_closed(self) -> None:
        # Distinct minors, same UUID: only the duplicate-UUID check can reject this.
        with self.assertRaisesRegex(platform_probe.PlatformProbeError, "duplicate NVIDIA GPU UUID"):
            self._probe_with_driver_identities(
                {
                    "0000:01:00.0": "GPU UUID: GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\nDevice Minor: 0\n",
                    "0000:02:00.0": "GPU UUID: GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\nDevice Minor: 1\n",
                }
            )


class AcceleratorResolutionTests(unittest.TestCase):
    def test_optional_missing_gpu_falls_back_to_cpu(self) -> None:
        empty = {"schemaVersion": 1, "capabilities": {}, "accelerators": {}}
        resolved = accelerator.resolve_service_accelerators(
            "test",
            service("oci", {"kind": "gpu", "vendor": "any", "quantity": 1, "required": False, "mode": "shared"}),
            empty,
        )
        self.assertEqual([], resolved)

    def test_required_missing_gpu_fails_closed(self) -> None:
        empty = {"schemaVersion": 1, "capabilities": {}, "accelerators": {}}
        with self.assertRaisesRegex(accelerator.AcceleratorResolutionError, "requires unavailable GPU"):
            accelerator.resolve_service_accelerators(
                "test",
                service("oci", {"kind": "gpu", "vendor": "AMD", "quantity": 1, "required": True, "mode": "shared"}),
                empty,
            )

    def test_oci_prefers_nvidia_cdi_for_vendor_any(self) -> None:
        resolved = accelerator.resolve_service_accelerators(
            "test",
            service("oci", {"kind": "gpu", "vendor": "any", "quantity": 1, "required": True, "mode": "shared"}),
            inventory(),
        )
        self.assertEqual("NVIDIA", resolved[0]["vendor"])
        self.assertEqual([{"type": "cdi", "value": "nvidia.com/gpu=0"}], resolved[0]["selectors"])

    def test_quadlet_prefers_nvidia_cdi_for_vendor_any(self) -> None:
        resolved = accelerator.resolve_service_accelerators(
            "test",
            service("quadlet", {"kind": "gpu", "vendor": "any", "quantity": 1, "required": True, "mode": "shared"}),
            inventory(),
        )
        self.assertEqual([{"type": "cdi", "value": "nvidia.com/gpu=0"}], resolved[0]["selectors"])

    def test_systemd_uses_one_gpu_device_set(self) -> None:
        resolved = accelerator.resolve_service_accelerators(
            "test",
            service("systemd", {"kind": "gpu", "vendor": "any", "quantity": 1, "required": True, "mode": "shared"}),
            inventory(),
        )
        self.assertEqual("NVIDIA", resolved[0]["vendor"])
        self.assertEqual(
            [{"type": "devices", "values": ["/dev/nvidia0", "/dev/nvidiactl", "/dev/nvidia-uvm"]}],
            resolved[0]["selectors"],
        )

    def test_one_physical_gpu_is_never_selected_twice(self) -> None:
        request: dict[str, object] = {
            "kind": "gpu",
            "vendor": "NVIDIA",
            "quantity": 2,
            "required": True,
            "mode": "shared",
        }
        with self.assertRaises(accelerator.AcceleratorResolutionError):
            accelerator.resolve_service_accelerators("test", service("oci", request), inventory())
        optional = dict(request, required=False)
        self.assertEqual([], accelerator.resolve_service_accelerators("test", service("oci", optional), inventory()))

    def test_quantity_counts_distinct_physical_gpus_not_representations(self) -> None:
        two_gpus = inventory()
        nvidia = cast(dict[str, object], two_gpus["accelerators"])["NVIDIA"]
        assert isinstance(nvidia, dict)
        nvidia["selectors"] = [
            {"type": "devices", "values": ["/dev/nvidia0", "/dev/nvidiactl", "/dev/nvidia-uvm"]},
            {"type": "cdi", "value": "nvidia.com/gpu=0"},
            {"type": "devices", "values": ["/dev/nvidia1", "/dev/nvidiactl", "/dev/nvidia-uvm"]},
            {"type": "cdi", "value": "nvidia.com/gpu=1"},
        ]
        resolved = accelerator.resolve_service_accelerators(
            "test",
            service("oci", {"kind": "gpu", "vendor": "NVIDIA", "quantity": 2, "required": True, "mode": "shared"}),
            two_gpus,
        )
        self.assertEqual(
            [{"type": "cdi", "value": "nvidia.com/gpu=0"}, {"type": "cdi", "value": "nvidia.com/gpu=1"}],
            resolved[0]["selectors"],
        )
        with self.assertRaises(accelerator.AcceleratorResolutionError):
            accelerator.resolve_service_accelerators(
                "test",
                service("oci", {"kind": "gpu", "vendor": "NVIDIA", "quantity": 3, "required": True, "mode": "shared"}),
                two_gpus,
            )

    def test_uuid_cdi_inventory_counts_each_physical_gpu_once(self) -> None:
        # Reproduction from the PR #189 review: device nodes and UUID CDI names
        # are the same two physical GPUs. quantity above the physical count must
        # fail instead of handing the same GPU to two slots.
        two_gpus = inventory()
        nvidia = cast(dict[str, object], two_gpus["accelerators"])["NVIDIA"]
        assert isinstance(nvidia, dict)
        nvidia["selectors"] = [
            {"type": "devices", "values": ["/dev/nvidia0", "/dev/nvidiactl", "/dev/nvidia-uvm"]},
            {"type": "cdi", "value": "nvidia.com/gpu=GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"},
            {"type": "devices", "values": ["/dev/nvidia1", "/dev/nvidiactl", "/dev/nvidia-uvm"]},
            {"type": "cdi", "value": "nvidia.com/gpu=GPU-bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"},
        ]
        nvidia["minorByUuid"] = {
            "GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa": 0,
            "GPU-bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb": 1,
        }
        resolved = accelerator.resolve_service_accelerators(
            "test",
            service("oci", {"kind": "gpu", "vendor": "NVIDIA", "quantity": 2, "required": True, "mode": "shared"}),
            two_gpus,
        )
        self.assertEqual(
            [
                {"type": "cdi", "value": "nvidia.com/gpu=GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"},
                {"type": "cdi", "value": "nvidia.com/gpu=GPU-bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"},
            ],
            resolved[0]["selectors"],
        )
        for quantity in (3, 4):
            with self.subTest(quantity=quantity):
                with self.assertRaises(accelerator.AcceleratorResolutionError):
                    accelerator.resolve_service_accelerators(
                        "test",
                        service(
                            "oci",
                            {
                                "kind": "gpu",
                                "vendor": "NVIDIA",
                                "quantity": quantity,
                                "required": True,
                                "mode": "shared",
                            },
                        ),
                        two_gpus,
                    )

    def test_probe_inventory_cannot_over_satisfy_quantity(self) -> None:
        # Contract check: the map the probe publishes is what makes the
        # resolver count a UUID CDI name and /dev/nvidiaN as one GPU.
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            dev = root / "dev"
            dev.mkdir()
            for minor in (0, 1):
                (dev / f"nvidia{minor}").touch()
            proc = root / "proc"
            uuids = {
                0: "GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                1: "GPU-bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            }
            for index, (minor, uuid) in enumerate(uuids.items()):
                info = proc / f"0000:0{index}:00.0"
                info.mkdir(parents=True)
                (info / "information").write_text(f"GPU UUID: {uuid}\nDevice Minor: {minor}\n", encoding="ascii")
            probed = platform_probe.probe_inventory(
                {"capabilities": {"gpu-nvidia": True, "gpu-nvidia-cdi": True}},
                sys_class_drm=root / "no-drm",
                dev_root=dev,
                proc_nvidia_gpus=proc,
                cdi_device_names={f"nvidia.com/gpu={uuid}" for uuid in uuids.values()} | {"nvidia.com/gpu=all"},
            )
            resolved = accelerator.resolve_service_accelerators(
                "test",
                service("oci", {"kind": "gpu", "vendor": "NVIDIA", "quantity": 2, "required": True, "mode": "shared"}),
                probed,
            )
            self.assertEqual(
                [f"nvidia.com/gpu={uuid}" for uuid in uuids.values()],
                [entry["value"] for entry in resolved[0]["selectors"]],
            )
            with self.assertRaises(accelerator.AcceleratorResolutionError):
                accelerator.resolve_service_accelerators(
                    "test",
                    service(
                        "oci",
                        {"kind": "gpu", "vendor": "NVIDIA", "quantity": 3, "required": True, "mode": "shared"},
                    ),
                    probed,
                )

    def test_uuid_cdi_inventory_without_minor_map_fails_closed(self) -> None:
        # The verbatim double-count reproduction: UUID CDI names and no identity
        # map. The resolver cannot tell the two representations apart, so it
        # must refuse instead of counting the same GPU twice.
        two_gpus = inventory()
        nvidia = cast(dict[str, object], two_gpus["accelerators"])["NVIDIA"]
        assert isinstance(nvidia, dict)
        nvidia["selectors"] = [
            {"type": "devices", "values": ["/dev/nvidia0", "/dev/nvidiactl", "/dev/nvidia-uvm"]},
            {"type": "cdi", "value": "nvidia.com/gpu=GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"},
            {"type": "devices", "values": ["/dev/nvidia1", "/dev/nvidiactl", "/dev/nvidia-uvm"]},
            {"type": "cdi", "value": "nvidia.com/gpu=GPU-bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"},
        ]
        for quantity in (2, 3, 4):
            with self.subTest(quantity=quantity):
                with self.assertRaisesRegex(accelerator.AcceleratorResolutionError, "minorByUuid"):
                    accelerator.resolve_service_accelerators(
                        "test",
                        service(
                            "oci",
                            {
                                "kind": "gpu",
                                "vendor": "NVIDIA",
                                "quantity": quantity,
                                "required": True,
                                "mode": "shared",
                            },
                        ),
                        two_gpus,
                    )
        # A device-only runtime never consults the UUID names, so it still works.
        resolved = accelerator.resolve_service_accelerators(
            "test",
            service("systemd", {"kind": "gpu", "vendor": "NVIDIA", "quantity": 2, "required": True, "mode": "shared"}),
            two_gpus,
        )
        self.assertEqual(2, len(resolved[0]["selectors"]))

    def test_single_gpu_host_cannot_meet_quantity_two_from_two_representations(self) -> None:
        one_gpu = inventory()
        nvidia = cast(dict[str, object], one_gpu["accelerators"])["NVIDIA"]
        assert isinstance(nvidia, dict)
        nvidia["selectors"] = [
            {"type": "devices", "values": ["/dev/nvidia0", "/dev/nvidiactl", "/dev/nvidia-uvm"]},
            {"type": "cdi", "value": "nvidia.com/gpu=GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"},
        ]
        nvidia["minorByUuid"] = {"GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa": 0}
        with self.assertRaises(accelerator.AcceleratorResolutionError):
            accelerator.resolve_service_accelerators(
                "test",
                service("oci", {"kind": "gpu", "vendor": "NVIDIA", "quantity": 2, "required": True, "mode": "shared"}),
                one_gpu,
            )
        resolved = accelerator.resolve_service_accelerators(
            "test",
            service("oci", {"kind": "gpu", "vendor": "NVIDIA", "quantity": 1, "required": True, "mode": "shared"}),
            one_gpu,
        )
        self.assertEqual(
            [{"type": "cdi", "value": "nvidia.com/gpu=GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}],
            resolved[0]["selectors"],
        )

    def test_compose_target_survives_resolution(self) -> None:
        resolved = accelerator.resolve_service_accelerators(
            "test",
            service(
                "compose",
                {
                    "kind": "gpu",
                    "vendor": "NVIDIA",
                    "quantity": "all",
                    "required": True,
                    "mode": "shared",
                    "target": "worker",
                },
            ),
            inventory(),
        )
        self.assertEqual("worker", resolved[0]["target"])
        self.assertEqual([{"type": "cdi", "value": "nvidia.com/gpu=all"}], resolved[0]["selectors"])

    def test_vm_passthrough_is_never_auto_resolved(self) -> None:
        request = {
            "kind": "gpu",
            "vendor": "NVIDIA",
            "quantity": 1,
            "required": True,
            "mode": "passthrough",
            "device": "pci:0000:01:00.0",
        }
        self.assertEqual(
            [request], accelerator.resolve_service_accelerators("test", service("vm", request), inventory())
        )

    def test_effective_materializes_cdi_runtime_request(self) -> None:
        raw_service = service(
            "oci",
            {"kind": "gpu", "vendor": "NVIDIA", "quantity": 1, "required": True, "mode": "shared"},
        )
        effective = {"services": {"test": raw_service}, "derived": {}}
        resolved = accelerator.resolve_effective(effective, inventory())
        self.assertEqual("nvidia.com/gpu=0", resolved["services"]["test"]["resources"]["accelerators"][0]["device"])
        self.assertEqual("cdi", resolved["derived"]["accelerators"]["test"][0]["selectors"][0]["type"])

    def test_host_device_set_materializes_all_required_device_acls(self) -> None:
        raw_service = service(
            "systemd",
            {"kind": "gpu", "vendor": "NVIDIA", "quantity": 1, "required": True, "mode": "shared"},
        )
        resolved = accelerator.resolve_effective({"services": {"test": raw_service}, "derived": {}}, inventory())
        lines = attachment_lines(resolved, resolved["services"]["test"])
        self.assertEqual("DevicePolicy=closed", lines[0])
        self.assertIn('DeviceAllow="/dev/nvidia0" rw', lines)
        self.assertIn('DeviceAllow="/dev/nvidiactl" rw', lines)
        self.assertIn('DeviceAllow="/dev/nvidia-uvm" rw', lines)

    def test_deviceallow_quotes_only_device_path_not_access_mode(self) -> None:
        lines = attachment_lines(
            {"storageResources": {}, "credentials": {}},
            {
                "runtime": {"type": "systemd"},
                "storage": [],
                "credentials": [],
                "resources": {"accelerators": [{"device": "/dev/nvidia0", "mode": "shared"}]},
            },
        )
        self.assertIn('DeviceAllow="/dev/nvidia0" rw', lines)
        self.assertNotIn('DeviceAllow="/dev/nvidia0 rw"', lines)

    def test_deviceallow_rejects_a_path_it_cannot_express(self) -> None:
        """DeviceAllow takes two whitespace-separated arguments.

        A device path containing whitespace cannot be expressed unambiguously,
        and systemd does not honour the quoted form, so projection must refuse
        it rather than emit a directive that grants nothing.
        """
        with self.assertRaisesRegex(SystemdAttachmentError, "whitespace or control characters"):
            attachment_lines(
                {"storageResources": {}, "credentials": {}},
                {
                    "runtime": {"type": "systemd"},
                    "storage": [],
                    "credentials": [],
                    "resources": {"accelerators": [{"device": "/dev/custom gpu", "mode": "shared"}]},
                },
            )

    def test_quadlet_cdi_lowers_to_v2_owned_podman_device_arg(self) -> None:
        raw_service = service(
            "oci",
            {"kind": "gpu", "vendor": "NVIDIA", "quantity": 1, "required": True, "mode": "shared"},
        )
        raw_service.update(
            {
                "runtime": {"type": "oci", "image": "example.invalid/test:latest", "pull": "missing", "command": []},
                "network": {
                    "mode": "host",
                    "outboundDefault": "allow",
                    "lanAccess": False,
                    "allowedHostPorts": [],
                    "allowedEgress": [],
                },
                "listeners": {},
                "routes": {},
            }
        )
        resolved = accelerator.resolve_effective({"services": {"test": raw_service}, "derived": {}}, inventory())
        rendered = quadlet.render_quadlet(
            resolved,
            "test",
            resolved["services"]["test"],
            unit_lines=[],
            service_lines=[],
        ).decode()
        self.assertIn('PodmanArgs=--device="nvidia.com/gpu=0"', rendered)


class CdiNameStrategyContractTests(unittest.TestCase):
    """The Nix generator and the probe must agree on the CDI naming contract.

    Option A: the host publishes index and UUID names; the probe prefers UUID
    and keeps the index name as the fallback.
    """

    def test_nix_host_platform_publishes_both_names_and_the_probe_prefers_uuid(self) -> None:
        host_platform = (ROOT / "modules/nas/config/host-platform.nix").read_text(encoding="utf-8")
        managed = (ROOT / "modules/nas/config/managed-services.nix").read_text(encoding="utf-8")

        self.assertIn(
            'device-name-strategy = lib.mkIf (hasNvidiaGpu && cfg.hardware.nvidia.containerToolkit) "index";',
            host_platform,
        )
        self.assertIn('"--device-name-strategy=uuid"', host_platform)
        self.assertIn('"--nvidia-ctk-bin"', managed)
        self.assertIn('config.hardware.nvidia-container-toolkit.package "nvidia-ctk"', managed)
        self.assertIn(
            '"nvidia-container-toolkit-cdi-generator.service"',
            managed.split("systemd.services.nas-managed-services-reconcile = {", 1)[1],
        )

    def test_probe_prefers_the_uuid_name_over_the_driver_minor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            dev = root / "dev"
            dev.mkdir()
            (dev / "nvidia0").touch()
            proc = root / "proc"
            info = proc / "0000:00:00.0"
            info.mkdir(parents=True)
            uuid = "GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
            (info / "information").write_text(f"GPU UUID: {uuid}\nDevice Minor: 0\n", encoding="ascii")
            result = platform_probe.probe_inventory(
                {"capabilities": {"gpu-nvidia": True, "gpu-nvidia-cdi": True}},
                sys_class_drm=root / "no-drm",
                dev_root=dev,
                proc_nvidia_gpus=proc,
                cdi_device_names={"nvidia.com/gpu=0", f"nvidia.com/gpu={uuid}", "nvidia.com/gpu=all"},
            )
            cdi = [entry["value"] for entry in result["accelerators"]["NVIDIA"]["selectors"] if entry["type"] == "cdi"]
            self.assertEqual([f"nvidia.com/gpu={uuid}"], cdi)


if __name__ == "__main__":
    unittest.main()
