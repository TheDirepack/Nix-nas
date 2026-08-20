from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))

import nas_v2_accelerator as accelerator  # noqa: E402
import nas_v2_platform_probe as platform_probe  # noqa: E402
import nas_v2_quadlet as quadlet  # noqa: E402
from nas_v2_systemd import attachment_lines  # noqa: E402


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
            base = {
                "schemaVersion": 1,
                "capabilities": {
                    "gpu-amd": True,
                    "gpu-intel": False,
                    "gpu-nvidia": True,
                    "gpu-nvidia-cdi": True,
                },
            }
            result = platform_probe.probe_inventory(base, sys_class_drm=sys_drm, dev_root=dev)
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
                {"type": "cdi", "value": "nvidia.com/gpu=0"},
                result["accelerators"]["NVIDIA"]["selectors"],
            )
            self.assertEqual(
                {"type": "cdi", "value": "nvidia.com/gpu=all"},
                result["accelerators"]["NVIDIA"]["allSelector"],
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
        self.assertIn('DeviceAllow="/dev/nvidia0 rw"', lines)
        self.assertIn('DeviceAllow="/dev/nvidiactl rw"', lines)
        self.assertIn('DeviceAllow="/dev/nvidia-uvm rw"', lines)

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


if __name__ == "__main__":
    unittest.main()
