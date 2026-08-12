from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))

import nas_v2_accelerator as accelerator  # noqa: E402
import nas_v2_platform_probe as platform_probe  # noqa: E402


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
        "capabilities": {"gpu-nvidia": True, "gpu-nvidia-cdi": True},
        "accelerators": {},
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
            base = {"schemaVersion": 1, "capabilities": {"gpu-amd": True}}
            result = platform_probe.probe_inventory(base, sys_class_drm=sys_drm, dev_root=dev)
            self.assertIn("AMD", str(result))


class AcceleratorResolutionTests(unittest.TestCase):
    def test_valid_gpu_request_passes_through(self) -> None:
        for vendor in ("any", "NVIDIA", "AMD", "Intel"):
            with self.subTest(vendor=vendor):
                req = {"kind": "gpu", "vendor": vendor, "quantity": 1, "required": False, "mode": "shared"}
                for rt in ("oci", "quadlet", "systemd", "exec"):
                    resolved = accelerator.resolve_service_accelerators("test", service(rt, req), inventory())
                    self.assertEqual(1, len(resolved))
                    self.assertEqual(vendor, resolved[0]["vendor"])

    def test_vm_passthrough_is_preserved(self) -> None:
        req = {
            "kind": "gpu",
            "vendor": "NVIDIA",
            "quantity": 1,
            "required": True,
            "mode": "passthrough",
            "device": "pci:0000:01:00.0",
        }
        self.assertEqual([req], accelerator.resolve_service_accelerators("test", service("vm", req), inventory()))

    def test_is_cdi_selector(self) -> None:
        self.assertTrue(accelerator.is_cdi_selector("nvidia.com/gpu=0"))
        self.assertFalse(accelerator.is_cdi_selector("/dev/nvidia0"))

    def test_effective_passthrough(self) -> None:
        raw = service("oci", {"kind": "gpu", "vendor": "any", "quantity": 1, "required": True, "mode": "shared"})
        eff = {"services": {"test": raw}, "derived": {}}
        resolved = accelerator.resolve_effective(eff, inventory())
        self.assertIn("test", resolved["derived"]["accelerators"])


if __name__ == "__main__":
    unittest.main()
