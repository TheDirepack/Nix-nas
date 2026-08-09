from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))

import nas_managed_service as msvc  # noqa: E402
import nas_service_runtime_libvirt as libvirt  # noqa: E402


class LibvirtAdapterTests(unittest.TestCase):
    def service(
        self,
        *,
        enabled: bool = True,
        source: str = "/var/lib/nas-control/apps/demo/domain.xml",
        lifecycle: str = "persistent",
    ) -> dict:
        return {
            "label": "Demo VM",
            "enabled": enabled,
            "lifecycle": {"mode": lifecycle},
            "runtime": {"type": "vm", "source": source, "startPolicy": "boot"},
            "resolvedStorage": [
                {
                    "resource": "vm-data",
                    "hostPath": "/tank/vms/demo-data",
                    "guestPath": "/data",
                    "mode": "rw",
                }
            ],
        }

    def test_plan_uses_native_xml_source(self) -> None:
        plan = libvirt.plan_libvirt("demo", self.service())
        self.assertEqual(plan["runtime"], "libvirt")
        self.assertEqual(plan["source"], "/var/lib/nas-control/apps/demo/domain.xml")
        self.assertEqual(plan["lifecycle"], "persistent")
        self.assertEqual(plan["actions"][0]["type"], "virsh-define")
        self.assertEqual(plan["resolvedStorage"][0]["resource"], "vm-data")

    def test_enabled_session_lifecycle_is_rejected(self) -> None:
        with self.assertRaisesRegex(msvc.ManagedServiceError, "session lifecycle is not supported for libvirt"):
            libvirt.plan_libvirt("demo", self.service(lifecycle="session"))

    def test_disabled_session_can_be_destroyed_for_cleanup(self) -> None:
        plan = libvirt.plan_libvirt("demo", self.service(enabled=False, lifecycle="session"))
        self.assertEqual(plan["actions"][1]["operation"], "destroy")

    def test_source_must_be_native_xml_under_service_root(self) -> None:
        for source in (
            "/var/lib/nas-control/apps/other/domain.xml",
            "/var/lib/nas-control/apps/demo/domain.yaml",
        ):
            with self.subTest(source=source), self.assertRaises(msvc.ManagedServiceError):
                libvirt.plan_libvirt("demo", self.service(source=source))

    def test_symlink_escape_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            app_root = pathlib.Path(td) / "apps"
            root = app_root / "demo"
            root.mkdir(parents=True)
            outside = pathlib.Path(td) / "outside.xml"
            outside.write_text("<domain/>", encoding="utf-8")
            link = root / "domain.xml"
            link.symlink_to(outside)
            with (
                mock.patch.object(libvirt, "APP_ROOT", app_root),
                self.assertRaisesRegex(msvc.ManagedServiceError, "must be under"),
            ):
                libvirt.plan_libvirt("demo", self.service(source=str(link)))

    @mock.patch.object(libvirt.subprocess, "run")
    def test_apply_defines_native_xml_and_starts_stopped_domain(self, run) -> None:
        run.side_effect = [
            mock.Mock(),
            mock.Mock(returncode=0, stdout="shut off\n"),
            mock.Mock(),
        ]
        libvirt.apply_libvirt("demo", self.service())
        run.assert_any_call(["virsh", "define", "/var/lib/nas-control/apps/demo/domain.xml"], check=True)
        run.assert_any_call(
            ["virsh", "domstate", "demo"],
            check=False,
            capture_output=True,
            text=True,
        )
        run.assert_any_call(["virsh", "start", "demo"], check=True)

    @mock.patch.object(libvirt.subprocess, "run")
    def test_disabled_apply_stops_domain_without_deleting_storage(self, run) -> None:
        run.side_effect = [mock.Mock(), mock.Mock()]
        libvirt.apply_libvirt("demo", self.service(enabled=False))
        run.assert_any_call(["virsh", "destroy", "demo"], check=False)
        for call in run.call_args_list:
            self.assertNotIn("--remove-all-storage", call.args[0])

    @mock.patch.object(libvirt.subprocess, "run")
    def test_remove_never_uses_remove_all_storage(self, run) -> None:
        run.side_effect = [mock.Mock(), mock.Mock(returncode=0)]
        libvirt.remove_libvirt("demo")
        run.assert_any_call(["virsh", "destroy", "demo"], check=False)
        run.assert_any_call(["virsh", "undefine", "demo", "--nvram"], check=False)
        for call in run.call_args_list:
            self.assertNotIn("--remove-all-storage", call.args[0])


if __name__ == "__main__":
    unittest.main()
