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
        storage: bool = False,
        mode: str = "rw",
        target: str = "nas-data",
    ) -> dict:
        resolved_storage = []
        if storage:
            resolved_storage.append(
                {
                    "resource": "vm-data",
                    "hostPath": "/tank/vms/demo-data",
                    "guestPath": "/data",
                    "mode": mode,
                    "target": target,
                }
            )
        return {
            "label": "Demo VM",
            "enabled": enabled,
            "lifecycle": {"mode": lifecycle},
            "runtime": {"type": "vm", "source": source, "startPolicy": "boot"},
            "resolvedStorage": resolved_storage,
        }

    def test_plan_uses_native_xml_source_without_v2_storage(self) -> None:
        plan = libvirt.plan_libvirt("demo", self.service())
        self.assertEqual(plan["runtime"], "libvirt")
        self.assertEqual(plan["source"], "/var/lib/nas-control/apps/demo/domain.xml")
        self.assertEqual(plan["nativeSource"], "/var/lib/nas-control/apps/demo/domain.xml")
        self.assertEqual(plan["lifecycle"], "persistent")
        self.assertEqual(plan["actions"][0]["type"], "virsh-define")
        self.assertEqual(plan["virtiofs"], [])

    def test_plan_uses_runtime_projection_for_v2_storage(self) -> None:
        plan = libvirt.plan_libvirt("demo", self.service(storage=True))
        self.assertEqual(plan["source"], "/run/nas-control/libvirt/demo.xml")
        self.assertEqual(plan["virtiofs"][0]["resource"], "vm-data")
        self.assertEqual(plan["virtiofs"][0]["target"], "nas-data")
        self.assertEqual(plan["virtiofs"][0]["guestPath"], "/data")

    def test_vm_storage_requires_explicit_virtiofs_target(self) -> None:
        service = self.service(storage=True)
        service["resolvedStorage"][0].pop("target")
        with self.assertRaisesRegex(msvc.ManagedServiceError, "virtiofs-mount-tag"):
            libvirt.plan_libvirt("demo", service)

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

    def test_render_projection_adds_shared_memory_and_virtiofs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            app_root = pathlib.Path(td) / "apps"
            source = app_root / "demo" / "domain.xml"
            source.parent.mkdir(parents=True)
            source.write_text("<domain><name>demo</name><devices/></domain>", encoding="utf-8")
            service = self.service(source=str(source), storage=True)
            with mock.patch.object(libvirt, "APP_ROOT", app_root):
                rendered = libvirt.render_domain_projection("demo", service)
            self.assertIsNotNone(rendered)
            text = rendered.decode("utf-8")
            self.assertIn('<source type="memfd"', text)
            self.assertIn('<access mode="shared"', text)
            self.assertIn('<driver type="virtiofs"', text)
            self.assertIn('<source dir="/tank/vms/demo-data"', text)
            self.assertIn('<target dir="nas-data"', text)
            self.assertNotIn("<readonly", text)

    def test_render_projection_marks_read_only_storage(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            app_root = pathlib.Path(td) / "apps"
            source = app_root / "demo" / "domain.xml"
            source.parent.mkdir(parents=True)
            source.write_text("<domain><devices/></domain>", encoding="utf-8")
            with mock.patch.object(libvirt, "APP_ROOT", app_root):
                rendered = libvirt.render_domain_projection(
                    "demo", self.service(source=str(source), storage=True, mode="ro")
                )
            self.assertIn(b"<readonly", rendered)

    def test_render_projection_rejects_target_collision(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            app_root = pathlib.Path(td) / "apps"
            source = app_root / "demo" / "domain.xml"
            source.parent.mkdir(parents=True)
            source.write_text(
                '<domain><devices><filesystem type="mount"><target dir="nas-data"/></filesystem></devices></domain>',
                encoding="utf-8",
            )
            with (
                mock.patch.object(libvirt, "APP_ROOT", app_root),
                self.assertRaisesRegex(msvc.ManagedServiceError, "already defines filesystem target"),
            ):
                libvirt.render_domain_projection("demo", self.service(source=str(source), storage=True))

    def test_render_projection_rejects_unsafe_xml_declarations(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            app_root = pathlib.Path(td) / "apps"
            source = app_root / "demo" / "domain.xml"
            source.parent.mkdir(parents=True)
            source.write_text('<!DOCTYPE domain [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><domain/>', encoding="utf-8")
            with (
                mock.patch.object(libvirt, "APP_ROOT", app_root),
                self.assertRaisesRegex(msvc.ManagedServiceError, "DTD or entity"),
            ):
                libvirt.render_domain_projection("demo", self.service(source=str(source), storage=True))

    def test_render_projection_rejects_non_shared_existing_memory_backing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            app_root = pathlib.Path(td) / "apps"
            source = app_root / "demo" / "domain.xml"
            source.parent.mkdir(parents=True)
            source.write_text(
                '<domain><memoryBacking><access mode="private"/></memoryBacking><devices/></domain>',
                encoding="utf-8",
            )
            with (
                mock.patch.object(libvirt, "APP_ROOT", app_root),
                self.assertRaisesRegex(msvc.ManagedServiceError, "access mode='shared'"),
            ):
                libvirt.render_domain_projection("demo", self.service(source=str(source), storage=True))

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
    def test_apply_uses_generated_projection_when_storage_is_attached(self, run) -> None:
        run.side_effect = [mock.Mock(), mock.Mock(returncode=0, stdout="running\n")]
        with mock.patch.object(libvirt, "_write_domain_projection", return_value=pathlib.Path("/run/projected.xml")):
            plan = libvirt.apply_libvirt("demo", self.service(storage=True))
        self.assertEqual(plan["source"], "/run/projected.xml")
        run.assert_any_call(["virsh", "define", "/run/projected.xml"], check=True)

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
