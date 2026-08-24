from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
SCHEMA = ROOT / "schemas" / "managed-services-v3.schema.json"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_libvirt as libvirt  # noqa: E402
import nas_v2_spec as v2  # noqa: E402
import nas_v2_systemd as systemd  # noqa: E402
import nas_v2_systemd_native as systemd_native  # noqa: E402


def required(element: ET.Element | None) -> ET.Element:
    if element is None:
        raise AssertionError("expected XML element was missing")
    return element


class V2LibvirtTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = v2.load_schema(SCHEMA)

    def fixture(self, root: pathlib.Path, *, xml: str | None = None) -> tuple[dict, dict, pathlib.Path]:
        app_root = root / "apps"
        service_root = app_root / "demo"
        service_root.mkdir(parents=True)
        source = service_root / "domain.xml"
        source.write_text(
            xml
            or """<domain type="kvm">
  <name>demo-vm</name>
  <memory unit="MiB">1024</memory>
  <vcpu>2</vcpu>
  <os><type arch="x86_64">hvm</type></os>
  <devices><disk type="file" device="disk"/></devices>
</domain>
""",
            encoding="utf-8",
        )
        document = {
            "schemaVersion": 3,
            "storageResources": {"projects": {"path": "/tank/projects", "stateClass": "authoritative"}},
            "services": {
                "demo": {
                    "name": "Demo VM",
                    "workload": {"kind": "daemon", "activation": "persistent"},
                    "runtime": {"type": "vm", "source": str(source)},
                    "storage": [
                        {"resource": "projects", "mountPath": "/workspace", "mountTag": "projects", "access": "read"}
                    ],
                    "resources": {
                        "accelerators": [
                            {
                                "kind": "gpu",
                                "vendor": "AMD",
                                "required": True,
                                "mode": "passthrough",
                                "device": "pci:0000:03:00.0",
                            }
                        ]
                    },
                }
            },
        }
        with mock.patch.object(v2, "APP_ROOT", pathlib.PurePosixPath(str(app_root))):
            effective = v2.compile_document(document, self.schema)
        return effective, effective["services"]["demo"], app_root

    def test_projects_virtiofs_shared_memory_and_explicit_pci_hostdev(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            effective, service, app_root = self.fixture(root)
            with mock.patch.object(libvirt, "APP_ROOT", app_root):
                source, name, rendered = libvirt.render_domain_xml(effective, "demo", service)

        domain = ET.fromstring(rendered)
        self.assertEqual(name, "demo-vm")
        self.assertEqual(source.name, "domain.xml")
        memory_source = required(domain.find("memoryBacking/source"))
        memory_access = required(domain.find("memoryBacking/access"))
        filesystem = required(domain.find("devices/filesystem"))
        driver = required(filesystem.find("driver"))
        filesystem_source = required(filesystem.find("source"))
        target = required(filesystem.find("target"))
        hostdev = required(domain.find("devices/hostdev"))
        host_address = required(hostdev.find("source/address"))

        self.assertEqual(memory_source.get("type"), "memfd")
        self.assertEqual(memory_access.get("mode"), "shared")
        self.assertEqual(filesystem.get("type"), "mount")
        self.assertEqual(driver.get("type"), "virtiofs")
        self.assertEqual(filesystem_source.get("dir"), "/tank/projects")
        self.assertEqual(target.get("dir"), "projects")
        self.assertIsNotNone(filesystem.find("readonly"))
        self.assertEqual(hostdev.attrib, {"mode": "subsystem", "type": "pci", "managed": "yes"})
        self.assertEqual(
            host_address.attrib,
            {"domain": "0x0000", "bus": "0x03", "slot": "0x00", "function": "0x0"},
        )

    def test_conflicting_memory_backing_fails_closed(self):
        xml = """<domain type="kvm">
  <name>demo-vm</name>
  <memoryBacking><source type="file"/><access mode="private"/></memoryBacking>
  <devices/>
</domain>
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            effective, service, app_root = self.fixture(root, xml=xml)
            with (
                mock.patch.object(libvirt, "APP_ROOT", app_root),
                self.assertRaisesRegex(libvirt.LibvirtProjectionError, "compatible memoryBacking"),
            ):
                libvirt.render_domain_xml(effective, "demo", service)

    def test_source_dtd_and_symlink_escape_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            effective, service, app_root = self.fixture(root)
            source = pathlib.Path(service["runtime"]["source"])
            source.write_text(
                '<!DOCTYPE domain [<!ENTITY x "bad">]><domain><name>&x;</name><devices/></domain>', encoding="utf-8"
            )
            with (
                mock.patch.object(libvirt, "APP_ROOT", app_root),
                self.assertRaisesRegex(libvirt.LibvirtProjectionError, "unsafe VM domain XML"),
            ):
                libvirt.render_domain_xml(effective, "demo", service)

            outside = root / "outside.xml"
            outside.write_text("<domain><name>outside</name><devices/></domain>", encoding="utf-8")
            source.unlink()
            source.symlink_to(outside)
            with (
                mock.patch.object(libvirt, "APP_ROOT", app_root),
                self.assertRaisesRegex(libvirt.LibvirtProjectionError, "managed app root"),
            ):
                libvirt.render_domain_xml(effective, "demo", service)

    def test_duplicate_pci_hostdev_is_rejected(self):
        xml = """<domain type="kvm">
  <name>demo-vm</name>
  <devices>
    <hostdev mode="subsystem" type="pci" managed="yes">
      <source><address domain="0x0000" bus="0x03" slot="0x00" function="0x0"/></source>
    </hostdev>
  </devices>
</domain>
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            effective, service, app_root = self.fixture(root, xml=xml)
            with (
                mock.patch.object(libvirt, "APP_ROOT", app_root),
                self.assertRaisesRegex(libvirt.LibvirtProjectionError, "already present"),
            ):
                libvirt.render_domain_xml(effective, "demo", service)

    def test_start_uses_transient_create_only(self):
        config = {"virsh": "/nix/store/libvirt/bin/virsh", "domain": "demo-vm", "xml": "/run/demo.xml"}
        with mock.patch.object(libvirt, "_run") as run:
            libvirt.start_domain(config)
        run.assert_called_once_with("/nix/store/libvirt/bin/virsh", "create", "/run/demo.xml")

    def test_stop_times_out_without_force_destroy(self):
        config = {
            "virsh": "/nix/store/libvirt/bin/virsh",
            "domain": "demo-vm",
            "xml": "/run/demo.xml",
            "shutdownTimeoutSeconds": 1,
        }
        running = subprocess.CompletedProcess([], 0, stdout="running\n", stderr="")
        with (
            mock.patch.object(libvirt, "_run", return_value=running) as run,
            mock.patch.object(libvirt.time, "monotonic", side_effect=[0.0, 0.0, 2.0]),
            mock.patch.object(libvirt.time, "sleep"),
            self.assertRaisesRegex(libvirt.LibvirtProjectionError, "did not shut down gracefully"),
        ):
            libvirt.stop_domain(config)

        commands = [call.args[1:] for call in run.call_args_list]
        self.assertIn(("shutdown", "demo-vm"), commands)
        self.assertFalse(any(command and command[0] == "destroy" for command in commands))

    def test_unified_systemd_projection_owns_transient_vm_lifecycle(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            effective, _service, app_root = self.fixture(root)
            output = root / "projection"
            with mock.patch.object(libvirt, "APP_ROOT", app_root):
                files, manifest = systemd.generate_projection(
                    effective,
                    output_dir=output,
                    python_bin="/run/current-system/sw/bin/python3",
                    source_dir=pathlib.Path("/nix/store/v2/services"),
                    systemctl_bin="/run/current-system/sw/bin/systemctl",
                    uv_bin="/nix/store/uv/bin/uv",
                    virsh_bin="/nix/store/libvirt/bin/virsh",
                )

        unit = files[output / "units/nas-v2-demo.service"].decode()
        descriptor = json.loads(files[output / "descriptors/demo.vm.json"])
        self.assertIn("Requires=libvirtd.service", unit)
        self.assertIn('nas_v2_libvirt.py" start', unit)
        self.assertIn('nas_v2_libvirt.py" stop', unit)
        self.assertEqual(descriptor["domain"], "demo-vm")
        self.assertEqual(descriptor["virsh"], "/nix/store/libvirt/bin/virsh")
        self.assertIn(output / "vm/demo.xml", files)
        self.assertIn("nas-v2-demo.service", manifest["ownedUnits"])
        self.assertIn("nas-v2-demo.service", manifest["startUnits"])

    def test_systemd_validation_requires_native_libvirt_schema_validator(self):
        files = {pathlib.Path("/run/nas-control/systemd/vm/demo.xml"): b"<domain><name>demo</name></domain>\n"}
        with self.assertRaisesRegex(systemd.SystemdProjectionError, "virt-xml-validate"):
            systemd.validate_projection(files, systemd_analyze_bin="systemd-analyze")

        with mock.patch.object(systemd_native, "validate_domain_xml") as validate:
            systemd.validate_projection(
                files,
                systemd_analyze_bin="systemd-analyze",
                virt_xml_validate_bin="/nix/store/libvirt/bin/virt-xml-validate",
            )
        validate.assert_called_once_with(
            files[pathlib.Path("/run/nas-control/systemd/vm/demo.xml")],
            validator_bin="/nix/store/libvirt/bin/virt-xml-validate",
        )

    def test_nix_runtime_module_pins_libvirt_tools(self):
        module = (ROOT / "modules/nas/config/managed-services.nix").read_text(encoding="utf-8")
        self.assertIn('NAS_V2_VIRSH_BIN = "${pkgs.libvirt}/bin/virsh";', module)
        self.assertIn('NAS_V2_VIRT_XML_VALIDATE_BIN = "${pkgs.libvirt}/bin/virt-xml-validate";', module)
        self.assertNotIn('"--virsh-bin"', module)
        self.assertNotIn('"--virt-xml-validate-bin"', module)


if __name__ == "__main__":
    unittest.main()
