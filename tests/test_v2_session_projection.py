from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_network as network  # noqa: E402
import nas_v2_session_projection as projection  # noqa: E402
from nas_v2_spec import compile_document, load_schema, parse_yaml_text  # noqa: E402


class V2SessionProjectionTests(unittest.TestCase):
    def effective(self, *, scope: str = "instance") -> dict:
        path_template = "/srv/sessions/{instance}" if scope == "instance" else "/srv/users/{user}"
        yaml = f"""
schemaVersion: 3
storageResources:
  workspace:
    path: /srv/{"sessions" if scope == "instance" else "users"}
    pathTemplate: {path_template}
    scope: {scope}
    stateClass: authoritative
services:
  agent:
    name: Coding session
    workload:
      kind: session
    runtime:
      type: oci
      image: example.invalid/agent:1
      command: [agent]
    storage:
      - resource: workspace
        mountPath: /workspace
        access: write
    network:
      mode: isolated
      outboundDefault: deny
      lanAccess: false
      allowedHostPorts: []
      allowedEgress: []
"""
        return compile_document(
            parse_yaml_text(yaml),
            load_schema(ROOT / "schemas/managed-services-v3.schema.json"),
            platform_capabilities=None,
        )

    def generate(self, effective: dict, output: pathlib.Path):
        return projection.generate_projection(
            effective,
            output_dir=output,
            python_bin="/usr/bin/python3",
            source_dir=SERVICES,
            systemctl_bin="/usr/bin/systemctl",
            uv_bin="/usr/bin/uv",
            podman_bin="/usr/bin/podman",
        )

    def test_session_becomes_descriptor_and_target_not_persistent_template(self):
        effective = self.effective()
        with tempfile.TemporaryDirectory() as raw:
            output = pathlib.Path(raw) / "projection"
            files, manifest = self.generate(effective, output)
            target = output / "units/nas-v2-session-agent.target"
            descriptor = output / "descriptors/agent.session.json"
            self.assertIn(target, files)
            self.assertIn(descriptor, files)
            self.assertFalse(any(path.name == "nas-v2-session-agent@.service" for path in files))
            self.assertNotIn("nas-v2-session-agent.target", manifest["startUnits"])
            self.assertIn("nas-v2-session-agent.target", manifest["ownedUnits"])
            self.assertFalse(any(unit.endswith("@.service") for unit in manifest["ownedUnits"]))
            description = json.loads(files[descriptor])
            self.assertEqual(2, description["schemaVersion"])
            self.assertEqual(description["volumeTemplates"][0]["sourceTemplate"], "/srv/sessions/{instance}")
            self.assertFalse(description["requiresUser"])
            self.assertEqual("/usr/bin/systemd-run", description["systemdRun"])
            self.assertNotIn("/srv/sessions:/workspace", " ".join(description["runArgs"]))

    def test_isolated_session_gets_shared_target_owned_network_and_transient_dependency(self):
        effective = self.effective()
        with tempfile.TemporaryDirectory() as raw:
            output = pathlib.Path(raw) / "projection"
            files, manifest = self.generate(effective, output)
            network.augment_projection(
                effective,
                output_dir=output,
                files=files,
                manifest=manifest,
                firewalld_enabled=True,
            )
            source = output / "quadlet/nas-v2-snet-agent.network"
            rendered = files[source].decode()
            self.assertIn("PartOf=nas-v2-session-agent.target", rendered)
            self.assertIn("NetworkName=nas-v2-session-agent", rendered)
            self.assertIn("NetworkDeleteOnStop=true", rendered)
            description = json.loads(files[output / "descriptors/agent.session.json"])
            self.assertIn("nas-v2-session-agent.target", description["requires"])
            self.assertIn("nas-v2-snet-agent-network.service", description["requires"])

    def test_user_scoped_storage_is_deferred_to_authenticated_transient_launcher(self):
        effective = self.effective(scope="user")
        with tempfile.TemporaryDirectory() as raw:
            output = pathlib.Path(raw) / "projection"
            files, _manifest = self.generate(effective, output)
            description = json.loads(files[output / "descriptors/agent.session.json"])
            self.assertTrue(description["requiresUser"])
            self.assertEqual("user", description["volumeTemplates"][0]["scope"])
            self.assertEqual("/srv/users/{user}", description["volumeTemplates"][0]["sourceTemplate"])

    def test_cdi_accelerator_is_lowered_to_podman_device_selector(self):
        effective = self.effective()
        effective["services"]["agent"]["resources"]["accelerators"] = [
            {
                "type": "gpu",
                "mode": "shared",
                "quantity": 1,
                "device": "nvidia.com/gpu=all",
            }
        ]
        with tempfile.TemporaryDirectory() as raw:
            output = pathlib.Path(raw) / "projection"
            files, _manifest = self.generate(effective, output)
            description = json.loads(files[output / "descriptors/agent.session.json"])
            run_args = description["runArgs"]
            index = run_args.index("--device")
            self.assertEqual("nvidia.com/gpu=all", run_args[index + 1])

    def test_cdi_accelerator_rejects_device_path_target(self):
        effective = self.effective()
        effective["services"]["agent"]["resources"]["accelerators"] = [
            {
                "type": "gpu",
                "mode": "shared",
                "quantity": 1,
                "device": "nvidia.com/gpu=all",
                "target": "/dev/dri/renderD128",
            }
        ]
        with tempfile.TemporaryDirectory() as raw:
            with self.assertRaisesRegex(
                projection.SessionProjectionError,
                "CDI accelerator selectors may not declare a device-path target",
            ):
                self.generate(effective, pathlib.Path(raw) / "projection")

    def test_non_session_service_cannot_depend_on_session_template(self):
        effective = self.effective()
        effective["services"]["consumer"] = {
            "name": "Consumer",
            "enabled": True,
            "managed": True,
            "workload": {"kind": "daemon", "activation": "persistent", "schedules": []},
            "runtime": {"type": "systemd", "unit": "consumer.service"},
            "dependencies": [{"service": "agent", "condition": "started"}],
            "requiresCapabilities": [],
            "authorization": {"capabilities": []},
            "resources": {"accelerators": []},
            "sandbox": {"mode": "inherit"},
            "storage": [],
            "credentials": [],
            "listeners": {},
            "routes": {},
            "backup": {"enabled": False, "consistency": "filesystem"},
        }
        with tempfile.TemporaryDirectory() as raw:
            with self.assertRaisesRegex(projection.SessionProjectionError, "may not depend on session template"):
                self.generate(effective, pathlib.Path(raw) / "projection")


if __name__ == "__main__":
    unittest.main()
