from __future__ import annotations

import hashlib
import json
import pathlib
import stat
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_network as reconcile  # noqa: E402


class V2FirewalldReconcileTests(unittest.TestCase):
    def executable(self, path: pathlib.Path, body: str) -> pathlib.Path:
        path.write_text("#!/bin/sh\nset -eu\n" + body, encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return path

    def projection(self, root: pathlib.Path, content: bytes = b"<zone/>\n") -> tuple[pathlib.Path, pathlib.Path, str]:
        projection = root / "projection"
        target = "zones/nv2z0123456789ab.xml"
        source = projection / target
        source.parent.mkdir(parents=True)
        source.write_bytes(content)
        manifest = projection / "manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "files": [{"target": target, "sha256": hashlib.sha256(content).hexdigest()}],
                    "owners": [{"service": "demo", "target": target}],
                }
            ),
            encoding="utf-8",
        )
        return projection, manifest, target

    def test_create_noop_and_stale_removal(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            projection, manifest, target = self.projection(root)
            system_config = root / "firewalld"
            (system_config / "zones").mkdir(parents=True)
            (system_config / "policies").mkdir(parents=True)
            offline = self.executable(root / "offline", "exit 0\n")
            firewall = self.executable(root / "firewall", "exit 0\n")

            first = reconcile.reconcile(
                manifest_path=manifest,
                projection_root=projection,
                system_config=system_config,
                firewall_cmd=str(firewall),
                firewall_offline_cmd=str(offline),
            )
            self.assertTrue(first["changed"])
            destination = system_config / target
            self.assertEqual(destination.read_bytes(), b"<zone/>\n")

            second = reconcile.reconcile(
                manifest_path=manifest,
                projection_root=projection,
                system_config=system_config,
                firewall_cmd=str(firewall),
                firewall_offline_cmd=str(offline),
            )
            self.assertFalse(second["changed"])

            manifest.write_text(json.dumps({"schemaVersion": 1, "files": [], "owners": []}), encoding="utf-8")
            third = reconcile.reconcile(
                manifest_path=manifest,
                projection_root=projection,
                system_config=system_config,
                firewall_cmd=str(firewall),
                firewall_offline_cmd=str(offline),
            )
            self.assertTrue(third["changed"])
            self.assertFalse(destination.exists())

    def test_reload_failure_restores_previous_bytes(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            projection, manifest, target = self.projection(root, b"<zone><short>new</short></zone>\n")
            system_config = root / "firewalld"
            destination = system_config / target
            destination.parent.mkdir(parents=True)
            (system_config / "policies").mkdir(parents=True)
            destination.write_bytes(b"<zone><short>old</short></zone>\n")
            offline = self.executable(root / "offline", "exit 0\n")
            firewall = self.executable(root / "firewall", "exit 1\n")

            with self.assertRaisesRegex(reconcile.FirewalldReconcileError, "rollback"):
                reconcile.reconcile(
                    manifest_path=manifest,
                    projection_root=projection,
                    system_config=system_config,
                    firewall_cmd=str(firewall),
                    firewall_offline_cmd=str(offline),
                )
            self.assertEqual(destination.read_bytes(), b"<zone><short>old</short></zone>\n")

    def test_refuses_manifest_outside_v2_namespace(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            projection = root / "projection"
            projection.mkdir()
            manifest = projection / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "files": [{"target": "zones/trusted.xml", "sha256": "0" * 64}],
                        "owners": [],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(reconcile.FirewalldReconcileError, "outside the V2 ownership namespace"):
                reconcile.reconcile(
                    manifest_path=manifest,
                    projection_root=projection,
                    system_config=root / "firewalld",
                    firewall_cmd="false",
                    firewall_offline_cmd="false",
                )


if __name__ == "__main__":
    unittest.main()
