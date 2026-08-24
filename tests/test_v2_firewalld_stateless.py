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

import nas_v2_firewalld_reconcile as firewalld  # noqa: E402


class V2StatelessFirewalldTests(unittest.TestCase):
    def executable(self, path: pathlib.Path, body: str) -> pathlib.Path:
        path.write_text("#!/bin/sh\nset -eu\n" + body, encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return path

    def projection(self, root: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path, str]:
        projection = root / "projection"
        target = "zones/nv2z0123456789ab.xml"
        source = projection / target
        source.parent.mkdir(parents=True)
        source.write_bytes(b"<zone><short>new</short></zone>\n")
        manifest = projection / "manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "files": [{"target": target, "sha256": hashlib.sha256(source.read_bytes()).hexdigest()}],
                    "owners": [{"service": "demo", "target": target}],
                }
            ),
            encoding="utf-8",
        )
        return projection, manifest, target

    def test_replaces_complete_owned_namespace_and_verifies_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            projection, manifest, target = self.projection(root)
            system_config = root / "firewalld"
            zones = system_config / "zones"
            policies = system_config / "policies"
            zones.mkdir(parents=True)
            policies.mkdir(parents=True)
            stale = zones / "nv2zffffffffffff.xml"
            stale.write_text("<zone/>\n", encoding="utf-8")
            baseline = zones / "nas-lan.xml"
            baseline.write_text("<zone/>\n", encoding="utf-8")
            log = root / "commands"
            firewall_cmd = self.executable(
                root / "firewall-cmd",
                f'printf "%s\\n" "$*" >> {log}\n'
                'case "$1" in\n'
                "  --state) echo running ;;\n"
                '  --get-zones) echo "nas-lan nv2z0123456789ab" ;;\n'
                '  --get-policies) echo "" ;;\n'
                "esac\n"
                "exit 0\n",
            )

            result = firewalld.reconcile(
                manifest_path=manifest,
                projection_root=projection,
                system_config=system_config,
                firewall_cmd=str(firewall_cmd),
            )

            self.assertTrue(result["changed"])
            self.assertTrue(result["runtimeVerified"])
            self.assertFalse(stale.exists())
            self.assertTrue(baseline.exists(), "non-V2 baseline must not be removed")
            self.assertEqual((system_config / target).read_bytes(), b"<zone><short>new</short></zone>\n")
            commands = log.read_text(encoding="utf-8")
            self.assertIn("--check-config", commands)
            self.assertIn("--reload", commands)
            self.assertIn("--state", commands)
            self.assertIn("--get-zones", commands)

    def test_runtime_verification_fails_closed_when_object_missing(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            projection, manifest, _target = self.projection(root)
            system_config = root / "firewalld"
            (system_config / "zones").mkdir(parents=True)
            (system_config / "policies").mkdir(parents=True)
            firewall_cmd = self.executable(
                root / "firewall-cmd",
                'case "$1" in\n'
                "  --state) echo running ;;\n"
                '  --get-zones) echo "nas-lan" ;;\n'
                '  --get-policies) echo "" ;;\n'
                "esac\n"
                "exit 0\n",
            )
            with self.assertRaisesRegex(firewalld.FirewalldReconcileError, "omitted projected objects"):
                firewalld.reconcile(
                    manifest_path=manifest,
                    projection_root=projection,
                    system_config=system_config,
                    firewall_cmd=str(firewall_cmd),
                )

    def test_rejects_projection_outside_owned_namespace(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            projection = root / "projection"
            projection.mkdir()
            manifest = projection / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "files": [{"target": "zones/nas-lan.xml", "sha256": "0" * 64}],
                        "owners": [],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(firewalld.FirewalldReconcileError, "outside the V2 ownership namespace"):
                firewalld.reconcile(
                    manifest_path=manifest,
                    projection_root=projection,
                    system_config=root / "firewalld",
                    firewall_cmd="false",
                )


if __name__ == "__main__":
    unittest.main()
