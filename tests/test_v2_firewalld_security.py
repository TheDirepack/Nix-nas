from __future__ import annotations

import hashlib
import json
import pathlib
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET


ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
sys.path.insert(0, str(SERVICES))

import nas_v2_firewalld_reconcile as firewall  # noqa: E402


class FirewalldSecurityTests(unittest.TestCase):
    def test_rich_rule_rejects_language_injection(self) -> None:
        rule = ET.Element("rule", {"family": "ipv4"})
        ET.SubElement(rule, "destination", {"address": '10.0.0.0/8" port port="22'})
        ET.SubElement(rule, "accept")
        with self.assertRaises(firewall.FirewalldReconcileError):
            firewall._rich_rule(rule)

    def test_rich_rule_rejects_family_mismatch(self) -> None:
        rule = ET.fromstring(
            '<rule family="ipv4"><destination address="2001:db8::/32"/><accept/></rule>'
        )
        with self.assertRaisesRegex(firewall.FirewalldReconcileError, "does not match"):
            firewall._rich_rule(rule)

    def test_rich_rule_rejects_invalid_protocol_and_priority(self) -> None:
        invalid_protocol = ET.fromstring(
            '<rule family="ipv4"><port port="443" protocol="tcp accept"/><accept/></rule>'
        )
        with self.assertRaisesRegex(firewall.FirewalldReconcileError, "invalid protocol"):
            firewall._rich_rule(invalid_protocol)
        invalid_priority = ET.fromstring('<rule family="ipv4" priority="0 accept"><accept/></rule>')
        with self.assertRaisesRegex(firewall.FirewalldReconcileError, "invalid priority"):
            firewall._rich_rule(invalid_priority)

    def test_valid_rich_rule_is_canonical(self) -> None:
        rule = ET.fromstring(
            '<rule family="ipv4" priority="10"><destination address="10.0.0.0/8"/>'
            '<port port="443" protocol="tcp"/><accept/></rule>'
        )
        self.assertEqual(
            firewall._rich_rule(rule),
            'rule family="ipv4" priority="10" destination address="10.0.0.0/8" port port="443" protocol="tcp" accept',
        )

    def test_projection_rejects_symlink_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            projection = root / "projection"
            zones = projection / "zones"
            zones.mkdir(parents=True)
            outside = root / "outside.xml"
            payload = b'<zone target="DROP"/>\n'
            outside.write_bytes(payload)
            name = "nv2z0123456789ab.xml"
            (zones / name).symlink_to(outside)
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "files": [
                            {
                                "target": f"zones/{name}",
                                "sha256": hashlib.sha256(payload).hexdigest(),
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(firewall.FirewalldReconcileError, "regular non-symlink"):
                firewall._read_projection(manifest, projection)


if __name__ == "__main__":
    unittest.main()
