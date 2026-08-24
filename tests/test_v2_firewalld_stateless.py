from __future__ import annotations

import hashlib
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_firewalld_reconcile as firewalld  # noqa: E402


class V2StatelessFirewalldTests(unittest.TestCase):
    def projection(
        self, root: pathlib.Path, *, files: dict[str, bytes] | None = None
    ) -> tuple[pathlib.Path, pathlib.Path]:
        projection = root / "projection"
        payloads = files or {"zones/nv2z0123456789ab.xml": b"<zone><interface name='nv2bridge'/></zone>\n"}
        entries = []
        for target, payload in payloads.items():
            source = projection / target
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_bytes(payload)
            entries.append({"target": target, "sha256": hashlib.sha256(payload).hexdigest()})
        manifest = projection / "manifest.json"
        manifest.write_text(
            json.dumps({"schemaVersion": 1, "files": entries, "owners": []}),
            encoding="utf-8",
        )
        return projection, manifest

    def test_zone_ir_is_applied_through_permanent_firewalld_api(self) -> None:
        payload = b"""<zone target="DROP">
  <interface name="nv2bridge"/>
  <service name="https"/>
  <port port="8443" protocol="tcp"/>
</zone>
"""
        with mock.patch.object(firewalld, "_permanent") as permanent:
            firewalld._apply_zone("firewall-cmd", "nv2z0123456789ab", payload)
        commands = [call.args[1:] for call in permanent.call_args_list]
        self.assertIn(("--new-zone=nv2z0123456789ab",), commands)
        self.assertIn(("--zone=nv2z0123456789ab", "--set-target=DROP"), commands)
        self.assertIn(("--zone=nv2z0123456789ab", "--add-interface=nv2bridge"), commands)
        self.assertIn(("--zone=nv2z0123456789ab", "--add-service=https"), commands)
        self.assertIn(("--zone=nv2z0123456789ab", "--add-port=8443/tcp"), commands)

    def test_policy_ir_is_applied_through_permanent_firewalld_api(self) -> None:
        payload = b"""<policy target="DROP" priority="-50">
  <ingress-zone name="nv2z0123456789ab"/>
  <egress-zone name="HOST"/>
  <port port="443" protocol="tcp"/>
  <forward-port port="8443" protocol="tcp" to-port="443"/>
  <rule family="ipv4" priority="-10">
    <destination address="10.0.0.0/8"/>
    <port port="53" protocol="udp"/>
    <accept/>
  </rule>
</policy>
"""
        with mock.patch.object(firewalld, "_permanent") as permanent:
            firewalld._apply_policy("firewall-cmd", "nv2h0123456789ab", payload)
        commands = [call.args[1:] for call in permanent.call_args_list]
        self.assertIn(("--new-policy=nv2h0123456789ab",), commands)
        self.assertIn(("--policy=nv2h0123456789ab", "--set-target=DROP"), commands)
        self.assertIn(("--policy=nv2h0123456789ab", "--set-priority=-50"), commands)
        self.assertIn(("--policy=nv2h0123456789ab", "--add-ingress-zone=nv2z0123456789ab"), commands)
        self.assertIn(("--policy=nv2h0123456789ab", "--add-egress-zone=HOST"), commands)
        self.assertIn(("--policy=nv2h0123456789ab", "--add-port=443/tcp"), commands)
        self.assertIn(
            ("--policy=nv2h0123456789ab", "--add-forward-port=port=8443:proto=tcp:toport=443"),
            commands,
        )
        rich = next(
            command[1]
            for command in commands
            if len(command) > 1 and command[1].startswith("--add-rich-rule=")
        )
        self.assertIn('family="ipv4"', rich)
        self.assertIn('destination address="10.0.0.0/8"', rich)
        self.assertIn('port="53" protocol="udp"', rich)
        self.assertTrue(rich.endswith(" accept"))

    def test_reconcile_replaces_only_v2_native_namespace(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            projection, manifest = self.projection(
                root,
                files={
                    "zones/nv2z0123456789ab.xml": b"<zone/>\n",
                    "policies/nv2h0123456789ab.xml": b"<policy target='DROP' priority='0'/>\n",
                },
            )
            completed = mock.Mock(returncode=0, stdout="", stderr="")
            with (
                mock.patch.object(
                    firewalld,
                    "_current_owned",
                    return_value=({"nv2zffffffffffff"}, {"nv2hffffffffffff"}),
                ),
                mock.patch.object(firewalld, "_permanent", return_value=completed) as permanent,
                mock.patch.object(firewalld, "_apply_zone") as apply_zone,
                mock.patch.object(firewalld, "_apply_policy") as apply_policy,
                mock.patch.object(firewalld, "_run", return_value=completed) as run,
                mock.patch.object(firewalld, "_verify_runtime") as verify,
            ):
                result = firewalld.reconcile(
                    manifest_path=manifest,
                    projection_root=projection,
                    firewall_cmd="firewall-cmd",
                )

            self.assertTrue(result["nativePermanentApi"])
            permanent.assert_any_call("firewall-cmd", "--delete-policy=nv2hffffffffffff")
            permanent.assert_any_call("firewall-cmd", "--delete-zone=nv2zffffffffffff")
            apply_zone.assert_called_once()
            apply_policy.assert_called_once()
            run.assert_any_call(["firewall-cmd", "--check-config"])
            run.assert_any_call(["firewall-cmd", "--reload"])
            verify.assert_called_once()

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
                    firewall_cmd="false",
                )

    def test_runtime_verification_fails_closed_when_object_missing(self) -> None:
        desired = {pathlib.PurePosixPath("zones/nv2z0123456789ab.xml"): b"<zone/>"}
        running = mock.Mock(returncode=0, stdout="running\n", stderr="")
        zones = mock.Mock(returncode=0, stdout="nas-lan\n", stderr="")
        policies = mock.Mock(returncode=0, stdout="\n", stderr="")
        with mock.patch.object(firewalld, "_run", side_effect=[running, zones, policies]):
            with self.assertRaisesRegex(firewalld.FirewalldReconcileError, "omitted projected objects"):
                firewalld._verify_runtime(desired=desired, firewall_cmd="firewall-cmd")


if __name__ == "__main__":
    unittest.main()