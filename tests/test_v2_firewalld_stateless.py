from __future__ import annotations

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
import nas_v2_network as network  # noqa: E402


class V2NativeFirewalldTests(unittest.TestCase):
    def fixture(self, root: pathlib.Path, *, objects: list[dict] | None = None) -> pathlib.Path:
        projection = root / "firewalld"
        projection.mkdir(parents=True)
        if objects is None:
            objects = [
                {"kind": "zone", "name": "nv2z0123456789ab", "interface": "nv20123456789a"},
                {
                    "kind": "policy",
                    "name": "nv2h0123456789ab",
                    "target": "DROP",
                    "priority": -50,
                    "ingress": "nv2z0123456789ab",
                    "egress": "HOST",
                    "ports": [["443", "tcp"]],
                    "forwardPorts": [],
                    "richRules": [{"family": "ipv4", "destination": "10.0.0.0/8", "port": "53", "protocol": "udp"}],
                },
            ]
        manifest = projection / "manifest.json"
        manifest.write_text(json.dumps({"schemaVersion": 2, "objects": objects}), encoding="utf-8")
        return manifest

    def test_native_objects_are_applied_directly_through_permanent_api(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            desired = firewalld._read_projection(self.fixture(pathlib.Path(raw)))
        calls = []

        def permanent(firewall_cmd: str, *args: str):
            calls.append(args)

        with mock.patch.object(firewalld, "_permanent", side_effect=permanent):
            firewalld._apply_zone("firewall-cmd", desired["nv2z0123456789ab"])
            firewalld._apply_policy("firewall-cmd", desired["nv2h0123456789ab"])
        self.assertIn(("--new-zone=nv2z0123456789ab",), calls)
        self.assertIn(("--zone=nv2z0123456789ab", "--add-interface=nv20123456789a"), calls)
        self.assertIn(("--new-policy=nv2h0123456789ab",), calls)
        self.assertIn(("--policy=nv2h0123456789ab", "--set-priority=-50"), calls)
        self.assertIn(("--policy=nv2h0123456789ab", "--add-port=443/tcp"), calls)
        self.assertIn(
            (
                "--policy=nv2h0123456789ab",
                '--add-rich-rule=rule family="ipv4" priority="-10" destination address="10.0.0.0/8" '
                'port port="53" protocol="udp" accept',
            ),
            calls,
        )

    def test_reconcile_orders_zones_before_policies_and_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            manifest = self.fixture(pathlib.Path(raw))
            executed: list[tuple[str, ...]] = []

            def permanent(_cmd: str, *args: str):
                executed.append(args)
                return mock.Mock(returncode=0, stdout="", stderr="")

            with (
                mock.patch.object(firewalld, "_current_owned", return_value=(set(), set())),
                mock.patch.object(firewalld, "_permanent", side_effect=permanent),
                mock.patch.object(firewalld, "_run", return_value=mock.Mock(returncode=0, stdout="")),
                mock.patch.object(firewalld, "_verify_runtime") as verify,
            ):
                result = firewalld.reconcile(manifest_path=manifest)
        self.assertTrue(result["ok"])
        self.assertLess(
            executed.index(("--new-zone=nv2z0123456789ab",)),
            executed.index(("--new-policy=nv2h0123456789ab",)),
        )
        verify.assert_called_once()

    def test_bad_namespace_is_rejected_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            manifest = self.fixture(
                pathlib.Path(raw),
                objects=[
                    {"kind": "zone", "name": "nas-lan", "interface": "nv20123456789a"},
                ],
            )
            with mock.patch.object(firewalld, "_current_owned") as current:
                with self.assertRaisesRegex(firewalld.FirewalldReconcileError, "outside the V2 ownership namespace"):
                    firewalld.reconcile(manifest_path=manifest)
                current.assert_not_called()

    def test_missing_zone_rejected_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            manifest = self.fixture(
                pathlib.Path(raw),
                objects=[
                    {
                        "kind": "policy",
                        "name": "nv2h0123456789ab",
                        "target": "DROP",
                        "priority": -50,
                        "ingress": "nv2zffffffffffff",
                        "egress": "HOST",
                        "ports": [],
                        "forwardPorts": [],
                        "richRules": [],
                    }
                ],
            )
            with mock.patch.object(firewalld, "_current_owned") as current:
                with self.assertRaisesRegex(firewalld.FirewalldReconcileError, "missing zone"):
                    firewalld.reconcile(manifest_path=manifest)
                current.assert_not_called()

    def test_invalid_priority_port_and_rich_rule_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            valid = {
                "kind": "policy",
                "name": "nv2h0123456789ab",
                "target": "DROP",
                "priority": -50,
                "ingress": "HOST",
                "egress": "ANY",
                "ports": [],
                "forwardPorts": [],
                "richRules": [],
            }
            for field, value in (
                ("kind", []),
                ("kind", {}),
                ("target", []),
                ("target", {}),
                ("priority", 0),
                ("ports", [["65536", "tcp"]]),
                ("richRules", [{"family": "ipv4", "destination": "invalid"}]),
                ("ingress", "--evil"),
            ):
                with self.subTest(field=field):
                    manifest = self.fixture(root / field, objects=[{**valid, field: value}])
                    with self.assertRaises(firewalld.FirewalldReconcileError):
                        firewalld._read_projection(manifest)

    def test_native_projection_requires_schema_version_2(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            manifest = self.fixture(pathlib.Path(raw))
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            payload["schemaVersion"] = 1
            manifest.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(firewalld.FirewalldReconcileError, "manifest is invalid"):
                firewalld._read_projection(manifest)

    def test_reconcile_retry_after_mid_apply_failure(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            manifest = self.fixture(pathlib.Path(raw))
            completed = mock.Mock(returncode=0, stdout="", stderr="")
            with (
                mock.patch.object(firewalld, "_current_owned", return_value=(set(), set())),
                mock.patch.object(
                    firewalld,
                    "_permanent",
                    side_effect=[completed, firewalld.FirewalldReconcileError("injected failure")],
                ),
                mock.patch.object(firewalld, "_run") as run,
            ):
                with self.assertRaisesRegex(firewalld.FirewalldReconcileError, "injected failure"):
                    firewalld.reconcile(manifest_path=manifest)
                run.assert_not_called()
            calls: list[tuple[str, ...]] = []

            def permanent(_cmd: str, *args: str):
                calls.append(args)
                return completed

            with (
                mock.patch.object(firewalld, "_current_owned", return_value=({"nv2z0123456789ab"}, set())),
                mock.patch.object(firewalld, "_permanent", side_effect=permanent),
                mock.patch.object(firewalld, "_run", return_value=completed),
                mock.patch.object(firewalld, "_verify_runtime"),
            ):
                result = firewalld.reconcile(manifest_path=manifest)
            self.assertTrue(result["ok"])
            self.assertIn(("--delete-zone=nv2z0123456789ab",), calls)
            self.assertIn(("--new-policy=nv2h0123456789ab",), calls)

    def test_runtime_verification_rejects_missing_objects(self) -> None:
        desired = {"nv2z0123456789ab": {"kind": "zone", "name": "nv2z0123456789ab"}}
        with mock.patch.object(
            firewalld,
            "_run",
            side_effect=[mock.Mock(stdout="running"), mock.Mock(stdout="nas-lan"), mock.Mock(stdout="")],
        ):
            with self.assertRaisesRegex(firewalld.FirewalldReconcileError, "omitted projected objects"):
                firewalld._verify_runtime(desired=desired, firewall_cmd="firewall-cmd")

    def test_projection_to_native_reconciler_contract(self) -> None:
        effective = {
            "services": {
                "worker": {
                    "enabled": True,
                    "managed": True,
                    "runtime": {"type": "oci"},
                    "network": {
                        "mode": "isolated",
                        "outboundDefault": "deny",
                        "lanAccess": False,
                        "allowedHostPorts": [8080],
                        "allowedEgress": [],
                    },
                }
            },
        }
        objects, manifest = network.compile_projection(effective, lan_zone="nas-lan")
        self.assertEqual(
            set(objects),
            {
                f"zones/{network.zone_name('worker')}",
                *[
                    f"policies/{name}"
                    for name in (
                        network.host_policy_name("worker"),
                        network.lan_policy_name("worker"),
                        network.world_policy_name("worker"),
                        network.remote_admin_policy_name(),
                    )
                ],
            },
        )
        with tempfile.TemporaryDirectory() as raw:
            path = pathlib.Path(raw) / "manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            self.assertEqual(set(firewalld._read_projection(path)), {obj["name"] for obj in objects.values()})


if __name__ == "__main__":
    unittest.main()
