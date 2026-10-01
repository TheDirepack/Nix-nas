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
            command[1] for command in commands if len(command) > 1 and command[1].startswith("--add-rich-rule=")
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
                    "policies/nv2h0123456789ab.xml": b"<policy target='DROP' priority='-50'/>\n",
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

    def _dependency_aware_permanent(self, calls: list[tuple[str, ...]] | None = None, *, fail_after: int | None = None):
        created_zones: set[str] = set()
        created_policies: set[str] = set()
        order: list[str] = []
        counter = {"n": 0}
        if calls is None:
            calls = []

        def fake(firewall_cmd: str, *args: str, check: bool = True):
            assert firewall_cmd == "firewall-cmd"
            counter["n"] += 1
            if fail_after is not None and counter["n"] > fail_after:
                raise firewalld.FirewalldReconcileError("injected mid-apply failure")
            calls.append(args)
            if len(args) == 1 and args[0].startswith("--new-zone="):
                name = args[0].removeprefix("--new-zone=")
                created_zones.add(name)
                order.append(f"zone:{name}")
            elif len(args) == 1 and args[0].startswith("--new-policy="):
                name = args[0].removeprefix("--new-policy=")
                created_policies.add(name)
                order.append(f"policy:{name}")
            elif len(args) == 2 and args[1].startswith("--add-ingress-zone="):
                zone = args[1].removeprefix("--add-ingress-zone=")
                if zone.startswith("nv2z") and zone not in created_zones:
                    raise firewalld.FirewalldReconcileError(
                        f"INVALID_ZONE: policy {args[0]} references missing zone {zone}"
                    )
            elif len(args) == 2 and args[1].startswith("--add-egress-zone="):
                zone = args[1].removeprefix("--add-egress-zone=")
                if zone.startswith("nv2z") and zone not in created_zones:
                    raise firewalld.FirewalldReconcileError(
                        f"INVALID_ZONE: policy {args[0]} references missing zone {zone}"
                    )
            return mock.Mock(returncode=0, stdout="", stderr="")

        fake.created_zones = created_zones  # type: ignore[attr-defined]
        fake.created_policies = created_policies  # type: ignore[attr-defined]
        fake.order = order  # type: ignore[attr-defined]
        return fake

    def test_reconcile_creates_zones_before_dependent_policies(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            projection, manifest = self.projection(
                root,
                files={
                    "zones/nv2z0123456789ab.xml": b"<zone><interface name='nv2bridge'/></zone>\n",
                    "policies/nv2h0123456789ab.xml": (
                        b"<policy target='DROP' priority='-50'>"
                        b"<ingress-zone name='nv2z0123456789ab'/>"
                        b"<egress-zone name='HOST'/>"
                        b"</policy>\n"
                    ),
                },
            )
            completed = mock.Mock(returncode=0, stdout="", stderr="")
            calls: list[tuple[str, ...]] = []
            fake = self._dependency_aware_permanent(calls)
            with (
                mock.patch.object(firewalld, "_current_owned", return_value=(set(), set())),
                mock.patch.object(firewalld, "_permanent", side_effect=fake),
                mock.patch.object(firewalld, "_run", return_value=completed),
                mock.patch.object(firewalld, "_verify_runtime") as verify,
            ):
                result = firewalld.reconcile(
                    manifest_path=manifest,
                    projection_root=projection,
                    firewall_cmd="firewall-cmd",
                )
            self.assertTrue(result["ok"])
            self.assertEqual(fake.order[:2], ["zone:nv2z0123456789ab", "policy:nv2h0123456789ab"])
            verify.assert_called_once()

    def test_reconcile_rejects_policy_referencing_missing_zone_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            projection, manifest = self.projection(
                root,
                files={
                    "policies/nv2h0123456789ab.xml": (
                        b"<policy target='DROP' priority='-50'>"
                        b"<ingress-zone name='nv2zffffffffffff'/>"
                        b"<egress-zone name='HOST'/>"
                        b"</policy>\n"
                    ),
                },
            )
            calls: list[tuple[str, ...]] = []
            fake = self._dependency_aware_permanent(calls)
            with (
                mock.patch.object(firewalld, "_current_owned", return_value=(set(), set())),
                mock.patch.object(firewalld, "_permanent", side_effect=fake),
                mock.patch.object(firewalld, "_run") as run,
            ):
                with self.assertRaisesRegex(firewalld.FirewalldReconcileError, "missing zone|INVALID_ZONE"):
                    firewalld.reconcile(
                        manifest_path=manifest,
                        projection_root=projection,
                        firewall_cmd="firewall-cmd",
                    )
            self.assertEqual(calls, [])
            run.assert_not_called()

    def test_reconcile_retry_converges_after_mid_apply_failure(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            files = {
                "zones/nv2z0123456789ab.xml": b"<zone><interface name='nv2bridge'/></zone>\n",
                "policies/nv2h0123456789ab.xml": (
                    b"<policy target='DROP' priority='-50'>"
                    b"<ingress-zone name='nv2z0123456789ab'/>"
                    b"<egress-zone name='HOST'/>"
                    b"</policy>\n"
                ),
            }
            projection, manifest = self.projection(root, files=files)
            completed = mock.Mock(returncode=0, stdout="", stderr="")
            failing_calls: list[tuple[str, ...]] = []
            failing = self._dependency_aware_permanent(failing_calls, fail_after=1)
            with (
                mock.patch.object(firewalld, "_current_owned", return_value=(set(), set())),
                mock.patch.object(firewalld, "_permanent", side_effect=failing),
                mock.patch.object(firewalld, "_run", return_value=completed) as run,
                mock.patch.object(firewalld, "_verify_runtime") as verify,
            ):
                with self.assertRaisesRegex(firewalld.FirewalldReconcileError, "injected mid-apply failure"):
                    firewalld.reconcile(
                        manifest_path=manifest,
                        projection_root=projection,
                        firewall_cmd="firewall-cmd",
                    )
            run.assert_not_called()
            verify.assert_not_called()
            retry_calls: list[tuple[str, ...]] = []
            retry = self._dependency_aware_permanent(retry_calls)
            with (
                mock.patch.object(
                    firewalld, "_current_owned", return_value=(failing.created_zones, failing.created_policies)
                ),
                mock.patch.object(firewalld, "_permanent", side_effect=retry),
                mock.patch.object(firewalld, "_run", return_value=completed) as retry_run,
                mock.patch.object(firewalld, "_verify_runtime") as retry_verify,
            ):
                result = firewalld.reconcile(
                    manifest_path=manifest,
                    projection_root=projection,
                    firewall_cmd="firewall-cmd",
                )
            self.assertTrue(result["ok"])
            self.assertEqual(retry.order[:2], ["zone:nv2z0123456789ab", "policy:nv2h0123456789ab"])
            for args in retry_calls:
                for token in args:
                    self.assertNotIn("ACCEPT", token)
            retry_run.assert_any_call(["firewall-cmd", "--check-config"])
            retry_run.assert_any_call(["firewall-cmd", "--reload"])
            retry_verify.assert_called_once()


if __name__ == "__main__":
    unittest.main()
