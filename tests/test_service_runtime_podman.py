from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))

import nas_managed_network as managed_network  # noqa: E402
import nas_managed_service as msvc  # noqa: E402
import nas_service_runtime_podman as podman  # noqa: E402


class PodmanQuadletAdapterTests(unittest.TestCase):
    def service(
        self,
        *,
        enabled: bool = True,
        source: object | None = None,
        resolved_storage: list[dict] | None = None,
        resolved_network: dict | None = None,
    ) -> dict:
        result = {
            "label": "Example",
            "enabled": enabled,
            "runtime": {
                "type": "quadlet",
                "source": source or "/var/lib/nas-control/apps/example/app.container",
                "startPolicy": "boot",
            },
        }
        if resolved_storage is not None:
            result["resolvedStorage"] = resolved_storage
        if resolved_network is not None:
            result["resolvedNetwork"] = resolved_network
        return result

    def v2_mount(self, *, mode: str = "rw") -> dict:
        return {
            "resource": "projects",
            "hostPath": "/tank/projects",
            "guestPath": "/workspace",
            "mode": mode,
            "requiredCapabilities": ["read", "write"] if mode == "rw" else ["read"],
            "stateClass": "authoritative",
            "scope": "system",
        }

    def v2_network(self) -> dict:
        return {
            "outboundDefault": "allow",
            "lanAccess": False,
            "allowedEgress": [],
            "allowedHostPorts": [9292],
            "identity": managed_network.service_network("example"),
        }

    def test_non_quadlet_is_not_claimed_by_adapter(self):
        plan = podman.plan_podman(
            "example",
            {"label": "Example", "enabled": True, "runtime": {"type": "compose", "source": "/var/lib/nas-control/apps/example/compose.yaml"}},
        )
        self.assertEqual(plan["actions"], [])

    def test_source_must_stay_under_service_root(self):
        with self.assertRaisesRegex(msvc.ManagedServiceError, "must be under"):
            podman.plan_podman("example", self.service(source="/var/lib/nas-control/apps/other/app.container"))

    def test_source_rejects_symlink_escape(self):
        with tempfile.TemporaryDirectory() as temporary:
            app_root = pathlib.Path(temporary) / "apps"
            service_root = app_root / "example"
            service_root.mkdir(parents=True)
            outside = pathlib.Path(temporary) / "outside.container"
            outside.write_text("[Container]\nImage=example.invalid/test\n", encoding="utf-8")
            source = service_root / "app.container"
            source.symlink_to(outside)
            with mock.patch.object(podman, "APP_ROOT", app_root), self.assertRaisesRegex(msvc.ManagedServiceError, "must be under"):
                podman.plan_podman("example", self.service(source=str(source)))

    def test_source_must_be_native_container_quadlet(self):
        with self.assertRaisesRegex(msvc.ManagedServiceError, "native .container"):
            podman.plan_podman("example", self.service(source="/var/lib/nas-control/apps/example/compose.yaml"))

    def test_policy_dropin_uses_native_volume_and_network_keys(self):
        service = self.service(resolved_storage=[self.v2_mount()], resolved_network=self.v2_network())
        rendered = podman.render_policy_dropin("example", service)
        self.assertIn("Volume=/tank/projects:/workspace:rw", rendered)
        self.assertIn(f"Network={managed_network.service_network('example')['quadlet']}", rendered)
        self.assertTrue(rendered.startswith(podman.GENERATED_MARKER))

    def test_resolved_network_identity_must_match_service(self):
        wrong = self.v2_network()
        wrong["identity"] = managed_network.service_network("other")
        with self.assertRaisesRegex(msvc.ManagedServiceError, "identity is invalid"):
            podman.plan_podman("example", self.service(resolved_network=wrong))

    def test_generated_policy_refuses_to_overwrite_user_dropin(self):
        with tempfile.TemporaryDirectory() as temporary:
            app_root = pathlib.Path(temporary) / "apps"
            service_root = app_root / "example"
            service_root.mkdir(parents=True)
            source = service_root / "app.container"
            source.write_text("[Container]\nImage=example.invalid/test\n", encoding="utf-8")
            dropin = source.parent / f"{source.name}.d" / podman.GENERATED_DROPIN
            dropin.parent.mkdir()
            dropin.write_text("[Container]\nVolume=/unsafe:/data\n", encoding="utf-8")
            with mock.patch.object(podman, "APP_ROOT", app_root), self.assertRaisesRegex(msvc.ManagedServiceError, "Refusing to overwrite"):
                podman._write_generated_policy(source, "example", self.service(source=str(source), resolved_storage=[self.v2_mount()]))

    def test_generated_network_is_written_inside_application_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            app_root = pathlib.Path(temporary) / "apps"
            service_root = app_root / "example"
            service_root.mkdir(parents=True)
            source = service_root / "app.container"
            source.write_text("[Container]\nImage=example.invalid/test\n", encoding="utf-8")
            service = self.service(source=str(source), resolved_network=self.v2_network())
            with mock.patch.object(podman, "APP_ROOT", app_root):
                _dropin, network_path = podman._write_generated_policy(source, "example", service)
            self.assertIsNotNone(network_path)
            assert network_path is not None
            self.assertTrue(network_path.is_file())
            self.assertIn("[Network]", network_path.read_text(encoding="utf-8"))

    @mock.patch.object(podman.subprocess, "run")
    def test_apply_uses_native_quadlet_application_install(self, run):
        run.side_effect = [
            mock.Mock(),
            mock.Mock(stdout='[{"Name":"app.container","UnitName":"app.service","App":"example"}]'),
            mock.Mock(),
        ]
        podman.apply_podman("example", self.service())
        run.assert_any_call(
            ["podman", "quadlet", "install", "--replace", "--application=example", "/var/lib/nas-control/apps/example"],
            check=True,
        )
        run.assert_any_call(["systemctl", "restart", "app.service"], check=True)

    @mock.patch.object(podman.subprocess, "run")
    def test_apply_stops_disabled_unit(self, run):
        run.side_effect = [mock.Mock(), mock.Mock(stdout='[{"Name":"app.container","UnitName":"app.service","App":"example"}]'), mock.Mock()]
        podman.apply_podman("example", self.service(enabled=False))
        run.assert_any_call(["systemctl", "stop", "app.service"], check=True)

    @mock.patch.object(podman.subprocess, "run")
    def test_dry_run_has_no_side_effects(self, run):
        plan = podman.apply_podman("example", self.service(), dry_run=True)
        self.assertEqual(plan["unit"], "app.service")
        run.assert_not_called()

    @mock.patch.object(podman.subprocess, "run")
    def test_remove_delegates_application_cleanup_to_podman(self, run):
        with mock.patch.object(podman, "_remove_generated_sources") as cleanup:
            podman.remove_podman("example")
        run.assert_called_once_with(
            ["podman", "quadlet", "rm", "--force", "--ignore", "--recursive", "example"],
            check=True,
        )
        cleanup.assert_called_once_with("example")


if __name__ == "__main__":
    unittest.main()
