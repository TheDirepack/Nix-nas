from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))

import nas_managed_service as msvc  # noqa: E402
import nas_service_runtime_podman as podman  # noqa: E402


class PodmanQuadletAdapterTests(unittest.TestCase):
    def service(
        self,
        *,
        enabled: bool = True,
        source: object | None = None,
        resolved_storage: list[dict] | None = None,
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

    def test_non_quadlet_is_not_claimed_by_adapter(self):
        plan = podman.plan_podman(
            "example",
            {
                "label": "Example",
                "enabled": True,
                "runtime": {
                    "type": "compose",
                    "source": "/var/lib/nas-control/apps/example/compose.yaml",
                },
            },
        )
        self.assertEqual(plan["actions"], [])
        self.assertIn("not a Quadlet service", plan["warnings"][0])

    def test_source_must_stay_under_service_root(self):
        with self.assertRaisesRegex(msvc.ManagedServiceError, "must be under"):
            podman.plan_podman(
                "example",
                self.service(source="/var/lib/nas-control/apps/other/app.container"),
            )

    def test_source_rejects_traversal_and_non_string_values(self):
        for source in (
            "/var/lib/nas-control/apps/example/../other/app.container",
            42,
        ):
            with self.subTest(source=source), self.assertRaisesRegex(msvc.ManagedServiceError, "must be under"):
                podman.plan_podman("example", self.service(source=source))

    def test_source_rejects_symlink_escape(self):
        with tempfile.TemporaryDirectory() as temporary:
            app_root = pathlib.Path(temporary) / "apps"
            service_root = app_root / "example"
            service_root.mkdir(parents=True)
            outside = pathlib.Path(temporary) / "outside.container"
            outside.write_text("[Container]\nImage=example.invalid/test\n", encoding="utf-8")
            source = service_root / "app.container"
            source.symlink_to(outside)
            with (
                mock.patch.object(podman, "APP_ROOT", app_root),
                self.assertRaisesRegex(msvc.ManagedServiceError, "must be under"),
            ):
                podman.plan_podman("example", self.service(source=str(source)))

    def test_source_must_be_native_container_quadlet(self):
        with self.assertRaisesRegex(msvc.ManagedServiceError, "native .container"):
            podman.plan_podman(
                "example",
                self.service(source="/var/lib/nas-control/apps/example/compose.yaml"),
            )

    def test_plan_delegates_application_directory_installation_to_podman(self):
        plan = podman.plan_podman("example", self.service())
        self.assertEqual(plan["runtime"], "podman-quadlet")
        self.assertEqual(plan["application"], "example")
        self.assertEqual(plan["source"], "/var/lib/nas-control/apps/example/app.container")
        self.assertEqual(plan["applicationSource"], "/var/lib/nas-control/apps/example")
        self.assertEqual(plan["unit"], "app.service")
        self.assertEqual(plan["actions"][0]["type"], "podman-quadlet-install")
        self.assertEqual(plan["actions"][0]["source"], "/var/lib/nas-control/apps/example")
        self.assertTrue(plan["actions"][0]["replace"])
        self.assertEqual(plan["actions"][1]["operation"], "restart")

    def test_storage_dropin_uses_native_quadlet_volume_keys(self):
        rendered = podman.render_storage_dropin(self.service(resolved_storage=[self.v2_mount()]))
        self.assertIn("[Container]", rendered)
        self.assertIn("Volume=/tank/projects:/workspace:rw", rendered)
        self.assertTrue(rendered.startswith(podman.GENERATED_MARKER))

    def test_storage_dropin_rejects_unsafe_volume_delimiter(self):
        mount = self.v2_mount()
        mount["hostPath"] = "/tank/bad:path"
        with self.assertRaisesRegex(msvc.ManagedServiceError, "unsafe Quadlet delimiter"):
            podman.render_storage_dropin(self.service(resolved_storage=[mount]))

    def test_generated_dropin_refuses_to_overwrite_user_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            app_root = pathlib.Path(temporary) / "apps"
            service_root = app_root / "example"
            service_root.mkdir(parents=True)
            source = service_root / "app.container"
            source.write_text("[Container]\nImage=example.invalid/test\n", encoding="utf-8")
            dropin = source.parent / f"{source.name}.d" / podman.GENERATED_DROPIN
            dropin.parent.mkdir()
            dropin.write_text("[Container]\nVolume=/unsafe:/data\n", encoding="utf-8")
            with (
                mock.patch.object(podman, "APP_ROOT", app_root),
                self.assertRaisesRegex(msvc.ManagedServiceError, "Refusing to overwrite"),
            ):
                podman._write_generated_dropin(source, self.service(source=str(source), resolved_storage=[self.v2_mount()]))

    @mock.patch.object(podman.subprocess, "run")
    def test_apply_uses_native_quadlet_application_install_and_restarts_enabled_unit(self, run):
        run.side_effect = [
            mock.Mock(),
            mock.Mock(stdout='[{"Name":"app.container","UnitName":"app.service","App":"example"}]'),
            mock.Mock(),
        ]
        podman.apply_podman("example", self.service())
        self.assertEqual(run.call_count, 3)
        run.assert_any_call(
            [
                "podman",
                "quadlet",
                "install",
                "--replace",
                "--application=example",
                "/var/lib/nas-control/apps/example",
            ],
            check=True,
        )
        run.assert_any_call(
            [
                "podman",
                "quadlet",
                "list",
                "--filter",
                "name=app.container",
                "--format",
                "json",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        run.assert_any_call(["systemctl", "restart", "app.service"], check=True)

    @mock.patch.object(podman.subprocess, "run")
    def test_apply_uses_native_unit_name_reported_by_quadlet(self, run):
        run.side_effect = [
            mock.Mock(),
            mock.Mock(
                stdout=(
                    '[{"Name":"app.container","UnitName":"other.service","App":"other"},'
                    '{"Name":"app.container","UnitName":"custom-example.service","App":"example"}]'
                )
            ),
            mock.Mock(),
        ]
        plan = podman.apply_podman("example", self.service())
        self.assertEqual(plan["unit"], "custom-example.service")
        run.assert_any_call(["systemctl", "restart", "custom-example.service"], check=True)

    @mock.patch.object(podman.subprocess, "run")
    def test_apply_stops_disabled_unit(self, run):
        run.side_effect = [
            mock.Mock(),
            mock.Mock(stdout='[{"Name":"app.container","UnitName":"app.service","App":"example"}]'),
            mock.Mock(),
        ]
        podman.apply_podman("example", self.service(enabled=False))
        run.assert_any_call(["systemctl", "stop", "app.service"], check=True)

    @mock.patch.object(podman.subprocess, "run")
    def test_dry_run_has_no_side_effects(self, run):
        plan = podman.apply_podman("example", self.service(), dry_run=True)
        self.assertEqual(plan["unit"], "app.service")
        run.assert_not_called()

    @mock.patch.object(podman.subprocess, "run")
    def test_remove_delegates_application_cleanup_to_podman(self, run):
        podman.remove_podman("example")
        run.assert_called_once_with(
            [
                "podman",
                "quadlet",
                "rm",
                "--force",
                "--ignore",
                "--recursive",
                "example",
            ],
            check=True,
        )


if __name__ == "__main__":
    unittest.main()
