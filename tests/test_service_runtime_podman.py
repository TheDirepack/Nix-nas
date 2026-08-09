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
    def service(self, *, enabled: bool = True, source: object | None = None) -> dict:
        return {
            "label": "Example",
            "enabled": enabled,
            "runtime": {
                "type": "quadlet",
                "source": source or "/var/lib/nas-control/apps/example/app.container",
                "startPolicy": "boot",
            },
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

    def test_plan_delegates_installation_to_podman(self):
        plan = podman.plan_podman("example", self.service())
        self.assertEqual(plan["runtime"], "podman-quadlet")
        self.assertEqual(plan["application"], "example")
        self.assertEqual(plan["source"], "/var/lib/nas-control/apps/example/app.container")
        self.assertEqual(plan["unit"], "app.service")
        self.assertEqual(plan["actions"][0]["type"], "podman-quadlet-install")
        self.assertTrue(plan["actions"][0]["replace"])
        self.assertEqual(plan["actions"][1]["operation"], "restart")

    @mock.patch.object(podman.subprocess, "run")
    def test_apply_uses_native_quadlet_install_and_restarts_enabled_unit(self, run):
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
                "/var/lib/nas-control/apps/example/app.container",
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
