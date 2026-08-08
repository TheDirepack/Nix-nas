from __future__ import annotations

import pathlib
import sys
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))

import nas_managed_service as msvc
import nas_service_runtime_podman as podman


class PodmanQuadletAdapterTests(unittest.TestCase):
    def service(self, *, enabled: bool = True, source: str | None = None) -> dict:
        return {
            "label": "Example",
            "enabled": enabled,
            "runtime": {
                "type": "quadlet",
                "source": source
                or "/var/lib/nas-control/apps/example/app.container",
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
        podman.apply_podman("example", self.service())
        self.assertEqual(run.call_count, 2)
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
        run.assert_any_call(["systemctl", "restart", "app.service"], check=True)

    @mock.patch.object(podman.subprocess, "run")
    def test_apply_stops_disabled_unit(self, run):
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
