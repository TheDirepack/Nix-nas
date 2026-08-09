from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))

import nas_managed_service as msvc  # noqa: E402
import nas_service_runtime_compose as compose  # noqa: E402


class PodmanComposeAdapterTests(unittest.TestCase):
    def service(
        self,
        *,
        enabled: bool = True,
        source: object | None = None,
        lifecycle: str = "persistent",
    ) -> dict:
        return {
            "label": "Example",
            "enabled": enabled,
            "lifecycle": {"mode": lifecycle},
            "runtime": {
                "type": "compose",
                "source": source or "/var/lib/nas-control/apps/example/compose.yaml",
                "startPolicy": "boot",
            },
        }

    def test_non_compose_is_not_claimed_by_adapter(self):
        plan = compose.plan_compose(
            "example",
            {
                "label": "Example",
                "enabled": True,
                "runtime": {
                    "type": "quadlet",
                    "source": "/var/lib/nas-control/apps/example/app.container",
                },
            },
        )
        self.assertEqual(plan["actions"], [])
        self.assertIn("not a Compose service", plan["warnings"][0])

    def test_source_must_stay_under_service_root(self):
        with self.assertRaisesRegex(msvc.ManagedServiceError, "must be under"):
            compose.plan_compose(
                "example",
                self.service(source="/var/lib/nas-control/apps/other/compose.yaml"),
            )

    def test_source_rejects_traversal_and_non_string_values(self):
        for source in (
            "/var/lib/nas-control/apps/example/../other/compose.yaml",
            42,
        ):
            with self.subTest(source=source), self.assertRaisesRegex(msvc.ManagedServiceError, "must be under"):
                compose.plan_compose("example", self.service(source=source))

    def test_source_rejects_symlink_escape(self):
        with tempfile.TemporaryDirectory() as temporary:
            app_root = pathlib.Path(temporary) / "apps"
            service_root = app_root / "example"
            service_root.mkdir(parents=True)
            outside = pathlib.Path(temporary) / "outside.yaml"
            outside.write_text("services: {}\n", encoding="utf-8")
            source = service_root / "compose.yaml"
            source.symlink_to(outside)
            with (
                mock.patch.object(compose, "APP_ROOT", app_root),
                self.assertRaisesRegex(msvc.ManagedServiceError, "must be under"),
            ):
                compose.plan_compose("example", self.service(source=str(source)))

    def test_source_must_be_yaml(self):
        with self.assertRaisesRegex(msvc.ManagedServiceError, "must be a YAML file"):
            compose.plan_compose(
                "example",
                self.service(source="/var/lib/nas-control/apps/example/compose.txt"),
            )

    def test_plan_uses_stable_project_name(self):
        plan = compose.plan_compose("example", self.service())
        self.assertEqual(plan["runtime"], "podman-compose")
        self.assertEqual(plan["project"], "example")
        self.assertEqual(plan["lifecycle"], "persistent")
        self.assertEqual(plan["actions"][0]["operation"], "up")

    def test_enabled_session_lifecycle_is_rejected(self):
        with self.assertRaisesRegex(msvc.ManagedServiceError, "session lifecycle is not supported for Compose"):
            compose.plan_compose("example", self.service(lifecycle="session"))

    def test_disabled_session_can_be_torn_down_for_cleanup(self):
        plan = compose.plan_compose("example", self.service(enabled=False, lifecycle="session"))
        self.assertEqual(plan["actions"][0]["operation"], "down")

    @mock.patch.object(compose.subprocess, "run")
    def test_apply_enabled_delegates_to_podman_compose(self, run):
        compose.apply_compose("example", self.service())
        run.assert_called_once_with(
            [
                "podman",
                "compose",
                "-p",
                "example",
                "-f",
                "/var/lib/nas-control/apps/example/compose.yaml",
                "up",
                "-d",
            ],
            check=True,
        )

    @mock.patch.object(compose.subprocess, "run")
    def test_apply_disabled_tears_project_down(self, run):
        compose.apply_compose("example", self.service(enabled=False))
        run.assert_called_once_with(
            [
                "podman",
                "compose",
                "-p",
                "example",
                "-f",
                "/var/lib/nas-control/apps/example/compose.yaml",
                "down",
                "--remove-orphans",
            ],
            check=True,
        )

    @mock.patch.object(compose.subprocess, "run")
    def test_dry_run_has_no_side_effects(self, run):
        plan = compose.apply_compose("example", self.service(), dry_run=True)
        self.assertEqual(plan["project"], "example")
        run.assert_not_called()

    @mock.patch.object(compose.subprocess, "run")
    def test_remove_uses_same_project_name_and_allows_session_cleanup(self, run):
        compose.remove_compose("example", self.service(lifecycle="session"))
        run.assert_called_once_with(
            [
                "podman",
                "compose",
                "-p",
                "example",
                "-f",
                "/var/lib/nas-control/apps/example/compose.yaml",
                "down",
                "--remove-orphans",
            ],
            check=True,
        )


if __name__ == "__main__":
    unittest.main()
