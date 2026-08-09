from __future__ import annotations

import unittest

from services.nas_managed_resources import (
    ManagedResourceError,
    application_capability,
    application_principal,
    backup_resource_ids,
    capability_group_name,
    storage_capability,
    validate_application_principal,
    validate_capability_reference,
    validate_storage_attachment,
    validate_storage_resources,
)


class ManagedResourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.resources = validate_storage_resources(
            {
                "projects": {
                    "path": "/tank/projects",
                    "stateClass": "authoritative",
                    "capabilities": ["read", "write", "move", "delete"],
                    "backup": {"enabled": True, "consistency": "zfs-snapshot"},
                },
                "pi-home": {
                    "path": "/tank/apps/pi/users",
                    "scope": "user",
                    "pathTemplate": "/tank/apps/pi/users/{user}",
                    "stateClass": "authoritative",
                    "capabilities": ["read", "write", "delete"],
                    "backup": {"enabled": True},
                },
                "model-cache": {
                    "path": "/tank/cache/models",
                    "stateClass": "cache",
                    "capabilities": ["read", "write"],
                    "backup": {"enabled": False, "consistency": "none"},
                },
            }
        )

    def test_application_principal_is_stable_and_runtime_independent(self) -> None:
        self.assertEqual(application_principal("pi"), "application:pi")
        self.assertEqual(validate_application_principal("application:pi", service_id="pi"), "application:pi")
        with self.assertRaises(ManagedResourceError):
            validate_application_principal("application:jellyfin", service_id="pi")

    def test_capability_names_are_stable_references_for_authentik(self) -> None:
        self.assertEqual(application_capability("pi"), "application.pi.access")
        self.assertEqual(storage_capability("projects", "write"), "storage.projects.write")
        self.assertEqual(validate_capability_reference("storage.projects.read"), "storage.projects.read")
        self.assertEqual(capability_group_name("storage.media-library.read"), "nas_storage_media_library_read")
        self.assertEqual(capability_group_name("application.pi.access"), "nas_application_pi_access")
        with self.assertRaises(ManagedResourceError):
            validate_capability_reference("alice:projects:rw")

    def test_user_scoped_resources_require_user_template(self) -> None:
        with self.assertRaises(ManagedResourceError):
            validate_storage_resources(
                {
                    "broken": {
                        "path": "/tank/apps/broken/users",
                        "scope": "user",
                        "stateClass": "authoritative",
                        "capabilities": ["read", "write"],
                        "backup": {"enabled": True},
                    }
                }
            )
        with self.assertRaises(ManagedResourceError):
            validate_storage_resources(
                {
                    "broken": {
                        "path": "/tank/apps/broken/users",
                        "scope": "user",
                        "pathTemplate": "/tank/apps/broken/users/static",
                        "stateClass": "authoritative",
                        "capabilities": ["read", "write"],
                        "backup": {"enabled": True},
                    }
                }
            )

    def test_cache_and_ephemeral_state_cannot_be_marked_for_backup(self) -> None:
        for state_class in ("cache", "ephemeral"):
            with self.subTest(state_class=state_class), self.assertRaises(ManagedResourceError):
                validate_storage_resources(
                    {
                        "bad": {
                            "path": "/tank/bad",
                            "stateClass": state_class,
                            "capabilities": ["read"],
                            "backup": {"enabled": True},
                        }
                    }
                )

    def test_attachment_references_existing_resource_and_exposed_capabilities(self) -> None:
        attachment = validate_storage_attachment(
            "pi",
            {
                "resource": "projects",
                "guestPath": "/workspace",
                "target": "web",
                "requiredCapabilities": ["read", "write"],
            },
            self.resources,
        )
        self.assertEqual(attachment["resource"], "projects")
        self.assertEqual(attachment["requiredCapabilities"], ["read", "write"])
        self.assertEqual(attachment["target"], "web")
        with self.assertRaises(ManagedResourceError):
            validate_storage_attachment(
                "pi",
                {"resource": "missing", "guestPath": "/workspace"},
                self.resources,
            )
        with self.assertRaises(ManagedResourceError):
            validate_storage_attachment(
                "pi",
                {
                    "resource": "projects",
                    "guestPath": "/workspace",
                    "requiredCapabilities": ["admin"],
                },
                self.resources,
            )

    def test_runtime_target_is_strict_metadata(self) -> None:
        for bad in ("", "web/service", "../../escape", "web:bad", "x" * 65):
            with self.subTest(target=bad), self.assertRaises(ManagedResourceError):
                validate_storage_attachment(
                    "pi",
                    {"resource": "projects", "guestPath": "/workspace", "target": bad},
                    self.resources,
                )

    def test_backup_inventory_is_derived_from_resource_policy(self) -> None:
        self.assertEqual(backup_resource_ids(self.resources), ["pi-home", "projects"])

    def test_managed_paths_cannot_escape_allowed_storage_roots(self) -> None:
        with self.assertRaises(ManagedResourceError):
            validate_storage_resources(
                {
                    "etc": {
                        "path": "/etc",
                        "stateClass": "authoritative",
                        "capabilities": ["read"],
                        "backup": {"enabled": True},
                    }
                }
            )
        with self.assertRaises(ManagedResourceError):
            validate_storage_resources(
                {
                    "escape": {
                        "path": "/tank/../etc",
                        "stateClass": "authoritative",
                        "capabilities": ["read"],
                        "backup": {"enabled": True},
                    }
                }
            )

    def test_mount_paths_reject_runtime_delimiters_and_control_characters(self) -> None:
        for path in ("/tank/bad:path", "/tank/bad\npath", "/tank/bad\rpath"):
            with self.subTest(path=path), self.assertRaises(ManagedResourceError):
                validate_storage_resources(
                    {
                        "bad": {
                            "path": path,
                            "stateClass": "authoritative",
                            "capabilities": ["read"],
                            "backup": {"enabled": True},
                        }
                    }
                )
        with self.assertRaises(ManagedResourceError):
            validate_storage_attachment(
                "pi",
                {"resource": "projects", "guestPath": "/bad:path"},
                self.resources,
            )


if __name__ == "__main__":
    unittest.main()
