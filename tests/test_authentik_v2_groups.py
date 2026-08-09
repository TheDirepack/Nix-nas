from __future__ import annotations

import pathlib
import sys
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_authentik_v2_groups as authz  # noqa: E402


class AuthentikV2GroupTests(unittest.TestCase):
    def effective(self) -> dict:
        return {
            "storageResources": {
                "media-library": {
                    "path": "/tank/media",
                    "stateClass": "authoritative",
                    "capabilities": ["read", "write"],
                    "backup": {"enabled": True},
                }
            },
            "services": {
                "jellyfin": {
                    "endpoints": {
                        "web": {
                            "auth": {
                                "mode": "forward-auth",
                                "capability": "application.jellyfin.access",
                            }
                        }
                    }
                }
            },
        }

    def test_desired_capabilities_include_storage_and_application_access(self) -> None:
        self.assertEqual(
            authz.desired_capabilities(self.effective()),
            {
                "storage.media-library.read",
                "storage.media-library.write",
                "application.jellyfin.access",
            },
        )

    def test_group_names_match_copyparty_storage_group_convention(self) -> None:
        self.assertEqual(
            authz.capability_group_name("storage.media-library.read"),
            "nas_storage_media_library_read",
        )
        self.assertEqual(
            authz.capability_group_name("application.jellyfin.access"),
            "nas_application_jellyfin_access",
        )

    @patch.object(authz, "authentik_request")
    @patch.object(authz, "authentik_list")
    def test_reconcile_creates_missing_non_superuser_groups(self, mocked_list, mocked_request) -> None:
        mocked_list.return_value = []
        result = authz.reconcile_groups("token", self.effective())
        self.assertEqual(len(result["createdGroups"]), 3)
        create_calls = [call for call in mocked_request.call_args_list if call.args[1] == "core/groups/"]
        self.assertEqual(len(create_calls), 3)
        for call in create_calls:
            self.assertFalse(call.kwargs["body"]["is_superuser"])
            self.assertTrue(call.kwargs["body"]["attributes"]["nixos_nas_managed"])

    @patch.object(authz, "authentik_request")
    @patch.object(authz, "authentik_list")
    def test_reconcile_corrects_managed_group_that_became_superuser(self, mocked_list, mocked_request) -> None:
        mocked_list.return_value = [
            {
                "name": "nas_application_jellyfin_access",
                "pk": "group-1",
                "is_superuser": True,
                "attributes": {authz.MANAGED_ATTRIBUTE: "application.jellyfin.access"},
            }
        ]
        result = authz.reconcile_groups("token", {"storageResources": {}, "services": self.effective()["services"]})
        self.assertEqual(result["correctedGroups"], ["nas_application_jellyfin_access"])
        patch_call = mocked_request.call_args
        self.assertEqual(patch_call.kwargs["method"], "PATCH")
        self.assertFalse(patch_call.kwargs["body"]["is_superuser"])


if __name__ == "__main__":
    unittest.main()
