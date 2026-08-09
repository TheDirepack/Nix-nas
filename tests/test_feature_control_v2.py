from __future__ import annotations

import pathlib
import sys
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_feature_control_v2 as feature_v2


class Headers(dict):
    pass


class FeatureControlV2Tests(unittest.TestCase):
    def effective(self, capability: str | None = "application.demo.access") -> dict:
        auth = {"mode": "forward-auth"}
        if capability is not None:
            auth["capability"] = capability
        return {
            "endpoints": {
                "demo:web": {
                    "auth": auth,
                }
            }
        }

    @patch.object(feature_v2, "_load_effective")
    def test_capability_group_authorizes_endpoint(self, mocked_effective) -> None:
        mocked_effective.return_value = self.effective()
        headers = Headers({"Remote-User": "alice", "Remote-Groups": "nas_users,nas_application_demo_access"})
        self.assertTrue(feature_v2.authorize_service_scope("service:demo:web", headers))

    @patch.object(feature_v2, "_load_effective")
    def test_authenticated_user_without_capability_group_is_denied(self, mocked_effective) -> None:
        mocked_effective.return_value = self.effective()
        headers = Headers({"Remote-User": "alice", "Remote-Groups": "nas_users"})
        self.assertFalse(feature_v2.authorize_service_scope("service:demo:web", headers))

    @patch.object(feature_v2, "_load_effective")
    def test_admin_retains_recovery_access(self, mocked_effective) -> None:
        mocked_effective.return_value = self.effective()
        headers = Headers({"Remote-User": "admin", "Remote-Groups": "nas_admin"})
        self.assertTrue(feature_v2.authorize_service_scope("service:demo:web", headers))

    @patch.object(feature_v2, "_load_effective")
    def test_cross_service_capability_fails_closed(self, mocked_effective) -> None:
        mocked_effective.return_value = self.effective("application.other.access")
        headers = Headers({"Remote-User": "alice", "Remote-Groups": "nas_application_other_access"})
        self.assertFalse(feature_v2.authorize_service_scope("service:demo:web", headers))

    @patch.object(feature_v2, "_ORIGINAL_AUTHORIZE_SERVICE_SCOPE")
    @patch.object(feature_v2, "_load_effective")
    def test_legacy_endpoint_falls_back_during_migration(self, mocked_effective, mocked_legacy) -> None:
        mocked_effective.return_value = self.effective(None)
        mocked_legacy.return_value = True
        headers = Headers({"Remote-User": "alice", "Remote-Groups": "legacy-group"})
        self.assertTrue(feature_v2.authorize_service_scope("service:demo:web", headers))
        mocked_legacy.assert_called_once()


if __name__ == "__main__":
    unittest.main()
