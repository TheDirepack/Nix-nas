from __future__ import annotations

import pathlib
import sys
import unittest
from unittest import mock
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_feature_control_v2 as feature_v2  # noqa: E402


class Headers(dict):
    pass


class FeatureControlV2Tests(unittest.TestCase):
    def effective(
        self,
        capability: str | None = "application.demo.access",
        lifecycle: dict | None = None,
        *,
        enabled: bool = True,
    ) -> dict:
        auth = {"mode": "forward-auth"}
        if capability is not None:
            auth["capability"] = capability
        return {
            "endpoints": {"demo:web": {"auth": auth}},
            "services": {
                "demo": {
                    "enabled": enabled,
                    "lifecycle": lifecycle or {"mode": "persistent"},
                }
            },
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

    @patch.object(feature_v2, "_ORIGINAL_AUTHORIZE_SERVICE_SCOPE")
    @patch.object(feature_v2, "_load_effective")
    def test_capability_endpoint_can_bridge_explicit_legacy_group(self, mocked_effective, mocked_legacy) -> None:
        effective = self.effective()
        effective["endpoints"]["demo:web"]["auth"].update({"allow": "groups", "groups": ["nas_allow_demo"]})
        mocked_effective.return_value = effective
        mocked_legacy.return_value = True
        headers = Headers({"Remote-User": "alice", "Remote-Groups": "nas_allow_demo"})
        self.assertTrue(feature_v2.authorize_service_scope("service:demo:web", headers))
        mocked_legacy.assert_called_once_with("service:demo:web", headers)

    @patch.object(feature_v2, "_ORIGINAL_AUTHORIZE_SERVICE_SCOPE")
    @patch.object(feature_v2, "_load_effective")
    def test_capability_endpoint_without_legacy_assignments_does_not_broaden_access(
        self, mocked_effective, mocked_legacy
    ) -> None:
        mocked_effective.return_value = self.effective()
        headers = Headers({"Remote-User": "alice", "Remote-Groups": "nas_users"})
        self.assertFalse(feature_v2.authorize_service_scope("service:demo:web", headers))
        mocked_legacy.assert_not_called()

    def test_disabled_service_blocks_even_authorized_endpoint(self) -> None:
        effective = self.effective(enabled=False)
        self.assertFalse(feature_v2._authorized_use("demo", effective))

    def test_session_lifecycle_is_never_auto_woken_by_static_endpoint(self) -> None:
        effective = self.effective(lifecycle={"mode": "session"})
        self.assertFalse(feature_v2._authorized_use("demo", effective))

    def test_on_demand_first_access_starts_then_later_access_touches(self) -> None:
        effective = self.effective(lifecycle={"mode": "on-demand", "idleSeconds": 300})
        fake = mock.Mock()
        fake._read_lifecycle_state.return_value = {"schemaVersion": 1, "services": {}}
        with patch.dict(sys.modules, {"nas_managed_service_v2": fake}):
            self.assertTrue(feature_v2._authorized_use("demo", effective))
        fake.start_service.assert_called_once_with("demo")

        fake.reset_mock()
        fake._read_lifecycle_state.return_value = {
            "schemaVersion": 1,
            "services": {"demo": {"lastAccess": 1}},
        }
        with patch.dict(sys.modules, {"nas_managed_service_v2": fake}):
            self.assertTrue(feature_v2._authorized_use("demo", effective))
        fake.touch_service.assert_called_once_with("demo")
        fake.start_service.assert_not_called()

    def test_unknown_lifecycle_fails_closed(self) -> None:
        effective = self.effective(lifecycle={"mode": "mystery"})
        self.assertFalse(feature_v2._authorized_use("demo", effective))


if __name__ == "__main__":
    unittest.main()
