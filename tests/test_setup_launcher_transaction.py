from __future__ import annotations

import pathlib
import sys
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_identity_sync as sync  # noqa: E402


def flows() -> dict[str, dict[str, str]]:
    return {
        "default-authentication-flow": {"pk": "auth"},
        "default-provider-authorization-implicit-consent": {"pk": "authorization"},
        "default-invalidation-flow": {"pk": "invalidation"},
    }


def embedded_outpost(*, providers: list[int] | None = None) -> dict[str, object]:
    return {
        "managed": "goauthentik.io/outposts/embedded",
        "pk": 7,
        "providers": list(providers or []),
    }


class SetupLauncherTransactionTests(unittest.TestCase):
    def test_validates_embedded_outpost_before_first_mutation(self) -> None:
        with (
            mock.patch.object(sync, "PUBLIC_HOST", "nas.local"),
            mock.patch.object(sync, "default_flows", return_value=flows()),
            mock.patch.object(sync, "authentik_list", side_effect=[[], [], []]),
            mock.patch.object(sync, "authentik_request") as request,
        ):
            with self.assertRaisesRegex(sync.SyncError, "embedded outpost"):
                sync.ensure_setup_launcher("token")
        request.assert_not_called()

    def test_application_failure_removes_new_provider(self) -> None:
        failure = sync.SyncError("injected application failure")
        with (
            mock.patch.object(sync, "PUBLIC_HOST", "nas.local"),
            mock.patch.object(sync, "default_flows", return_value=flows()),
            mock.patch.object(
                sync,
                "authentik_list",
                side_effect=[[], [], [embedded_outpost()]],
            ),
            mock.patch.object(
                sync,
                "authentik_request",
                side_effect=[{"pk": 11}, failure, None],
            ) as request,
        ):
            with self.assertRaisesRegex(sync.SyncError, "injected application failure"):
                sync.ensure_setup_launcher("token")

        self.assertEqual(request.call_args_list[-1].args, ("token", "providers/proxy/11/"))
        self.assertEqual(request.call_args_list[-1].kwargs, {"method": "DELETE"})

    def test_outpost_failure_removes_new_application_then_provider(self) -> None:
        failure = sync.SyncError("injected outpost failure")
        with (
            mock.patch.object(sync, "PUBLIC_HOST", "nas.local"),
            mock.patch.object(sync, "default_flows", return_value=flows()),
            mock.patch.object(
                sync,
                "authentik_list",
                side_effect=[[], [], [embedded_outpost()]],
            ),
            mock.patch.object(
                sync,
                "authentik_request",
                side_effect=[{"pk": 11}, None, failure, None, None, None],
            ) as request,
        ):
            with self.assertRaisesRegex(sync.SyncError, "injected outpost failure"):
                sync.ensure_setup_launcher("token")

        rollback_outpost, rollback_app, rollback_provider = request.call_args_list[-3:]
        self.assertEqual(rollback_outpost.args, ("token", "outposts/instances/7/"))
        self.assertEqual(
            rollback_outpost.kwargs,
            {"method": "PATCH", "body": {"providers": []}},
        )
        self.assertEqual(rollback_app.args, ("token", "core/applications/nas-setup/"))
        self.assertEqual(rollback_app.kwargs, {"method": "DELETE"})
        self.assertEqual(rollback_provider.args, ("token", "providers/proxy/11/"))
        self.assertEqual(rollback_provider.kwargs, {"method": "DELETE"})

    def test_outpost_failure_restores_existing_application_and_provider(self) -> None:
        provider = {
            "pk": 11,
            "name": "NAS Setup",
            "mode": "forward_single",
            "external_host": "https://old.local/setup/",
            "internal_host": "http://127.0.0.1:8980",
            "internal_host_ssl_validation": False,
            "authentication_flow": "old-auth",
            "authorization_flow": "old-authorization",
            "invalidation_flow": "old-invalidation",
        }
        application = {
            "name": "NAS Setup",
            "slug": "nas-setup",
            "provider": 4,
            "meta_description": "Old description",
            "meta_publisher": "Old publisher",
            "meta_launch_url": "https://old.local/setup/",
            "open_in_new_tab": True,
        }
        failure = sync.SyncError("injected outpost failure")
        with (
            mock.patch.object(sync, "PUBLIC_HOST", "nas.local"),
            mock.patch.object(sync, "default_flows", return_value=flows()),
            mock.patch.object(
                sync,
                "authentik_list",
                side_effect=[[provider], [application], [embedded_outpost()]],
            ),
            mock.patch.object(
                sync,
                "authentik_request",
                side_effect=[{"pk": 11}, None, failure, None, None, None],
            ) as request,
        ):
            with self.assertRaisesRegex(sync.SyncError, "injected outpost failure"):
                sync.ensure_setup_launcher("token")

        rollback_outpost, restore_app, restore_provider = request.call_args_list[-3:]
        self.assertEqual(rollback_outpost.args, ("token", "outposts/instances/7/"))
        self.assertEqual(
            rollback_outpost.kwargs,
            {"method": "PATCH", "body": {"providers": []}},
        )
        self.assertEqual(restore_app.args, ("token", "core/applications/nas-setup/"))
        self.assertEqual(restore_app.kwargs, {"method": "PATCH", "body": application})
        self.assertEqual(restore_provider.args, ("token", "providers/proxy/11/"))
        self.assertEqual(
            restore_provider.kwargs,
            {
                "method": "PATCH",
                "body": {key: value for key, value in provider.items() if key != "pk"},
            },
        )

    def test_rollback_failure_is_reported_as_incomplete(self) -> None:
        apply_failure = sync.SyncError("injected application failure")
        rollback_failure = sync.SyncError("injected rollback failure")
        with (
            mock.patch.object(sync, "PUBLIC_HOST", "nas.local"),
            mock.patch.object(sync, "default_flows", return_value=flows()),
            mock.patch.object(
                sync,
                "authentik_list",
                side_effect=[[], [], [embedded_outpost()]],
            ),
            mock.patch.object(
                sync,
                "authentik_request",
                side_effect=[{"pk": 11}, apply_failure, rollback_failure],
            ),
        ):
            with self.assertRaisesRegex(sync.SyncError, "rollback incomplete") as raised:
                sync.ensure_setup_launcher("token")
        self.assertIs(raised.exception.__cause__, apply_failure)

    def test_portal_outpost_failure_restores_config_application_and_provider(self) -> None:
        provider = {
            "pk": 11,
            "name": "NAS Portal",
            "mode": "forward_single",
            "external_host": "https://old.local",
            "internal_host": "http://127.0.0.1:8080",
            "internal_host_ssl_validation": False,
            "authentication_flow": "old-auth",
            "authorization_flow": "old-authorization",
            "invalidation_flow": "old-invalidation",
        }
        application = {
            "name": "NAS Portal",
            "slug": "nas-portal",
            "provider": 4,
            "meta_launch_url": "https://old.local",
        }
        outpost = embedded_outpost(providers=[4])
        outpost["config"] = {
            "existing": "value",
            "authentik_host": "https://old.local/identity/",
            "authentik_host_browser": "https://old.local/identity/",
        }
        failure = sync.SyncError("injected portal outpost failure")
        with (
            mock.patch.object(sync, "PUBLIC_HOST", "nas.local"),
            mock.patch.object(sync, "default_flows", return_value=flows()),
            mock.patch.object(sync, "authentik_list", side_effect=[[provider], [application], [outpost]]),
            mock.patch.object(
                sync,
                "authentik_request",
                side_effect=[None, None, failure, None, None, None],
            ) as request,
        ):
            with self.assertRaisesRegex(sync.SyncError, "injected portal outpost failure"):
                sync.ensure_portal_proxy("token")

        restore_outpost, restore_app, restore_provider = request.call_args_list[-3:]
        self.assertEqual(restore_outpost.args, ("token", "outposts/instances/7/"))
        self.assertEqual(
            restore_outpost.kwargs,
            {
                "method": "PATCH",
                "body": {
                    "providers": [4],
                    "config": outpost["config"],
                },
            },
        )
        self.assertEqual(restore_app.args, ("token", "core/applications/nas-portal/"))
        self.assertEqual(restore_app.kwargs, {"method": "PATCH", "body": application})
        self.assertEqual(restore_provider.args, ("token", "providers/proxy/11/"))
        self.assertEqual(
            restore_provider.kwargs,
            {
                "method": "PATCH",
                "body": {key: value for key, value in provider.items() if key != "pk"},
            },
        )

    def test_cockpit_application_failure_removes_new_provider(self) -> None:
        failure = sync.SyncError("injected cockpit application failure")
        with (
            mock.patch.object(sync, "PUBLIC_HOST", "nas.local"),
            mock.patch.object(sync, "default_flows", return_value=flows()),
            mock.patch.object(sync, "authentik_list", side_effect=[[], [], [embedded_outpost()]]),
            mock.patch.object(
                sync,
                "authentik_request",
                side_effect=[{"pk": 9}, failure, None],
            ) as request,
        ):
            with self.assertRaisesRegex(sync.SyncError, "injected cockpit application failure"):
                sync.ensure_cockpit_launcher("token")

        self.assertEqual(request.call_args_list[-1].args, ("token", "providers/proxy/9/"))
        self.assertEqual(request.call_args_list[-1].kwargs, {"method": "DELETE"})


if __name__ == "__main__":
    unittest.main()
