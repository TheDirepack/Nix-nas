"""Hypothesis coverage for every repository-owned Python input boundary.

The targets in this file are deliberately side-effect free.  They cover the
normalizers, validators, protocol decoders, and service-plan renderers that
turn operator or remote input into control-plane data.  Whole-system mutation
and destructive lifecycle checks remain separate VM qualifications.
"""

from __future__ import annotations

import contextlib
import io
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
TESTS = ROOT / "tests"
for path in (SERVICES, TESTS):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

try:
    from hypothesis import HealthCheck, given, settings, strategies as st
except ImportError:
    HAS_HYPOTHESIS = False
else:
    HAS_HYPOTHESIS = True
    import nas_ai_config as ai_config
    import nas_alert_router as alert_router
    import nas_cockpit_api as cockpit_api
    import nas_coding_agent as coding_agent
    import nas_common as common
    import nas_doctor as doctor
    import nas_feature_control as feature_control
    import nas_feature_model as feature_model
    import nas_identity_model as identity_model
    import nas_identity_sync as identity_sync
    import nas_logging
    import nas_managed_service as managed_service
    import nas_migrate_state as migrate_state
    import nas_operation_journal as operation_journal
    import nas_operation_lock as operation_lock
    import nas_service_authentik as service_authentik
    import nas_service_caddy as service_caddy
    import nas_service_firewall as service_firewall
    import nas_service_runtime_compose as runtime_compose
    import nas_service_runtime_libvirt as runtime_libvirt
    import nas_service_runtime_podman as runtime_podman
    import nas_setup as setup
    import nas_setup_config as setup_config
    import nas_state as state
    import nas_syncthing_devices as syncthing


SERVICE_INPUT_MODULES = frozenset(
    {
        "nas_ai_config",
        "nas_alert_router",
        "nas_cockpit_api",
        "nas_coding_agent",
        "nas_common",
        "nas_doctor",
        "nas_feature_control",
        "nas_feature_model",
        "nas_identity_model",
        "nas_identity_sync",
        "nas_logging",
        "nas_managed_service",
        "nas_migrate_state",
        "nas_operation_journal",
        "nas_operation_lock",
        "nas_service_authentik",
        "nas_service_caddy",
        "nas_service_firewall",
        "nas_service_runtime_compose",
        "nas_service_runtime_libvirt",
        "nas_service_runtime_podman",
        "nas_setup",
        "nas_setup_config",
        "nas_state",
        "nas_syncthing_devices",
    }
)


if HAS_HYPOTHESIS:
    HOSTILE_TEXT = st.text(max_size=2048)
    JSON_VALUE = st.recursive(
        st.none() | st.booleans() | st.integers() | st.text(max_size=512),
        lambda children: st.lists(children, max_size=12) | st.dictionaries(st.text(max_size=64), children, max_size=12),
        max_leaves=40,
    )
    SAFE_SERVICE_ID = st.from_regex(r"[a-z][a-z0-9-]{0,12}", fullmatch=True)

    def expected_boundary_error(function, *args, **kwargs):
        """Run a boundary and ignore only its documented validation failures."""

        try:
            return function(*args, **kwargs)
        except (ValueError, OSError, RuntimeError):
            return None

    class CustomInputSurfaceFuzzTests(unittest.TestCase):  # pyright: ignore[reportRedeclaration]
        def test_feature_catalog_rejects_unhashable_scalars(self) -> None:
            contract = feature_control.catalog_contract()
            catalogs = [
                {"schemaVersion": [], "features": {"demo": {}}},
                {"schemaVersion": 1, "features": {"demo": {"parent": []}}},
                {
                    "schemaVersion": 1,
                    "features": {"demo": {"availabilityProbe": {"type": []}}},
                },
                {
                    "schemaVersion": 1,
                    "features": {
                        "demo": {
                            "allowedModes": ["off", "on-demand"],
                            "idleSeconds": [],
                        }
                    },
                },
                {"schemaVersion": 1, "features": {"demo": {"activePorts": [[]]}}},
                {"schemaVersion": 1, "features": {"demo": {}}, "memoryComponents": [{"feature": []}]},
            ]
            for catalog in catalogs:
                with self.assertRaises(feature_model.FeatureError):
                    feature_model.normalize_catalog(catalog, contract)

        @settings(max_examples=350, deadline=None, suppress_health_check=[HealthCheck.too_slow])
        @given(HOSTILE_TEXT)
        def test_text_protocol_and_shell_boundaries(self, value: str) -> None:
            expected_boundary_error(ai_config.validate_provider_id, value)
            expected_boundary_error(ai_config.validate_proxy_url, value)
            expected_boundary_error(ai_config.validate_model_id, value)
            expected_boundary_error(ai_config.validate_local_model_id, value)
            expected_boundary_error(ai_config.validate_local_extra_args, [value])
            expected_boundary_error(ai_config.validate_models, [value])
            expected_boundary_error(ai_config.validate_filters, {"stripParams": value})
            expected_boundary_error(ai_config.validate_role, value)
            expected_boundary_error(coding_agent.validate_workspace, value, (pathlib.Path("/tmp"),))
            with contextlib.redirect_stderr(io.StringIO()):
                common.split_groups(value)
            common.parse_systemd_show(value)
            expected_boundary_error(identity_model.validate_uid, value)
            expected_boundary_error(identity_sync.endpoint_label, value)
            expected_boundary_error(syncthing.validate_username, value)
            expected_boundary_error(operation_lock._validate_class, value)
            expected_boundary_error(setup_config.normalize_secret_line, value, "fuzz-secret")
            expected_boundary_error(state.safe_member_name, value)
            expected_boundary_error(service_firewall._validate_cidr, value)
            feature_model.valid_loopback_http_url(value)
            feature_control._is_valid_service_scope(value)
            expected_boundary_error(
                service_caddy._validate_exposure,
                {"type": "path", "value": value},
            )

        @settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
        @given(JSON_VALUE)
        def test_structured_control_plane_boundaries(self, value: object) -> None:
            nas_logging.sanitize(value)
            operation_journal._journal_value(value)
            expected_boundary_error(migrate_state._schema, value if isinstance(value, dict) else {})
            doctor._human(value if isinstance(value, dict) else {})
            expected_boundary_error(cockpit_api._json_string, value if isinstance(value, dict) else {}, "value")
            expected_boundary_error(
                cockpit_api._json_string_list,
                value if isinstance(value, dict) else {},
                "values",
            )
            expected_boundary_error(feature_control.normalize_catalog, value if isinstance(value, dict) else {})
            expected_boundary_error(
                feature_model.normalize_catalog,
                value if isinstance(value, dict) else {},
                feature_control.catalog_contract(),
            )
            expected_boundary_error(setup_config.normalize_config, value if isinstance(value, dict) else {})
            expected_boundary_error(
                identity_model.build_model,
                {
                    "groups": [],
                    "users": [
                        {
                            "pk": "1",
                            "username": str(value)[:128],
                            "is_active": True,
                            "groups": [],
                            "attributes": {},
                        }
                    ],
                },
            )
            expected_boundary_error(identity_sync.sanitize_error_payload, str(value).encode("utf-8"))

        @settings(max_examples=250, deadline=None, suppress_health_check=[HealthCheck.too_slow])
        @given(service_id=SAFE_SERVICE_ID, hostile=HOSTILE_TEXT)
        def test_managed_service_adapters_render_or_reject_hostile_fields(self, service_id: str, hostile: str) -> None:
            endpoint = {
                "transport": "http",
                "targetPort": 8080,
                "exposure": {"type": "path", "value": "/" + hostile.replace("/", "")[:32]},
                "auth": {"mode": "public"},
            }
            service = {
                "label": hostile,
                "enabled": True,
                "runtime": {
                    "type": "compose",
                    "source": f"/var/lib/nas-control/apps/{service_id}/app.yaml",
                    "startPolicy": "boot",
                },
                "endpoints": {"web": endpoint},
                "network": {"allowedEgress": []},
                "resources": {"cpus": 2, "memoryBytes": 2 * 1024 * 1024 * 1024},
            }
            expected_boundary_error(managed_service.validate_service, service_id, service)
            expected_boundary_error(service_authentik.plan_authentik, service_id, service)
            expected_boundary_error(service_caddy.generate_caddy_fragment, service)
            expected_boundary_error(service_firewall.plan_firewall, service_id, service)
            expected_boundary_error(runtime_compose.plan_compose, service_id, service)
            expected_boundary_error(runtime_libvirt.plan_libvirt, service_id, service)
            expected_boundary_error(runtime_podman.plan_podman, service_id, service)

        @settings(max_examples=180, deadline=None)
        @given(HOSTILE_TEXT)
        def test_setup_and_alert_inputs_remain_bounded(self, value: str) -> None:
            expected_boundary_error(
                alert_router.normalize_alert,
                {
                    "labels": {"alertname": value, "severity": value},
                    "annotations": {"summary": value, "description": value},
                },
            )
            expected_boundary_error(setup.validate_feature_request, {value: "on-demand"})
            expected_boundary_error(
                setup.validate_storage_request,
                {"createPool": True, "devices": [value]},
                [],
                False,
            )

else:

    @unittest.skip("Hypothesis is not installed; CI runs the property-test tier with it")
    class CustomInputSurfaceFuzzTests(unittest.TestCase):  # pyright: ignore[reportRedeclaration]
        def test_hypothesis_tier_placeholder(self) -> None:
            pass


if __name__ == "__main__":
    unittest.main()
