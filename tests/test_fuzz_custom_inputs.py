"""Hypothesis coverage for every repository-owned Python input boundary.

The targets in this file are deliberately side-effect free.  They cover the
normalizers, validators, protocol decoders, and V2 service-plan renderers that
turn operator or remote input into control-plane data.  Whole-system mutation
and destructive lifecycle checks remain separate VM qualifications.
"""

from __future__ import annotations

import contextlib
import copy
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
    import nas_identity_model as identity_model
    import nas_identity_sync as identity_sync
    import nas_logging
    import nas_operation_journal as operation_journal
    import nas_operation_lock as operation_lock
    import nas_setup as setup
    import nas_setup_config as setup_config
    import nas_state as state
    import nas_syncthing_devices as syncthing
    import nas_v2_accelerator as accelerator
    import nas_v2_authentik as authentik
    import nas_v2_caddy as caddy
    import nas_v2_compose as compose
    import nas_v2_network as network
    import nas_v2_nmstate as nmstate
    import nas_v2_podman_network as podman_network
    import nas_v2_quadlet as quadlet
    import nas_v2_spec as v2_spec


SERVICE_INPUT_MODULES = frozenset(
    {
        "nas_ai_config",
        "nas_alert_router",
        "nas_cockpit_api",
        "nas_coding_agent",
        "nas_common",
        "nas_doctor",
        "nas_guarded_apply",
        "nas_identity_model",
        "nas_identity_sync",
        "nas_logging",
        "nas_operation_journal",
        "nas_operation_lock",
        "nas_setup",
        "nas_setup_config",
        "nas_state",
        "nas_syncthing_devices",
        "nas_v2_accelerator",
        "nas_v2_apply",
        "nas_v2_authentik",
        "nas_v2_backup",
        "nas_v2_bootstrap",
        "nas_v2_caddy",
        "nas_v2_compose",
        "nas_v2_control",
        "nas_v2_editor",
        "nas_v2_entry",
        "nas_v2_exec_runner",
        "nas_v2_firewalld_reconcile",
        "nas_v2_history",
        "nas_v2_libvirt",
        "nas_v2_network",
        "nas_v2_nmstate",
        "nas_v2_plan",
        "nas_v2_platform_probe",
        "nas_v2_podman_network",
        "nas_v2_python_prepare",
        "nas_v2_quadlet",
        "nas_v2_readiness",
        "nas_v2_session",
        "nas_v2_source_watch",
        "nas_v2_spec",
        "nas_v2_systemd",
        "nas_v2_systemd_reconcile",
        "nas_v2_wake",
    }
)


BASE_V2_DOCUMENT = {
    "schemaVersion": 3,
    "services": {
        "demo": {
            "name": "Demo",
            "workload": {"kind": "daemon"},
            "runtime": {"type": "systemd", "unit": "demo.service"},
            "routes": {
                "web": {
                    "target": {"type": "http", "port": 8080},
                    "exposure": {"type": "path", "paths": ["/demo/"]},
                    "auth": {"mode": "public"},
                    "portal": {"visible": False},
                }
            },
        }
    },
}


def _compiled_v2_schema() -> dict[str, object]:
    return v2_spec.load_schema(ROOT / "schemas" / "managed-services-v3.schema.json")


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
            expected_boundary_error(caddy._header_name, value)
            expected_boundary_error(caddy._path_patterns, value)
            expected_boundary_error(caddy._safe_posix, value, "fuzz path")
            expected_boundary_error(quadlet._reject_control, value, "fuzz field")
            expected_boundary_error(quadlet._single_line, value, field="fuzz field")
            expected_boundary_error(quadlet._safe_path, value, field="fuzz field")
            expected_boundary_error(authentik._api_root, value)
            expected_boundary_error(authentik.desired_capabilities, {"services": {}})
            expected_boundary_error(network.bridge_interface_name, value)
            expected_boundary_error(network.podman_network_name, value, {})
            expected_boundary_error(network.vlan_binding, {"vlanId": value, "vlanParent": value})
            expected_boundary_error(nmstate._bound_policy, {"vlanId": 10}, value)
            expected_boundary_error(
                podman_network._network_source,
                value,
                "nas-v2-demo.service",
                {
                    "mode": "isolated",
                    "outboundDefault": "deny",
                    "lanAccess": False,
                    "allowedHostPorts": [],
                    "allowedEgress": [],
                },
                network_name="nas-v2-demo",
            )
            v2_spec.SERVICE_ID_RE.fullmatch(value)
            v2_spec.CAPABILITY_ID_RE.fullmatch(value)
            v2_spec.SYSTEMD_UNIT_RE.fullmatch(value)
            authentik.CAPABILITY_RE.fullmatch(value)
            accelerator.is_cdi_selector(value)

        @settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
        @given(HOSTILE_TEXT)
        def test_v2_document_compilation_rejects_hostile_service_fields(self, value: str) -> None:
            document = copy.deepcopy(BASE_V2_DOCUMENT)
            document["services"]["demo"]["name"] = value
            schema = _compiled_v2_schema()
            expected_boundary_error(v2_spec.compile_document, document, schema)

        @settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
        @given(JSON_VALUE)
        def test_structured_control_plane_boundaries(self, value: object) -> None:
            nas_logging.sanitize(value)
            operation_journal._journal_value(value)
            doctor._human(value if isinstance(value, dict) else {})
            expected_boundary_error(cockpit_api._json_string, value if isinstance(value, dict) else {}, "value")
            expected_boundary_error(
                cockpit_api._json_string_list,
                value if isinstance(value, dict) else {},
                "values",
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
            document = copy.deepcopy(BASE_V2_DOCUMENT)
            if isinstance(value, dict):
                document["services"]["demo"]["name"] = str(value)[:512]
            schema = _compiled_v2_schema()
            expected_boundary_error(v2_spec.compile_document, document, schema)

        @settings(max_examples=250, deadline=None, suppress_health_check=[HealthCheck.too_slow])
        @given(service_id=SAFE_SERVICE_ID, hostile=HOSTILE_TEXT)
        def test_v2_plan_renderers_reject_or_build_hostile_fields(self, service_id: str, hostile: str) -> None:
            expected_boundary_error(network.bridge_interface_name, service_id + hostile)
            expected_boundary_error(
                network.podman_network_name, service_id + hostile, {"workload": {"kind": "session"}}
            )
            expected_boundary_error(network.network_policy, {"networkProfiles": {}}, {"networkProfile": service_id})
            expected_boundary_error(compose._is_host_volume_source, hostile)
            expected_boundary_error(compose._volume_target, hostile)
            expected_boundary_error(
                caddy.generate_caddyfile, {"services": {}, "derived": {"routes": []}}, lan_host=hostile
            )

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
            expected_boundary_error(setup.validate_service_request, {value: "on-demand"})
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
