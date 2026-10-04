"""Slow-tier Hypothesis stateful suites for Managed Services V2.

The RuleBasedStateMachine drives a lifecycle model (add / enable / disable /
delete / port-change) and reconciles it through the V2 compiler, Caddy
projection, and portal projection, asserting that every projection stays
consistent with the model. The differential suite checks the same agreement
over generated multi-service documents.
"""

from __future__ import annotations

import copy
import pathlib
import tempfile
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas" / "managed-services-v3.schema.json"
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

try:
    from hypothesis import HealthCheck, assume, given, settings, strategies as st
    from hypothesis.stateful import Bundle, RuleBasedStateMachine, invariant, rule, run_state_machine_as_test
except ImportError:
    HAS_HYPOTHESIS = False
else:
    HAS_HYPOTHESIS = True
    import nas_v2_caddy as caddy
    import nas_v2_spec as v2
    import nas_v2_editor as editor
    import nas_v2_apply as apply


def _valid_service_doc(service_id: str, enabled: bool = True) -> dict:
    return {
        "name": f"Service {service_id}",
        "enabled": enabled,
        "workload": {"kind": "daemon", "activation": "persistent"},
        "runtime": {"type": "systemd", "unit": f"{service_id}.service"},
        "routes": {
            "web": {
                "target": {"type": "http", "port": 8080},
                "exposure": {"type": "path", "paths": [f"/{service_id}/"]},
                "auth": {"mode": "public"},
                "portal": {"visible": True, "title": service_id},
            }
        },
    }


if HAS_HYPOTHESIS:
    SAFE_SERVICE_ID = st.one_of(
        st.integers(min_value=0, max_value=63).map(lambda index: f"svc{index}"),
        st.sampled_from(["a-b", "a", "a" * 64, "b" * 64]),
    )
    SAFE_PORT = st.integers(1024, 65535)

    class ManagedServiceStateMachine(RuleBasedStateMachine):
        services_bundle = Bundle("services")

        def __init__(self) -> None:
            super().__init__()
            self.schema = v2.load_schema(SCHEMA)
            self.services: dict[str, dict] = {}
            self._revision = 0
            self._cache: tuple[int, dict | None] = (-1, None)

        def _compile(self) -> dict:
            if self._cache[0] == self._revision and self._cache[1] is not None:
                return self._cache[1]
            effective = v2.compile_document(
                {"schemaVersion": 3, "generation": 1, "services": copy.deepcopy(self.services)},
                self.schema,
            )
            self._cache = (self._revision, effective)
            return effective

        def _bump(self) -> None:
            self._revision += 1

        @rule(
            target=services_bundle,
            sid=SAFE_SERVICE_ID,
            enabled=st.booleans(),
        )
        def add_service(self, sid: str, enabled: bool) -> str:
            assume(sid not in self.services)
            self.services[sid] = _valid_service_doc(sid, enabled=enabled)
            self._bump()
            return sid

        @rule(sid=services_bundle, port=SAFE_PORT)
        def modify_port(self, sid: str, port: int) -> None:
            assume(sid in self.services)
            self.services[sid]["routes"]["web"]["target"]["port"] = port
            self._bump()

        @rule(sid=services_bundle, protected=st.booleans(), on_demand=st.booleans())
        def change_auth_and_activation(self, sid: str, protected: bool, on_demand: bool) -> None:
            assume(sid in self.services)
            service = self.services[sid]
            service["routes"]["web"]["auth"] = (
                {"mode": "identity", "capability": "access"} if protected else {"mode": "public"}
            )
            workload: dict = {"kind": "daemon", "activation": "on-demand" if on_demand else "persistent"}
            service["workload"] = workload
            if on_demand:
                workload["idleSeconds"] = 60
            self._bump()

        @rule(sid=services_bundle)
        def disable_service(self, sid: str) -> None:
            assume(sid in self.services)
            self.services[sid]["enabled"] = False
            self._bump()

        @rule(sid=services_bundle)
        def enable_service(self, sid: str) -> None:
            assume(sid in self.services)
            self.services[sid]["enabled"] = True
            self._bump()

        @rule(sid=services_bundle)
        def delete_service(self, sid: str) -> None:
            assume(sid in self.services)
            del self.services[sid]
            self._bump()

        @invariant()
        def effective_routes_match_model(self) -> None:
            effective = self._compile()
            routes = effective["derived"]["routes"]
            actual_ids = {route["service"] for route in routes}
            assert actual_ids == set(self.services), f"route mismatch: {actual_ids} vs {set(self.services)}"
            for route in routes:
                service_id = route["service"]
                assert service_id in self.services, f"stale route for {service_id}"

        @invariant()
        def portal_and_caddy_agree_on_visible_services(self) -> None:
            effective = self._compile()
            portal = caddy.compile_portal_projection(effective)
            portal_ids = {entry["service"] for entry in portal["entries"]}
            caddyfile = caddy.generate_caddyfile(effective)
            for sid, service in self.services.items():
                if service["enabled"]:
                    assert sid in portal_ids, f"enabled {sid} missing from portal"
                    assert f"/{sid}/" in caddyfile, f"enabled {sid} missing from caddyfile"
                else:
                    assert sid not in portal_ids, f"disabled {sid} present in portal"
                    assert f"/{sid}/" not in caddyfile, f"disabled {sid} present in caddyfile"

        @invariant()
        def rejected_document_preserves_model(self) -> None:
            bad = copy.deepcopy(self.services)
            for index, sid in enumerate(("svc0", "svc1")):
                if sid not in bad:
                    bad[sid] = _valid_service_doc(sid, enabled=True)
            first, second = ("svc0", "svc1")
            duplicate_path = bad[first]["routes"]["web"]["exposure"]["paths"][0]
            bad[second]["routes"]["web"]["exposure"]["paths"] = [duplicate_path]
            document = {"schemaVersion": 3, "generation": 1, "services": bad}
            snapshot = copy.deepcopy(document)
            try:
                v2.compile_document(
                    document,
                    self.schema,
                )
            except v2.ManagedServicesV2Error as exc:
                assert "route path" in str(exc).lower() or "route" in str(exc).lower()
                assert document == snapshot, "rejected compilation mutated its input"
            else:
                raise AssertionError("duplicate route path unexpectedly committed")

    class StatefulTests(unittest.TestCase):  # pyright: ignore[reportRedeclaration]
        @settings(
            max_examples=30,
            deadline=None,
            suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
            stateful_step_count=25,
        )
        def test_stateful_machine(self) -> None:
            run_state_machine_as_test(ManagedServiceStateMachine)

    class ProjectionDifferentialTests(unittest.TestCase):  # pyright: ignore[reportRedeclaration]
        @settings(max_examples=15, deadline=None)
        @given(st.lists(st.tuples(st.booleans(), st.booleans()), min_size=1, max_size=6))
        def test_real_editor_apply_sequence_rejects_stale_changes_without_mutation(self, steps):
            with tempfile.TemporaryDirectory() as raw:
                root = pathlib.Path(raw)
                authority = root / "services.yaml"
                authority.write_text("schemaVersion: 3\nservices: {}\n")
                effective_path = root / "effective.json"
                plan_path = root / "plan.json"

                def project():
                    return apply.apply(
                        apply.ApplyPaths(
                            desired=authority, schema=SCHEMA, platform=None, effective=effective_path, plan=plan_path
                        )
                    )

                project()
                for enabled, stale in steps:
                    before = {
                        path.relative_to(root): path.read_bytes()
                        for path in root.rglob("*")
                        if path.is_file() and path.suffix != ".lock"
                    }
                    service = _valid_service_doc("demo", enabled=enabled)
                    document = {"schemaVersion": 3, "services": {"demo": service}}
                    revision = editor.read_document(desired_path=authority, schema_path=SCHEMA)["revision"]
                    if stale:
                        with self.assertRaises(editor.ManagedServicesEditorError):
                            editor.replace_document_value(
                                document,
                                desired_path=authority,
                                schema_path=SCHEMA,
                                platform_path=None,
                                expected_revision="0" * 64,
                            )
                        self.assertEqual(
                            {
                                path.relative_to(root): path.read_bytes()
                                for path in root.rglob("*")
                                if path.is_file() and path.suffix != ".lock"
                            },
                            before,
                        )
                    else:
                        editor.replace_document_value(
                            document,
                            desired_path=authority,
                            schema_path=SCHEMA,
                            platform_path=None,
                            expected_revision=revision,
                        )
                        project()
                        import json

                        effective = json.loads(effective_path.read_text())
                        self.assertEqual(effective["services"]["demo"]["enabled"], enabled)
                        self.assertEqual(
                            editor.read_document(desired_path=authority, schema_path=SCHEMA)["document"], document
                        )

        @settings(
            max_examples=80,
            deadline=None,
            suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
        )
        @given(
            st.lists(
                st.tuples(
                    SAFE_SERVICE_ID,
                    SAFE_PORT,
                    st.booleans(),
                ),
                min_size=1,
                max_size=6,
                unique_by=lambda item: item[0],
            )
        )
        def test_effective_portal_caddy_describe_same_semantics(self, items) -> None:
            schema = v2.load_schema(SCHEMA)
            services: dict[str, dict] = {}
            for sid, port, enabled in items:
                service = _valid_service_doc(sid, enabled=enabled)
                service["routes"]["web"]["target"]["port"] = port
                services[sid] = service

            effective = v2.compile_document(
                {"schemaVersion": 3, "generation": 1, "services": services},
                schema,
            )
            portal = caddy.compile_portal_projection(effective)
            portal_ids = {entry["service"] for entry in portal["entries"]}
            caddyfile = caddy.generate_caddyfile(effective)

            for sid, service in services.items():
                enabled = service["enabled"]
                self.assertEqual(enabled, sid in portal_ids, msg=f"{sid} portal visibility")
                self.assertEqual(enabled, f"/{sid}/" in caddyfile, msg=f"{sid} caddyfile presence")


else:

    @unittest.skip("Hypothesis is not installed; CI runs this file in the slow property tier")
    class StatefulTests(unittest.TestCase):  # pyright: ignore[reportRedeclaration]
        def test_hypothesis_required(self) -> None:
            pass

    @unittest.skip("Hypothesis is not installed; CI runs this file in the slow property tier")
    class ProjectionDifferentialTests(unittest.TestCase):  # pyright: ignore[reportRedeclaration]
        def test_hypothesis_required(self) -> None:
            pass


if __name__ == "__main__":
    unittest.main()
