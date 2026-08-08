from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_managed_service as msvc
import nas_service_caddy as caddy

try:
    from hypothesis import HealthCheck, assume, given, settings, strategies as st
    from hypothesis.stateful import Bundle, RuleBasedStateMachine, invariant, rule, run_state_machine_as_test

    HAS_HYPOTHESIS = True
except ImportError:
    HAS_HYPOTHESIS = False


if HAS_HYPOTHESIS:

    SAFE_HOSTNAME = st.from_regex(r"[a-z0-9][a-z0-9-]{0,7}\.example\.test", fullmatch=True)

    def _valid_service_doc(service_id: str, label: str, port: int, hostname: str, enabled: bool) -> dict:
        return {
            "label": label,
            "enabled": enabled,
            "runtime": {
                "type": "compose",
                "source": f"/var/lib/nas-control/apps/{service_id}/compose.yaml",
                "startPolicy": "boot",
            },
            "endpoints": {
                "web": {
                    "transport": "http",
                    "targetPort": port,
                    "exposure": {"type": "hostname", "value": hostname},
                    "auth": {"mode": "public"},
                }
            },
        }

    class ManagedServiceStateMachine(RuleBasedStateMachine):
        services_bundle = Bundle("services")

        def __init__(self):
            super().__init__()
            self._tmp = tempfile.TemporaryDirectory()
            self.builtin = pathlib.Path(self._tmp.name) / "builtin.json"
            self.store = pathlib.Path(self._tmp.name) / "store.json"
            self.effective_path = pathlib.Path(self._tmp.name) / "effective.json"
            self.portal_path = pathlib.Path(self._tmp.name) / "portal.json"
            self.builtin.write_text(json.dumps({"schemaVersion": 1, "endpoints": {}}), encoding="utf-8")
            msvc.atomic_write_store({"schemaVersion": 2, "services": {}}, self.store)
            self.model: dict[str, dict] = {}

        def teardown(self):
            self._tmp.cleanup()
            super().teardown()

        @rule(
            target=services_bundle,
            sid=st.from_regex(r"[a-z][a-z0-9-]{0,8}", fullmatch=True),
            label=st.text(
                min_size=1,
                max_size=12,
                alphabet=st.characters(
                    min_codepoint=33,
                    max_codepoint=126,
                    blacklist_characters="\x00\r\n/\\",
                ),
            ),
            port=st.integers(1024, 65535),
            hostname=SAFE_HOSTNAME,
            enabled=st.booleans(),
        )
        def add_service(self, sid: str, label: str, port: int, hostname: str, enabled: bool):
            assume(sid not in self.model)
            doc = _valid_service_doc(sid, label, port, hostname, enabled)
            self.model[sid] = doc
            self._write_model()
            return sid

        def _write_model(self) -> None:
            current = msvc.load_store(self.store)
            msvc.atomic_write_store(
                {
                    "schemaVersion": 2,
                    "services": json.loads(json.dumps(self.model)),
                    "generation": current.get("generation", 1),
                },
                self.store,
            )

        @rule(sid=services_bundle, port=st.integers(1, 65535))
        def modify_port(self, sid: str, port: int):
            assume(sid in self.model)
            self.model[sid]["endpoints"]["web"]["targetPort"] = port
            self._write_model()

        @rule(sid=services_bundle)
        def disable_service(self, sid: str):
            assume(sid in self.model)
            self.model[sid]["enabled"] = False
            self._write_model()

        @rule(sid=services_bundle)
        def enable_service(self, sid: str):
            assume(sid in self.model)
            self.model[sid]["enabled"] = True
            self._write_model()

        @rule(sid=services_bundle)
        def delete_service(self, sid: str):
            assume(sid in self.model)
            del self.model[sid]
            self._write_model()

        @rule()
        def reconcile(self):
            effective = msvc.write_effective(self.builtin, self.store, self.effective_path)
            portal = msvc.write_portal(self.effective_path, self.portal_path)
            self.assert_projection_files_match(effective, portal)

        def assert_projection_files_match(self, effective: dict, portal: dict) -> None:
            stored_effective = json.loads(self.effective_path.read_text(encoding="utf-8"))
            stored_portal = json.loads(self.portal_path.read_text(encoding="utf-8"))
            assert stored_effective == effective
            assert stored_portal == portal
            assert portal["generation"] == effective["generation"]

        @invariant()
        def effective_matches_store(self):
            effective = msvc.effective_registry(self.builtin, self.store)
            for sid, service in self.model.items():
                for endpoint_id, endpoint in (service.get("endpoints") or {}).items():
                    key = f"{sid}:{endpoint_id}"
                    assert key in effective["endpoints"], f"missing {key} in effective"
                    assert effective["endpoints"][key]["targetPort"] == endpoint["targetPort"]
                    assert effective["endpoints"][key]["available"] == service.get("enabled", False)
            for key in effective["endpoints"]:
                if ":" in key:
                    sid = key.split(":", 1)[0]
                    assert sid in self.model, f"stale endpoint {key}"

        @invariant()
        def portal_generation_matches_effective(self):
            effective = msvc.effective_registry(self.builtin, self.store)
            for endpoint in effective["endpoints"].values():
                endpoint.setdefault("portal", {})["visible"] = True
            portal = msvc.portal_projection(effective)
            assert portal["generation"] == effective.get("generation", 1)

        @invariant()
        def duplicate_exposures_fail_closed(self):
            effective = msvc.effective_registry(self.builtin, self.store)
            hostname_counts: dict[str, int] = {}
            for endpoint in effective["endpoints"].values():
                exposure = endpoint.get("exposure") or {}
                if exposure.get("type") == "hostname":
                    value = exposure.get("value")
                    hostname_counts[value] = hostname_counts.get(value, 0) + 1
            duplicates = any(count > 1 for count in hostname_counts.values())
            if duplicates:
                try:
                    caddy.generate_caddy_fragment(effective)
                except caddy.CaddyError:
                    return
                raise AssertionError("duplicate managed-service exposure did not fail closed")
            caddy.generate_caddy_fragment(effective)

        @invariant()
        def disabled_endpoints_are_not_reported_available(self):
            effective = msvc.effective_registry(self.builtin, self.store)
            for endpoint in effective["endpoints"].values():
                endpoint.setdefault("portal", {})["visible"] = True
            portal = msvc.portal_projection(effective)
            by_id = {entry["id"]: entry for entry in portal["entries"]}
            for sid, service in self.model.items():
                if service.get("enabled", False):
                    continue
                for endpoint_id in service.get("endpoints") or {}:
                    key = f"{sid}:{endpoint_id}"
                    if key in by_id:
                        assert not by_id[key]["available"], f"disabled {key} should not be available"

        @invariant()
        def rejected_write_preserves_previous_store(self):
            before = self.store.read_bytes()
            try:
                msvc.atomic_write_store({"schemaVersion": 99, "services": {}}, self.store)
            except msvc.ManagedServiceError:
                assert self.store.read_bytes() == before
            else:
                raise AssertionError("invalid schemaVersion unexpectedly committed")

    class StatefulTests(unittest.TestCase):
        @settings(
            max_examples=30,
            deadline=None,
            suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
            stateful_step_count=25,
        )
        def test_stateful_machine(self):
            run_state_machine_as_test(ManagedServiceStateMachine)

    class ProjectionDifferentialTests(unittest.TestCase):
        @settings(
            max_examples=80,
            deadline=None,
            suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
        )
        @given(
            st.lists(
                st.tuples(
                    st.from_regex(r"[a-z][a-z0-9-]{0,8}", fullmatch=True),
                    st.integers(1024, 65535),
                    SAFE_HOSTNAME,
                    st.booleans(),
                ),
                min_size=1,
                max_size=8,
                unique_by=lambda item: item[0],
            )
        )
        def test_effective_portal_caddy_describe_same_semantics(self, items):
            with tempfile.TemporaryDirectory() as tmp:
                builtin = pathlib.Path(tmp) / "builtin.json"
                store = pathlib.Path(tmp) / "store.json"
                builtin.write_text(json.dumps({"schemaVersion": 1, "endpoints": {}}), encoding="utf-8")
                services: dict[str, dict] = {}
                used_hostnames: set[str] = set()
                for sid, port, hostname, enabled in items:
                    # The differential test compares successful projections, so
                    # make each exposure unique. Duplicate-exposure rejection is
                    # covered independently by the state-machine invariant.
                    if hostname in used_hostnames:
                        hostname = f"{sid}.example.test"
                    used_hostnames.add(hostname)
                    services[sid] = _valid_service_doc(sid, sid, port, hostname, enabled)

                msvc.atomic_write_store({"schemaVersion": 2, "services": services}, store)
                effective = msvc.effective_registry(builtin, store)
                for endpoint in effective["endpoints"].values():
                    endpoint.setdefault("portal", {})["visible"] = True
                portal = msvc.portal_projection(effective)
                fragment = caddy.generate_caddy_fragment(effective)
                by_portal = {entry["id"]: entry for entry in portal["entries"]}
                route_ids = {route["id"] for route in fragment["routes"]}

                for sid, service in services.items():
                    key = f"{sid}:web"
                    self.assertIn(key, effective["endpoints"])
                    enabled = service["enabled"]
                    self.assertEqual(effective["endpoints"][key]["available"], enabled)
                    self.assertIn(key, by_portal)
                    self.assertEqual(by_portal[key]["available"], enabled)
                    self.assertIn(f"nas-managed-{sid}-web", route_ids)

else:

    @unittest.skip("Hypothesis is not installed; CI runs this file in the slow property tier")
    class StatefulTests(unittest.TestCase):
        def test_hypothesis_required(self):
            pass

    @unittest.skip("Hypothesis is not installed; CI runs this file in the slow property tier")
    class ProjectionDifferentialTests(unittest.TestCase):
        def test_hypothesis_required(self):
            pass


if __name__ == "__main__":
    unittest.main()
