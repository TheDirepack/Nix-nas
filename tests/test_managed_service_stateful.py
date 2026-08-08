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

    def _valid_service_doc(service_id: str, label: str, port: int, hostname: str, enabled: bool) -> dict:
        return {
            "label": label,
            "enabled": enabled,
            "runtime": {"type": "compose", "source": f"/var/lib/nas-control/apps/{service_id}/compose.yaml", "startPolicy": "boot"},
            "endpoints": {
                "web": {"transport": "http", "targetPort": port, "exposure": {"type": "hostname", "value": hostname}, "auth": {"mode": "public"}}
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
            self.builtin.write_text(json.dumps({"schemaVersion": 1, "endpoints": {}}))
            msvc.atomic_write_store({"schemaVersion": 2, "services": {}}, self.store)
            self.model: dict[str, dict] = {}
            self.generation: int = 1

        def teardown(self):
            self._tmp.cleanup()
            super().teardown()

        @rule(target=services_bundle, sid=st.from_regex(r"[a-z][a-z0-9-]{0,8}", fullmatch=True), label=st.text(min_size=1, max_size=12, alphabet=st.characters(min_codepoint=33, max_codepoint=126, blacklist_characters="\x00\r\n/\\")), port=st.integers(1024, 65535), hostname=st.from_regex(r"[a-z0-9-]{1,8}\.local", fullmatch=True), enabled=st.booleans())
        def add_service(self, sid: str, label: str, port: int, hostname: str, enabled: bool):
            assume(sid not in self.model)
            doc = _valid_service_doc(sid, label, port, hostname, enabled)
            self.model[sid] = doc
            data = {"schemaVersion": 2, "services": dict(self.model), "generation": self.generation}
            msvc.atomic_write_store(data, self.store)
            return sid

        @rule(sid=services_bundle, port=st.integers(1, 65535))
        def modify_port(self, sid: str, port: int):
            assume(sid in self.model)
            self.model[sid]["endpoints"]["web"]["targetPort"] = port
            data = {"schemaVersion": 2, "services": dict(self.model), "generation": self.generation}
            try:
                msvc.atomic_write_store(data, self.store)
            except msvc.ManagedServiceError:
                self.model[sid]["endpoints"]["web"]["targetPort"] = 8080
                raise

        @rule(sid=services_bundle)
        def disable_service(self, sid: str):
            assume(sid in self.model)
            self.model[sid]["enabled"] = False
            data = {"schemaVersion": 2, "services": dict(self.model), "generation": self.generation}
            msvc.atomic_write_store(data, self.store)

        @rule(sid=services_bundle)
        def enable_service(self, sid: str):
            assume(sid in self.model)
            self.model[sid]["enabled"] = True
            data = {"schemaVersion": 2, "services": dict(self.model), "generation": self.generation}
            msvc.atomic_write_store(data, self.store)

        @rule(sid=services_bundle)
        def delete_service(self, sid: str):
            assume(sid in self.model)
            del self.model[sid]
            data = {"schemaVersion": 2, "services": dict(self.model), "generation": self.generation}
            msvc.atomic_write_store(data, self.store)

        @rule()
        def reconcile(self):
            self.generation += 1
            data = {"schemaVersion": 2, "services": dict(self.model), "generation": self.generation}
            msvc.atomic_write_store(data, self.store)
            eff = msvc.effective_registry(self.builtin, self.store)
            msvc.write_effective(self.builtin, self.store, self.effective_path)
            stored_eff = json.loads(self.effective_path.read_text(encoding="utf-8"))
            self.generation = stored_eff.get("generation", self.generation)

        @invariant()
        def effective_matches_store(self):
            eff = msvc.effective_registry(self.builtin, self.store)
            for sid, svc in self.model.items():
                for eid, ep in (svc.get("endpoints") or {}).items():
                    key = f"{sid}:{eid}"
                    assert key in eff["endpoints"], f"missing {key} in effective"
                    assert eff["endpoints"][key]["targetPort"] == ep["targetPort"]
                    assert eff["endpoints"][key]["available"] == svc.get("enabled", False)
            for key in list(eff["endpoints"].keys()):
                if ":" in key:
                    sid = key.split(":")[0]
                    assert sid in self.model, f"stale endpoint {key}"

        @invariant()
        def portal_generation_matches_effective(self):
            eff = msvc.effective_registry(self.builtin, self.store)
            for k, ep in list(eff["endpoints"].items()):
                ep.setdefault("portal", {})["visible"] = True
            portal = msvc.portal_projection(eff)
            assert portal["generation"] == eff.get("generation", 1)

        @invariant()
        def no_duplicate_exposure_in_caddy(self):
            eff = msvc.effective_registry(self.builtin, self.store)
            seen: set[str] = set()
            for key, ep in eff["endpoints"].items():
                exp = ep.get("exposure") or {}
                if exp.get("type") == "hostname":
                    val = exp.get("value")
                    if val in seen:
                        try:
                            caddy.generate_caddy_fragment(eff)
                        except ValueError:
                            return
                        assert False, "expected duplicate exposure ValueError"
                    seen.add(val)

        @invariant()
        def disabled_not_reachable_as_available(self):
            eff = msvc.effective_registry(self.builtin, self.store)
            for k, ep in list(eff["endpoints"].items()):
                ep.setdefault("portal", {})["visible"] = True
            portal = msvc.portal_projection(eff)
            by_id = {e["id"]: e for e in portal["entries"]}
            for sid, svc in self.model.items():
                enabled = svc.get("enabled", False)
                if not enabled:
                    for eid in (svc.get("endpoints") or {}):
                        key = f"{sid}:{eid}"
                        if key in by_id:
                            assert not by_id[key]["available"], f"disabled {key} should not be available"

        @invariant()
        def delete_removes_artifacts(self):
            eff = msvc.effective_registry(self.builtin, self.store)
            for key in list(eff["endpoints"].keys()):
                if ":" in key:
                    sid = key.split(":")[0]
                    assert sid in self.model, f"stale endpoint {key}"

        @invariant()
        def failed_generation_leaves_previous(self):
            before_text = self.store.read_text(encoding="utf-8")
            bad = {"schemaVersion": 99, "services": {}}
            try:
                msvc.atomic_write_store(bad, self.store)  # type: ignore
            except msvc.ManagedServiceError:
                after_text = self.store.read_text(encoding="utf-8")
                assert before_text == after_text
            else:
                assert False, "expected ManagedServiceError for bad schemaVersion"

    class StatefulTests(unittest.TestCase):
        @settings(max_examples=30, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large], stateful_step_count=25)
        def test_stateful_machine(self):
            run_state_machine_as_test(ManagedServiceStateMachine)

    class ProjectionDifferentialTests(unittest.TestCase):
        @settings(max_examples=80, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])
        @given(st.lists(st.tuples(st.from_regex(r"[a-z][a-z0-9-]{0,8}", fullmatch=True), st.integers(1024, 65535), st.from_regex(r"[a-z0-9-]{1,8}\.local", fullmatch=True), st.booleans()), min_size=1, max_size=8, unique_by=lambda x: x[0]))
        def test_effective_portal_caddy_describe_same_semantics(self, items):
            with tempfile.TemporaryDirectory() as tmp:
                builtin = pathlib.Path(tmp) / "builtin.json"
                store = pathlib.Path(tmp) / "store.json"
                builtin.write_text(json.dumps({"schemaVersion": 1, "endpoints": {}}))
                services: dict[str, dict] = {}
                for sid, port, hostname, enabled in items:
                    services[sid] = {
                        "label": sid,
                        "enabled": enabled,
                        "runtime": {"type": "compose", "source": f"/var/lib/nas-control/apps/{sid}/compose.yaml", "startPolicy": "boot"},
                        "endpoints": {
                            "web": {"transport": "http", "targetPort": port, "exposure": {"type": "hostname", "value": f"{sid}.local" if hostname else "x.local"}, "auth": {"mode": "public"}}
                        },
                    }
                msvc.atomic_write_store({"schemaVersion": 2, "services": services}, store)
                eff = msvc.effective_registry(builtin, store)
                for k, ep in list(eff["endpoints"].items()):
                    ep.setdefault("portal", {})["visible"] = True
                portal = msvc.portal_projection(eff)
                fragment = caddy.generate_caddy_fragment(eff)
                by_portal = {e["id"]: e for e in portal["entries"]}
                route_ids = {r["id"] for r in fragment["routes"]}
                for sid, svc in services.items():
                    key = f"{sid}:web"
                    enabled = svc.get("enabled", False)
                    in_effective = key in eff["endpoints"]
                    self.assertEqual(in_effective, True)
                    self.assertEqual(eff["endpoints"][key]["available"], enabled)
                    if not enabled:
                        if key in by_portal:
                            self.assertFalse(by_portal[key]["available"])
                    else:
                        if key in by_portal:
                            self.assertTrue(by_portal[key]["available"])
                    caddy_has = f"nas-managed-{key.replace(':', '-')}" in route_ids
                    if enabled:
                        self.assertIn(f"nas-managed-{key.replace(':', '-')}", route_ids)
                    else:
                        pass
                for eid in eff["endpoints"]:
                    if ":" in eid:
                        sid = eid.split(":")[0]
                        svc = services.get(sid)
                        if svc and not svc.get("enabled", False):
                            if eid in by_portal:
                                self.assertFalse(by_portal[eid]["available"])

else:

    @unittest.skip("Hypothesis is not installed")
    class StatefulTests(unittest.TestCase):
        def test_placeholder(self):
            pass

    @unittest.skip("Hypothesis is not installed")
    class ProjectionDifferentialTests(unittest.TestCase):
        def test_placeholder(self):
            pass


if __name__ == "__main__":
    unittest.main()
