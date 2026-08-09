from __future__ import annotations

import pathlib
import sys
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_managed_service_dependencies as deps  # noqa: E402


def service(*, ownership: str = "v2", mode: str = "persistent", depends_on: list[str] | None = None) -> dict:
    lifecycle = {"mode": mode}
    if mode == "on-demand":
        lifecycle["idleSeconds"] = 600
    return {
        "label": "Service",
        "enabled": True,
        "ownership": ownership,
        "lifecycle": lifecycle,
        "dependsOn": list(depends_on or []),
        "runtime": {"type": "systemd", "units": ["example.service"]},
    }


class ManagedServiceDependencyTests(unittest.TestCase):
    def test_dependency_graph_rejects_missing_reference_and_cycle(self) -> None:
        with self.assertRaisesRegex(Exception, "unknown dependency"):
            deps._validate_dependency_graph({"app": service(depends_on=["missing"])})

        graph = {
            "alpha": service(depends_on=["beta"]),
            "beta": service(depends_on=["alpha"]),
        }
        with self.assertRaisesRegex(Exception, "dependency cycle"):
            deps._validate_dependency_graph(graph)

    def test_dependency_order_is_topological(self) -> None:
        services = {
            "core": service(ownership="system"),
            "database": service(depends_on=["core"]),
            "app": service(depends_on=["database"]),
        }
        self.assertEqual(deps.dependency_order("app", services), ["core", "database", "app"])

    def test_start_service_starts_system_and_v2_dependencies_first(self) -> None:
        services = {
            "identity": service(ownership="system"),
            "model": service(mode="on-demand", depends_on=["identity"]),
            "ui": service(mode="on-demand", depends_on=["model"]),
        }
        effective = {"services": services}
        calls: list[tuple[str, bool]] = []

        def apply_runtime(service_id: str, _service: dict, *, enabled: bool) -> dict:
            calls.append((service_id, enabled))
            return {"service": service_id, "enabled": enabled}

        with (
            mock.patch.object(deps, "effective_registry", return_value=effective),
            mock.patch.object(deps._v2, "_apply_runtime", side_effect=apply_runtime),
            mock.patch.object(deps, "_touch_chain", return_value={"model": {}, "ui": {}}),
        ):
            result = deps.start_service("ui")

        self.assertEqual(calls, [("identity", True), ("model", True), ("ui", True)])
        self.assertEqual(result["order"], ["identity", "model", "ui"])
        self.assertEqual(result["touched"], ["model", "ui"])

    def test_touch_service_refreshes_on_demand_dependencies_together(self) -> None:
        services = {
            "model": service(mode="on-demand"),
            "ui": service(mode="on-demand", depends_on=["model"]),
        }
        state = {"schemaVersion": 1, "services": {}}
        written: list[dict] = []
        with (
            mock.patch.object(deps, "effective_registry", return_value={"services": services}),
            mock.patch.object(deps._v2, "_read_lifecycle_state", return_value=state),
            mock.patch.object(deps._v2, "_write_lifecycle_state", side_effect=lambda value: written.append(value)),
        ):
            deps.touch_service("ui", now=1234)

        self.assertEqual(state["services"]["model"]["lastAccess"], 1234)
        self.assertEqual(state["services"]["ui"]["lastAccess"], 1234)
        self.assertEqual(len(written), 1)

    def test_reaper_retains_dependency_while_dependent_is_active(self) -> None:
        services = {
            "model": service(mode="on-demand"),
            "ui": service(mode="on-demand", depends_on=["model"]),
        }
        state = {
            "schemaVersion": 1,
            "services": {
                "model": {"lastAccess": 100},
                "ui": {"lastAccess": 950},
            },
        }
        with (
            mock.patch.object(deps, "effective_registry", return_value={"services": services}),
            mock.patch.object(deps._v2, "_read_lifecycle_state", return_value=state),
            mock.patch.object(deps._v2, "_apply_runtime") as apply_runtime,
        ):
            result = deps.reap_lifecycle(now=1000)

        self.assertEqual(result["retainedForDependents"], ["model"])
        self.assertEqual(result["stopped"], [])
        apply_runtime.assert_not_called()


if __name__ == "__main__":
    unittest.main()
