from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest
from email.message import Message
from types import SimpleNamespace
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))
MODULE_PATH = ROOT / "services" / "nas_feature_control.py"
SPEC = importlib.util.spec_from_file_location("nas_feature_control", MODULE_PATH)
assert SPEC and SPEC.loader
features = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = features
SPEC.loader.exec_module(features)

common = importlib.import_module("nas_common")


class FeatureControlTests(unittest.TestCase):
    def test_catalog_root_must_be_an_object(self):
        for value in (None, [], "catalog", 1, True):
            with self.subTest(value=value):
                with self.assertRaises(features.FeatureError):
                    features.normalize_catalog(value)

    def catalog(self):
        return features.normalize_catalog(
            {
                "schemaVersion": 2,
                "features": {
                    "parent": {
                        "available": True,
                        "allowedModes": ["off", "on-demand", "always"],
                        "defaultMode": "on-demand",
                        "idleSeconds": 60,
                        "startUnits": ["parent.service"],
                    },
                    "child": {
                        "available": True,
                        "allowedModes": ["off", "on-demand", "always"],
                        "defaultMode": "on-demand",
                        "idleSeconds": 30,
                        "parent": "parent",
                        "startUnits": ["child.service"],
                    },
                    "missing": {
                        "available": False,
                        "allowedModes": ["off", "always"],
                        "defaultMode": "off",
                        "startUnits": ["missing.service"],
                    },
                },
                "memoryComponents": [
                    {"id": "base", "label": "Base", "minMiB": 10, "typicalMiB": 20, "maxMiB": 30, "units": []},
                    {
                        "id": "child",
                        "label": "Child",
                        "feature": "child",
                        "minMiB": 5,
                        "typicalMiB": 8,
                        "maxMiB": 12,
                        "units": ["child.service"],
                    },
                ],
            }
        )

    def test_parent_off_disables_child_effectively(self):
        catalog = self.catalog()
        state = features.default_state(catalog)
        state["features"]["parent"] = "off"
        report = features.status(catalog, state)
        by_id = {entry["id"]: entry for entry in report["features"]}
        self.assertEqual(by_id["parent"]["effectiveMode"], "off")
        self.assertEqual(by_id["child"]["effectiveMode"], "off")
        self.assertEqual(report["memory"]["residentEstimateMiB"]["typical"], 20)

    def test_load_state_migrates_boolean_true_to_catalog_policy(self):
        catalog = self.catalog()
        catalog["features"]["parent"]["legacyTrueMode"] = "on-demand"
        with tempfile.TemporaryDirectory() as tmp:
            state_path = pathlib.Path(tmp) / "settings.json"
            last_good_path = pathlib.Path(tmp) / "settings.last-good.json"
            state_path.write_text(json.dumps({"schemaVersion": 1, "features": {"parent": True}, "updatedAt": 1}))
            with (
                mock.patch.object(features, "STATE_PATH", state_path),
                mock.patch.object(features, "LAST_GOOD_PATH", last_good_path),
            ):
                state = features.load_state(catalog)
            self.assertEqual(state["features"]["parent"], "on-demand")
            self.assertEqual(state["features"]["child"], "on-demand")
            self.assertEqual(state["features"]["missing"], "off")
            self.assertEqual(json.loads(state_path.read_text())["schemaVersion"], 2)

    def test_apply_stops_on_demand_at_boot_and_starts_always_parent_before_child(self):
        catalog = self.catalog()
        state = features.default_state(catalog)
        calls: list[tuple[str, list[str]]] = []
        active_snapshot = {
            "parent.service": {"ActiveState": "active"},
            "child.service": {"ActiveState": "active"},
            "missing.service": {"ActiveState": "inactive"},
        }
        with (
            mock.patch.object(features, "systemd_unit_snapshot", return_value=active_snapshot),
            mock.patch.object(features, "stop_units", side_effect=lambda units: calls.append(("stop", units)) or []),
            mock.patch.object(features, "start_units", side_effect=lambda units: calls.append(("start", units)) or []),
        ):
            features.apply(catalog, state, strict=True, preserve_on_demand=False)
        self.assertEqual(calls, [("stop", ["child.service"]), ("stop", ["parent.service"])])

        calls.clear()
        state["features"]["child"] = "always"
        inactive_snapshot = {
            "parent.service": {"ActiveState": "inactive"},
            "child.service": {"ActiveState": "inactive"},
            "missing.service": {"ActiveState": "inactive"},
        }
        with (
            mock.patch.object(features, "systemd_unit_snapshot", return_value=inactive_snapshot),
            mock.patch.object(features, "stop_units", side_effect=lambda units: calls.append(("stop", units)) or []),
            mock.patch.object(features, "start_units", side_effect=lambda units: calls.append(("start", units)) or []),
        ):
            result = features.apply(catalog, state, strict=True)
        self.assertEqual(calls, [("start", ["parent.service"]), ("start", ["child.service"])])
        self.assertEqual(result["persistent"], ["child", "parent"])

    def test_switching_running_service_to_on_demand_arms_idle_deadline(self):
        catalog = self.catalog()
        state = features.default_state(catalog)
        state["features"]["parent"] = "always"
        with tempfile.TemporaryDirectory() as tmp:
            state_path = pathlib.Path(tmp) / "settings.json"
            runtime_path = pathlib.Path(tmp) / "runtime.json"
            features.atomic_write_json(state_path, state)
            journal_path = pathlib.Path(tmp) / "transaction.json"
            last_good_path = pathlib.Path(tmp) / "last-good.json"
            with (
                mock.patch.object(features, "STATE_PATH", state_path),
                mock.patch.object(features, "RUNTIME_PATH", runtime_path),
                mock.patch.object(features, "JOURNAL_PATH", journal_path),
                mock.patch.object(features, "LAST_GOOD_PATH", last_good_path),
                mock.patch.object(
                    features, "systemd_unit_snapshot", return_value={"parent.service": {"ActiveState": "active"}}
                ),
                mock.patch.object(features, "apply", return_value={"ok": True}),
            ):
                features.set_mode(catalog, state, "parent", "on-demand")
            runtime = json.loads(runtime_path.read_text())
            self.assertGreater(runtime["features"]["parent"]["lastAccess"], 0)

    def test_failed_mode_change_restores_previous_runtime_and_state(self):
        catalog = self.catalog()
        state = features.default_state(catalog)
        with tempfile.TemporaryDirectory() as tmp:
            state_path = pathlib.Path(tmp) / "settings.json"
            features.atomic_write_json(state_path, state)
            journal_path = pathlib.Path(tmp) / "transaction.json"
            last_good_path = pathlib.Path(tmp) / "last-good.json"
            with (
                mock.patch.object(features, "STATE_PATH", state_path),
                mock.patch.object(features, "JOURNAL_PATH", journal_path),
                mock.patch.object(features, "LAST_GOOD_PATH", last_good_path),
                mock.patch.object(
                    features, "capture_runtime_snapshot", return_value={"parent.service": False, "child.service": False}
                ),
                mock.patch.object(features, "restore_runtime_snapshot", return_value={"ok": True}) as restore,
                mock.patch.object(features, "apply", side_effect=features.FeatureError("start failed")) as apply_mock,
            ):
                with self.assertRaises(features.FeatureError):
                    features.set_mode(catalog, state, "parent", "always")
                calls = [call.args[1]["features"]["parent"] for call in apply_mock.call_args_list]
            self.assertEqual(calls, ["always"])
            restore.assert_called_once_with(catalog, {"parent.service": False, "child.service": False})
            self.assertEqual(json.loads(state_path.read_text())["features"]["parent"], "on-demand")
            self.assertEqual(state["features"]["parent"], "on-demand")

    def test_unavailable_or_unsupported_mode_is_rejected(self):
        catalog = self.catalog()
        state = features.default_state(catalog)
        with self.assertRaises(features.FeatureError):
            features.set_mode(catalog, state, "missing", "always")
        with self.assertRaises(features.FeatureError):
            features.set_mode(catalog, state, "missing", "on-demand")

    def test_wake_starts_dependency_chain_and_records_start_duration(self):
        catalog = self.catalog()
        state = features.default_state(catalog)
        with tempfile.TemporaryDirectory() as tmp:
            runtime_path = pathlib.Path(tmp) / "runtime.json"
            with (
                mock.patch.object(features, "RUNTIME_PATH", runtime_path),
                mock.patch.object(features, "unit_active", return_value=False),
                mock.patch.object(features, "start_units", return_value=[]),
                mock.patch.object(features, "wait_ready", return_value=None),
            ):
                result = features.wake_feature(catalog, state, "child")
            self.assertEqual(result["chain"], ["parent", "child"])
            runtime = json.loads(runtime_path.read_text())
            self.assertIn("lastAccess", runtime["features"]["parent"])
            self.assertIn("lastStartDurationMs", runtime["features"]["child"])

    def test_reaper_stops_expired_child_before_parent(self):
        catalog = self.catalog()
        state = features.default_state(catalog)
        with tempfile.TemporaryDirectory() as tmp:
            runtime_path = pathlib.Path(tmp) / "runtime.json"
            features.atomic_write_json(
                runtime_path,
                {
                    "schemaVersion": 1,
                    "features": {"parent": {"lastAccess": 1}, "child": {"lastAccess": 1}},
                },
            )
            active = {"parent.service": True, "child.service": True}
            stopped: list[list[str]] = []

            def stop(units):
                stopped.append(list(units))
                for unit in units:
                    active[unit] = False
                return [{"unit": unit, "action": "stop", "ok": True, "error": ""} for unit in units]

            with (
                mock.patch.object(features, "RUNTIME_PATH", runtime_path),
                mock.patch.object(
                    features,
                    "systemd_unit_snapshot",
                    return_value={
                        unit: {"ActiveState": "active" if enabled else "inactive"} for unit, enabled in active.items()
                    },
                ),
                mock.patch.object(features, "stop_units", side_effect=stop),
                mock.patch.object(features, "established_on_ports", return_value=False),
            ):
                result = features.reap(catalog, state, now=1000)
            self.assertEqual(result["stopped"], ["child", "parent"])
            self.assertEqual(stopped, [["child.service"], ["parent.service"]])

    def test_catalog_rejects_cycles_non_loopback_health_and_invalid_probes(self):
        with self.assertRaisesRegex(features.FeatureError, "cycle"):
            features.normalize_catalog(
                {
                    "schemaVersion": 2,
                    "features": {
                        "a": {
                            "available": True,
                            "allowedModes": ["off", "always"],
                            "defaultMode": "always",
                            "parent": "b",
                            "startUnits": [],
                        },
                        "b": {
                            "available": True,
                            "allowedModes": ["off", "always"],
                            "defaultMode": "always",
                            "parent": "a",
                            "startUnits": [],
                        },
                    },
                }
            )
        with self.assertRaisesRegex(features.FeatureError, "loopback plain HTTP"):
            features.normalize_catalog(
                {
                    "schemaVersion": 2,
                    "features": {
                        "x": {
                            "available": True,
                            "allowedModes": ["off", "always"],
                            "defaultMode": "always",
                            "healthUrl": "https://example.com/",
                            "startUnits": [],
                        }
                    },
                }
            )
        with self.assertRaisesRegex(features.FeatureError, "absolute path"):
            features.normalize_catalog(
                {
                    "schemaVersion": 2,
                    "features": {
                        "x": {
                            "available": True,
                            "allowedModes": ["off", "always"],
                            "defaultMode": "always",
                            "availabilityProbe": {"type": "path", "path": "relative"},
                            "startUnits": [],
                        }
                    },
                }
            )

    def test_load_state_rejects_explicit_null_and_runtime_probe_is_reported(self):
        catalog = self.catalog()
        with tempfile.TemporaryDirectory() as tmp:
            state_path = pathlib.Path(tmp) / "settings.json"
            state_path.write_text(json.dumps({"schemaVersion": 2, "features": {"parent": None}}))
            with mock.patch.object(features, "STATE_PATH", state_path):
                with self.assertRaisesRegex(features.FeatureError, "malformed"):
                    features.load_state(catalog)

            missing = pathlib.Path(tmp) / "missing-device"
            catalog["features"]["parent"]["availabilityProbe"] = {
                "type": "path",
                "path": str(missing),
                "description": "device missing",
            }
            state = features.default_state(catalog)
            with (
                mock.patch.object(features, "unit_active", return_value=False),
                mock.patch.object(features, "unit_memory_bytes", return_value=None),
                mock.patch.object(features, "meminfo", return_value={}),
            ):
                report = features.status(catalog, state)
            parent = next(item for item in report["features"] if item["id"] == "parent")
            self.assertFalse(parent["runtimeAvailable"])
            self.assertEqual(parent["availabilityReason"], "device missing")

    def test_feature_graph_precomputes_depth_and_descendants(self):
        graph = self.catalog()["features"]
        depths, descendants = features.feature_graph(graph)
        self.assertEqual(depths["parent"], 0)
        self.assertEqual(depths["child"], 1)
        self.assertEqual(descendants["parent"], ["child"])

    def test_schema_contract_rejects_unknown_catalog_fields(self):
        catalog = {
            "schemaVersion": 2,
            "features": {
                "x": {
                    "available": True,
                    "allowedModes": ["off", "always"],
                    "defaultMode": "always",
                    "startUnits": [],
                    "healthPorts": [1234],
                }
            },
        }
        with self.assertRaisesRegex(features.FeatureError, "unknown field.*healthPorts"):
            features.normalize_catalog(catalog)

    def test_status_batches_systemd_state_and_memory_queries(self):
        catalog = self.catalog()
        state = features.default_state(catalog)
        output = (
            "Id=parent.service\nActiveState=active\nMemoryCurrent=1048576\n\n"
            "Id=child.service\nActiveState=inactive\nMemoryCurrent=[not set]\n\n"
            "Id=missing.service\nActiveState=inactive\nMemoryCurrent=[not set]\n"
        )
        with (
            mock.patch.object(
                features,
                "run",
                return_value=features.CommandResult(0, output, ""),
            ) as command,
            mock.patch.object(features, "meminfo", return_value={}),
        ):
            report = features.status(catalog, state)
        command.assert_called_once()
        args = command.call_args.args[0]
        self.assertEqual(args[:3], ["systemctl", "show", "--property=Id,ActiveState,SubState,Result,MemoryCurrent"])
        by_id = {entry["id"]: entry for entry in report["features"]}
        self.assertTrue(by_id["parent"]["running"])
        self.assertEqual(by_id["parent"]["units"][0]["memoryBytes"], 1048576)
        self.assertFalse(by_id["child"]["running"])

    def test_missing_state_uses_typed_exception_without_message_matching(self):
        catalog = self.catalog()
        with tempfile.TemporaryDirectory() as tmp:
            state_path = pathlib.Path(tmp) / "missing.json"
            last_good_path = pathlib.Path(tmp) / "settings.last-good.json"
            with (
                mock.patch.object(features, "STATE_PATH", state_path),
                mock.patch.object(features, "LAST_GOOD_PATH", last_good_path),
            ):
                state = features.load_state(catalog)
            self.assertTrue(state_path.exists())
            self.assertEqual(state["schemaVersion"], 2)
        with self.assertRaises(features.FeatureFileMissingError):
            features.read_json(pathlib.Path(tmp) / "still-missing.json")

    def test_capability_only_gate_does_not_touch_feature_state(self):
        class FakeHandler:
            path = "/authorize?scope=webdav"
            headers = Message()

            def __init__(self):
                self.responses = []
                self.headers["Remote-User"] = "alice"
                self.headers["Remote-Groups"] = f"{common.USER_GROUP},nas_allow_webdav"

            def respond(self, status, body=""):
                self.responses.append((status, body))

        handler = FakeHandler()
        with mock.patch.object(features, "load_catalog", side_effect=AssertionError("must not load catalog")):
            features.GateHandler.do_GET(handler)
        self.assertEqual(handler.responses, [(features.HTTPStatus.NO_CONTENT, "")])

        handler = FakeHandler()
        handler.headers.replace_header("Remote-Groups", common.USER_GROUP)
        features.GateHandler.do_GET(handler)
        self.assertEqual(handler.responses[0][0], features.HTTPStatus.FORBIDDEN)

    def test_admin_and_ai_gate_permissions_fail_closed(self):
        headers = Message()
        headers["Remote-User"] = "alice"
        headers["Remote-Groups"] = common.USER_GROUP
        self.assertFalse(features.authorize({"access": "ai"}, headers))
        headers.replace_header("Remote-Groups", f"{common.USER_GROUP},{features.AI_ALLOW_GROUP}")
        self.assertTrue(features.authorize({"access": "ai"}, headers))
        self.assertFalse(features.authorize({"access": "admin"}, headers))
        headers.replace_header(
            "Remote-Groups", f"{common.USER_GROUP},{features.AI_ALLOW_GROUP},{features.DISABLED_GROUP}"
        )
        self.assertFalse(features.authorize({"access": "ai"}, headers))
        with tempfile.TemporaryDirectory() as tmp:
            key_file = pathlib.Path(tmp) / "llama.env"
            key_file.write_text("LLAMA_SWAP_API_KEY=test-secret-key\n")
            api_headers = Message()
            api_headers["Authorization"] = "Bearer test-secret-key"
            with mock.patch.object(features, "AI_API_KEY_FILE", key_file):
                self.assertTrue(features.authorize({"access": "admin"}, api_headers, "ai-api"))
                api_headers.replace_header("Authorization", "Bearer wrong")
                self.assertFalse(features.authorize({"access": "admin"}, api_headers, "ai-api"))

    def test_partial_start_failure_rolls_back_every_successful_unit(self):
        catalog = self.catalog()
        state = features.default_state(catalog)
        state["features"]["child"] = "always"
        starts = [
            {"unit": "parent.service", "action": "start", "ok": True, "error": ""},
            {"unit": "child.service", "action": "start", "ok": False, "error": "boom"},
        ]
        with (
            mock.patch.object(
                features,
                "systemd_unit_snapshot",
                return_value={
                    "parent.service": {"ActiveState": "inactive"},
                    "child.service": {"ActiveState": "inactive"},
                },
            ),
            mock.patch.object(features, "start_units", return_value=starts),
            mock.patch.object(features, "stop_units", return_value=[]) as stop,
        ):
            with self.assertRaisesRegex(features.FeatureError, "child.service"):
                features.wake_feature(catalog, state, "child")
        stop.assert_called_once_with(["parent.service"])

    def test_persistence_failure_rolls_runtime_back_and_keeps_previous_state(self):
        catalog = self.catalog()
        state = features.default_state(catalog)
        candidate = json.loads(json.dumps(state))
        candidate["features"]["parent"] = "always"
        with tempfile.TemporaryDirectory() as tmp:
            state_path = pathlib.Path(tmp) / "settings.json"
            journal_path = pathlib.Path(tmp) / "transaction.json"
            last_good_path = pathlib.Path(tmp) / "last-good.json"
            features.atomic_write_json(state_path, state)
            real_write = features.atomic_write_json
            calls = []

            def fail_candidate(path, value, mode=0o644):
                if path == state_path and value == candidate:
                    raise OSError("disk full")
                return real_write(path, value, mode)

            with (
                mock.patch.object(features, "STATE_PATH", state_path),
                mock.patch.object(features, "JOURNAL_PATH", journal_path),
                mock.patch.object(features, "LAST_GOOD_PATH", last_good_path),
                mock.patch.object(
                    features,
                    "apply",
                    side_effect=lambda _catalog, value, **_kwargs: (
                        calls.append(value["features"]["parent"]) or {"ok": True, "failures": []}
                    ),
                ),
                mock.patch.object(
                    features, "capture_runtime_snapshot", return_value={"parent.service": False, "child.service": False}
                ),
                mock.patch.object(features, "restore_runtime_snapshot", return_value={"ok": True}),
                mock.patch.object(features, "atomic_write_json", side_effect=fail_candidate),
            ):
                with self.assertRaisesRegex(features.FeatureError, "rolled back"):
                    features.commit_state_transactionally(catalog, state, candidate)
            self.assertEqual(calls, ["always"])
            self.assertEqual(json.loads(state_path.read_text())["features"]["parent"], "on-demand")
            self.assertFalse(journal_path.exists())

    def test_persistence_failure_plus_runtime_rollback_failure_requires_manual_recovery(self):
        catalog = self.catalog()
        state = features.default_state(catalog)
        candidate = json.loads(json.dumps(state))
        candidate["features"]["parent"] = "always"
        with tempfile.TemporaryDirectory() as tmp:
            state_path = pathlib.Path(tmp) / "settings.json"
            journal_path = pathlib.Path(tmp) / "transaction.json"
            last_good_path = pathlib.Path(tmp) / "last-good.json"
            features.atomic_write_json(state_path, state)
            real_write = features.atomic_write_json

            def fail_candidate(path, value, mode=0o644):
                if path == state_path and value == candidate:
                    raise OSError("disk full")
                return real_write(path, value, mode)

            with (
                mock.patch.object(features, "STATE_PATH", state_path),
                mock.patch.object(features, "JOURNAL_PATH", journal_path),
                mock.patch.object(features, "LAST_GOOD_PATH", last_good_path),
                mock.patch.object(features, "apply", return_value={"ok": True, "failures": []}),
                mock.patch.object(
                    features, "capture_runtime_snapshot", return_value={"parent.service": False, "child.service": False}
                ),
                mock.patch.object(
                    features, "restore_runtime_snapshot", side_effect=features.FeatureError("restart rollback failed")
                ),
                mock.patch.object(features, "atomic_write_json", side_effect=fail_candidate),
            ):
                with self.assertRaisesRegex(features.FeatureError, "rollback was incomplete"):
                    features.commit_state_transactionally(catalog, state, candidate)
            journal = json.loads(journal_path.read_text(encoding="utf-8"))
            self.assertEqual(journal["phase"], "manual-recovery-required")
            self.assertTrue(any("restart rollback failed" in item for item in journal["rollbackErrors"]))
            self.assertEqual(json.loads(state_path.read_text())["features"]["parent"], "on-demand")

    def test_status_reports_degraded_partial_stack_and_observed_memory(self):
        catalog = self.catalog()
        catalog["features"]["parent"]["startUnits"] = ["parent-a.service", "parent-b.service"]
        catalog["memoryComponents"][1]["units"] = ["parent-a.service"]
        state = features.default_state(catalog)
        snapshot = {
            "parent-a.service": {"ActiveState": "active", "MemoryCurrent": "1024"},
            "parent-b.service": {"ActiveState": "inactive", "MemoryCurrent": "[not set]"},
            "child.service": {"ActiveState": "inactive", "MemoryCurrent": "[not set]"},
            "missing.service": {"ActiveState": "inactive", "MemoryCurrent": "[not set]"},
        }
        with (
            mock.patch.object(features, "systemd_unit_snapshot", return_value=snapshot),
            mock.patch.object(features, "meminfo", return_value={}),
        ):
            report = features.status(catalog, state)
        parent = next(item for item in report["features"] if item["id"] == "parent")
        self.assertEqual(parent["healthState"], "degraded")
        memory = next(item for item in report["memory"]["components"] if item["id"] == "child")
        self.assertTrue(memory["activeObserved"])
        self.assertFalse(memory["residentExpected"])

    def test_set_many_validates_all_modes_before_one_transaction(self):
        catalog = self.catalog()
        state = features.default_state(catalog)
        with mock.patch.object(features, "commit_state_transactionally", return_value={"ok": True}) as commit:
            result = features.set_modes(catalog, state, {"parent": "always", "child": "off"})
        self.assertEqual(result["requestedModes"], {"parent": "always", "child": "off"})
        commit.assert_called_once()
        candidate = commit.call_args.args[2]
        self.assertEqual(candidate["features"]["parent"], "always")
        self.assertEqual(candidate["features"]["child"], "off")

    def test_set_many_rejects_entire_document_before_commit(self):
        catalog = self.catalog()
        state = features.default_state(catalog)
        with mock.patch.object(features, "commit_state_transactionally") as commit:
            with self.assertRaisesRegex(features.FeatureError, "not installed"):
                features.set_modes(catalog, state, {"parent": "always", "missing": "always"})
        commit.assert_not_called()

    def test_mutation_locks_are_released_before_slow_status_report(self):
        catalog = self.catalog()
        state = features.default_state(catalog)
        events: list[str] = []

        class Marker:
            def __enter__(self):
                events.append("enter")
                return self

            def __exit__(self, *_args):
                events.append("exit")

        class Parser:
            def add_subparsers(self, **_kwargs):
                return self

            def add_parser(self, *_args, **_kwargs):
                return self

            def add_argument(self, *_args, **_kwargs):
                return None

            def parse_args(self):
                return SimpleNamespace(command="set-many", source="-")

        with (
            mock.patch.object(features.argparse, "ArgumentParser", return_value=Parser()),
            mock.patch.object(features, "mutation_operation", return_value=Marker()),
            mock.patch.object(features, "acquire_lock", return_value=Marker()),
            mock.patch.object(features, "load_catalog", return_value=catalog),
            mock.patch.object(features, "load_state", return_value=state),
            mock.patch.object(features, "read_mode_document", return_value={"parent": "always"}),
            mock.patch.object(features, "set_modes", return_value={"ok": True}),
            mock.patch.object(
                features,
                "status",
                side_effect=lambda *_args: events.append("status") or {"features": []},
            ),
            mock.patch("builtins.print"),
        ):
            self.assertEqual(features.main(), 0)

        self.assertEqual(events, ["enter", "enter", "exit", "exit", "status"])

    def test_exact_runtime_snapshot_restores_on_demand_activity(self):
        catalog = self.catalog()
        observations = [
            {
                "parent.service": {"ActiveState": "inactive"},
                "child.service": {"ActiveState": "active"},
                "missing.service": {"ActiveState": "inactive"},
            },
            {
                "parent.service": {"ActiveState": "inactive"},
                "child.service": {"ActiveState": "inactive"},
                "missing.service": {"ActiveState": "inactive"},
            },
            {
                "parent.service": {"ActiveState": "active"},
                "child.service": {"ActiveState": "inactive"},
                "missing.service": {"ActiveState": "inactive"},
            },
        ]
        with (
            mock.patch.object(features, "systemd_unit_snapshot", side_effect=observations),
            mock.patch.object(
                features,
                "stop_units",
                return_value=[{"unit": "child.service", "action": "stop", "ok": True, "error": ""}],
            ) as stop,
            mock.patch.object(
                features,
                "start_units",
                return_value=[{"unit": "parent.service", "action": "start", "ok": True, "error": ""}],
            ) as start,
        ):
            result = features.restore_runtime_snapshot(
                catalog,
                {"parent.service": True, "child.service": False, "missing.service": False},
            )
        stop.assert_called_once_with(["child.service"])
        start.assert_called_once_with(["parent.service"])
        self.assertTrue(result["ok"])

    def test_readiness_fails_fast_on_deterministic_http_4xx(self):
        error = features.urllib.error.HTTPError("http://127.0.0.1:9999/health", 404, "not found", Message(), None)
        with (
            mock.patch.object(features.urllib.request, "urlopen", side_effect=error) as urlopen,
            mock.patch.object(features.time, "sleep") as sleep,
        ):
            with self.assertRaisesRegex(features.FeatureError, "misconfigured"):
                features.wait_ready(
                    {
                        "label": "Broken",
                        "healthUrl": "http://127.0.0.1:9999/health",
                        "startupTimeoutSeconds": 30,
                    }
                )
        self.assertEqual(urlopen.call_count, 1)
        sleep.assert_not_called()

    def test_malformed_transaction_journal_is_quarantined_once(self):
        catalog = self.catalog()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            journal = root / "transaction.json"
            journal.write_text("{not-json", encoding="utf-8")
            with mock.patch.object(features, "JOURNAL_PATH", journal):
                with self.assertRaisesRegex(features.FeatureError, "quarantined"):
                    features.recover_pending_transaction(catalog)
                self.assertFalse(journal.exists())
                quarantined = list(root.glob("transaction.json.corrupt-*"))
                self.assertEqual(len(quarantined), 1)
                features.recover_pending_transaction(catalog)
                self.assertEqual(list(root.glob("transaction.json.corrupt-*")), quarantined)

    def test_gate_default_logging_never_emits_raw_request_metadata(self):
        handler = object.__new__(features.GateHandler)
        with mock.patch("sys.stderr") as stderr:
            handler.log_message("%s %s", "GET /?authorization=secret", "200")
        stderr.write.assert_not_called()

    def test_wake_cache_rechecks_dead_backend(self):
        catalog = self.catalog()
        state = features.default_state(catalog)
        features.WAKE_CACHE.record("child", features.time.monotonic())
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.object(features, "RUNTIME_PATH", pathlib.Path(tmp) / "runtime.json"),
            mock.patch.object(
                features,
                "systemd_unit_snapshot",
                side_effect=[
                    {"parent.service": {"ActiveState": "active"}, "child.service": {"ActiveState": "inactive"}},
                    {"parent.service": {"ActiveState": "active"}, "child.service": {"ActiveState": "inactive"}},
                ],
            ),
            mock.patch.object(features, "observed_health", return_value=(False, "dead")),
            mock.patch.object(
                features,
                "start_units",
                return_value=[{"unit": "child.service", "action": "start", "ok": True, "error": ""}],
            ) as start,
            mock.patch.object(features, "wait_ready", return_value=None),
        ):
            result = features.wake_feature(catalog, state, "child")
        self.assertFalse(result["cached"])
        start.assert_called_once_with(["child.service"])


if __name__ == "__main__":
    unittest.main()
