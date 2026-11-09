from __future__ import annotations

import copy
import importlib.util
import io
import json
import pathlib
import subprocess
import tempfile
import unittest
from typing import Any
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_probe() -> Any:
    spec = importlib.util.spec_from_file_location("oci_persistence", ROOT / "tests/vm/oci-probe.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class OciPersistenceTests(unittest.TestCase):
    def test_persistence_fixture_uses_the_canonical_schema_and_offline_image(self):
        from services import nas_v2_spec as spec

        probe = load_probe()
        calls = []

        def command(*argv, input_text=None):
            calls.append((argv, input_text))
            if argv == ("nas-managed-services-control", "document"):
                return json.dumps({"revision": "a" * 64, "document": {"schemaVersion": 3, "services": {}}})
            return ""

        with tempfile.TemporaryDirectory() as raw:
            probe.DATA = pathlib.Path(raw) / "new-data/sentinel"
            probe.BASELINE = pathlib.Path(raw) / "baseline"
            with (
                mock.patch.object(probe, "command", side_effect=command),
                mock.patch.object(probe, "record"),
                mock.patch.object(probe, "verify"),
            ):
                probe.create()
            writer = next(argv[-1] for argv, _ in calls if argv[:2] == ("podman", "exec"))
            target = pathlib.Path(raw) / "sentinel"
            subprocess.run(["sh", "-c", writer.replace("/data/sentinel", str(target))], check=True, timeout=5)
            self.assertEqual(target.read_bytes(), b"nas-v2-persistent-data\n")
        replacement = next(json.loads(payload) for argv, payload in calls if "replace-json-document" in argv)
        # The VM uses /tank; the temporary path above only isolates collision checks.
        replacement["storageResources"][probe.RESOURCE]["path"] = "/tank/vm-oci-persist"
        effective = spec.compile_document(
            replacement, spec.load_schema(ROOT / "schemas/managed-services-v3.schema.json")
        )
        service = effective["services"][probe.SERVICE]
        self.assertEqual(service["runtime"]["pull"], "never")
        self.assertEqual(service["resources"]["pidsMax"], 64)
        self.assertEqual(service["readiness"]["probes"][0]["url"], "http://127.0.0.1:18089/")
        self.assertEqual(service["storage"][0]["access"], "write")
        self.assertFalse(any("start" in argv or "restart" in argv for argv, _ in calls))

    def test_verifier_rejects_each_surviving_state_fault_without_repairing_it(self):
        for fault in (
            None,
            "revision",
            "service",
            "resource",
            "data",
            "metadata",
            "mount",
            "image",
            "http",
            "attachment",
            "memory",
            "pids",
            "cpu",
            "route",
            "upstream",
            "proxy",
            "auth",
            "duplicate-before",
            "duplicate-after",
            "duplicate-wildcard",
            "overlap",
        ):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as raw:
                probe = load_probe()
                root = pathlib.Path(raw)
                probe.DATA = root / "data/sentinel"
                probe.DATA.parent.mkdir()
                probe.DATA.write_text("nas-v2-persistent-data\n")
                probe.BASELINE = root / "baseline.json"
                probe.CADDY = root / "caddy.conf"
                desired = probe.fixture_document()
                desired["storageResources"][probe.RESOURCE]["path"] = "/tank/vm-oci-persist"
                value = {"revision": "a" * 64, "document": desired}
                route = "\n".join(
                    probe.expected_route(
                        {
                            "service": desired["services"][probe.SERVICE],
                            "resource": desired["storageResources"][probe.RESOURCE],
                        }
                    )
                )
                probe.CADDY.write_text(route.replace("_path_0", "_path_9"))
                with mock.patch.object(probe, "document", return_value=value):
                    probe.record()
                changed = copy.deepcopy(value)
                if fault == "revision":
                    changed["revision"] = "b" * 64
                elif fault == "service":
                    changed["document"]["services"][probe.SERVICE]["runtime"]["image"] = "old"
                elif fault == "resource":
                    changed["document"]["storageResources"][probe.RESOURCE]["path"] = "/wrong"
                elif fault == "data":
                    probe.DATA.write_text("lost data")
                elif fault == "metadata":
                    probe.DATA.chmod(0o400)
                elif fault == "route":
                    probe.CADDY.write_text("unrelated route")

                if fault == "upstream":
                    probe.CADDY.write_text(route.replace("127.0.0.1:18089", "127.0.0.1:18090"))
                elif fault == "proxy":
                    probe.CADDY.write_text(route.replace('/vm-oci-persist"', '/wrong"'))
                elif fault == "auth":
                    probe.CADDY.write_text(route.replace("forward_auth", "reverse_proxy"))

                if fault in {"duplicate-before", "duplicate-after", "duplicate-wildcard"}:
                    unsafe = route.replace("forward_auth", "reverse_proxy").replace("_path_0", "_path_8")
                    if fault == "duplicate-wildcard":
                        unsafe_lines = unsafe.splitlines()
                        unsafe_lines[0] = unsafe_lines[0].split(" path ")[0] + ' path "/vm-oci-persist/*"'
                        unsafe = "\n".join(unsafe_lines)
                    probe.CADDY.write_text(
                        unsafe + "\n" + route if fault == "duplicate-before" else route + "\n" + unsafe
                    )

                if fault == "overlap":
                    unsafe = route.splitlines()
                    unsafe[0] = unsafe[0].split(" path ")[0] + ' path "/vm*"'
                    probe.CADDY.write_text(route + "\n" + "\n".join(unsafe).replace("forward_auth", "reverse_proxy"))
                calls = []

                def command(*argv, **kwargs):
                    calls.append(argv)
                    if argv[0] == "findmnt":
                        return f"zfs {'wrong' if fault == 'mount' else 'tank/nas/vm-oci-persist'} {probe.DATA.parent}"
                    if argv[0] == "systemctl":
                        self.assertEqual(argv[1:], ("is-active", "--quiet", probe.UNIT))
                        return ""
                    if argv[0] == "curl":
                        return "wrong" if fault == "http" else "nas-v2-oci-v2"
                    if argv[1] == "inspect":
                        return "old" if fault == "image" else "localhost/nas-v2-vm-probe:v2"
                    self.assertEqual(argv[:4], ("podman", "exec", probe.CONTAINER, "cat"))
                    return {
                        "/data/sentinel": "lost" if fault == "attachment" else "nas-v2-persistent-data",
                        "/sys/fs/cgroup/memory.max": "max" if fault == "memory" else "134217728",
                        "/sys/fs/cgroup/pids.max": "max" if fault == "pids" else "64",
                        "/sys/fs/cgroup/cpu.max": "100000 100000" if fault == "cpu" else "25000 100000",
                    }[argv[-1]]

                before = probe.BASELINE.read_bytes()
                with (
                    mock.patch.object(probe, "document", return_value=changed),
                    mock.patch.object(probe, "command", side_effect=command),
                ):
                    if fault:
                        with self.assertRaises(RuntimeError):
                            probe.verify("test reboot")
                    else:
                        probe.verify("test reboot")
                self.assertEqual(probe.BASELINE.read_bytes(), before)
                self.assertFalse(any("start" in call or "restart" in call for call in calls))

    def test_creation_collisions_do_not_mutate_the_guest(self):
        for collision in ("service", "resource", "baseline", "data"):
            with self.subTest(collision=collision), tempfile.TemporaryDirectory() as raw:
                probe = load_probe()
                root = pathlib.Path(raw)
                probe.DATA = root / "data/sentinel"
                probe.BASELINE = root / "baseline"
                desired = {"services": {}, "storageResources": {}}
                if collision == "service":
                    desired["services"][probe.SERVICE] = {"name": "existing"}
                elif collision == "resource":
                    desired["storageResources"][probe.RESOURCE] = {"path": "/tank/existing"}
                elif collision == "baseline":
                    probe.BASELINE.touch()
                else:
                    probe.DATA.parent.mkdir()
                with (
                    mock.patch.object(probe, "document", return_value={"document": desired}),
                    mock.patch.object(probe, "command") as command,
                    self.assertRaisesRegex(RuntimeError, "already exists"),
                ):
                    probe.create()
                command.assert_not_called()

    def test_failed_creation_compensates_only_its_own_resources(self):
        for failure in (
            "zfs",
            "zfs-after",
            "zfs-unowned",
            "zfs-inspection",
            "replace",
            "concurrent",
            "sentinel",
            "snapshot",
            "record",
            "verify",
            "cleanup",
            "child",
            "mount-replaced",
            "mount-nonempty",
        ):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as raw:
                probe = load_probe()
                root = pathlib.Path(raw)
                probe.DATA = root / "data/sentinel"
                probe.BASELINE = root / "baseline"
                original = {"services": {"unrelated": {"enabled": True}}, "storageResources": {}}
                live = {"document": copy.deepcopy(original), "revision": "a" * 64}
                destroyed = []
                destroy_calls = []
                dataset_owner = "-"
                dataset_exists = False

                def command(*argv, input_text=None):
                    nonlocal dataset_owner, dataset_exists
                    if argv[:2] == ("zfs", "create"):
                        if failure in {"zfs", "zfs-unowned", "zfs-inspection"}:
                            raise RuntimeError("fixture failure")
                        dataset_exists = True
                        dataset_owner = next(
                            arg.split("=", 1)[1] for arg in argv if arg.startswith("nas:qualification=")
                        )
                        if failure == "zfs-after":
                            raise RuntimeError("fixture failure")
                    elif argv[:2] == ("zfs", "list"):
                        if failure == "zfs-inspection":
                            raise RuntimeError("inspection failure")
                        return "tank/nas/vm-oci-persist" if dataset_exists or failure == "zfs-unowned" else ""
                    elif argv[:2] == ("zfs", "get"):
                        return dataset_owner
                    elif "replace-json-document" in argv:
                        if input_text is None:
                            self.fail("replacement did not send desired state on stdin")
                        desired = json.loads(input_text)
                        if probe.SERVICE in desired["services"]:
                            live["document"] = desired
                            if failure in {"replace", "concurrent"}:
                                if failure == "concurrent":
                                    live["document"]["services"]["concurrent"] = {"enabled": True}
                                raise RuntimeError("fixture failure")
                        elif failure == "cleanup":
                            raise RuntimeError("cleanup failure")
                        else:
                            live["document"] = desired
                    elif argv[:2] == ("podman", "exec") and failure == "sentinel":
                        raise RuntimeError("fixture failure")
                    elif argv[:2] == ("zfs", "snapshot") and failure == "snapshot":
                        raise RuntimeError("fixture failure")
                    elif argv[:2] == ("zfs", "destroy"):
                        destroy_calls.append(argv)
                        if "@" in argv[-1]:
                            return ""
                        if failure == "child":
                            raise RuntimeError("child dataset remains")
                        destroyed.append(argv[-1])
                        dataset_exists = False
                        if failure == "mount-replaced":
                            probe.DATA.parent.rename(root / "old-mountpoint")
                            probe.DATA.parent.mkdir()
                        if failure in {"mount-replaced", "mount-nonempty"}:
                            (probe.DATA.parent / "unrelated").write_text("preserve")
                    return ""

                def record():
                    probe.BASELINE.write_text("recorded")
                    if failure == "record":
                        raise RuntimeError("fixture failure")

                with (
                    mock.patch.object(probe, "document", side_effect=lambda: copy.deepcopy(live)),
                    mock.patch.object(probe, "command", side_effect=command),
                    mock.patch.object(probe, "record", side_effect=record),
                    mock.patch.object(
                        probe,
                        "verify",
                        side_effect=RuntimeError("fixture failure")
                        if failure in {"verify", "cleanup", "child", "mount-replaced", "mount-nonempty"}
                        else None,
                    ),
                    self.assertRaisesRegex(
                        RuntimeError, "manual recovery required" if failure == "cleanup" else "fixture failure"
                    ) as caught,
                ):
                    probe.create()
                if failure == "zfs":
                    self.assertNotIn("manual recovery", str(caught.exception))
                elif failure in {"zfs-unowned", "zfs-inspection"}:
                    self.assertIn("manual recovery", str(caught.exception))
                if failure == "child":
                    self.assertIn("manual recovery", str(caught.exception))
                    self.assertEqual(live["document"], original)
                    self.assertTrue(probe.DATA.parent.exists())
                    self.assertFalse(destroyed)
                    self.assertTrue(all("-r" not in call for call in destroy_calls))
                elif failure in {"mount-replaced", "mount-nonempty"}:
                    self.assertIn("manual recovery", str(caught.exception))
                    self.assertEqual((probe.DATA.parent / "unrelated").read_text(), "preserve")
                    if failure == "mount-replaced":
                        self.assertIn("mountpoint was replaced", str(caught.exception))
                elif failure in {"cleanup", "replace", "concurrent", "zfs-unowned", "zfs-inspection"}:
                    self.assertIn("manual recovery", str(caught.exception))
                    if failure not in {"zfs-unowned", "zfs-inspection"}:
                        self.assertIn(probe.SERVICE, live["document"]["services"])
                    if failure == "concurrent":
                        self.assertIn("concurrent", live["document"]["services"])
                    self.assertTrue(probe.DATA.parent.exists())
                    self.assertFalse(destroyed)
                else:
                    self.assertEqual(live["document"], original)
                    self.assertFalse(probe.BASELINE.exists())
                    self.assertFalse(probe.DATA.parent.exists())
                    self.assertEqual(
                        destroyed,
                        [] if failure in {"zfs", "zfs-unowned", "zfs-inspection"} else ["tank/nas/vm-oci-persist"],
                    )

    def test_compensated_mountpoint_failure_can_retry_safely(self):
        probe = load_probe()
        with tempfile.TemporaryDirectory() as raw:
            probe.DATA = pathlib.Path(raw) / "mount/sentinel"
            probe.BASELINE = pathlib.Path(raw) / "baseline"
            attempts = 0

            def command(*argv, input_text=None):
                nonlocal attempts
                if argv[:2] == ("zfs", "create"):
                    attempts += 1
                    if attempts == 1:
                        probe.DATA.parent.mkdir(exist_ok=True)
                        raise RuntimeError("create failed")
                return ""

            with (
                mock.patch.object(
                    probe,
                    "document",
                    side_effect=lambda: {"revision": "a" * 64, "document": {"services": {}, "storageResources": {}}},
                ),
                mock.patch.object(probe, "command", side_effect=command),
                mock.patch.object(probe, "record"),
                mock.patch.object(probe, "verify"),
            ):
                with self.assertRaisesRegex(RuntimeError, "create failed"):
                    probe.create()
                self.assertFalse(probe.DATA.parent.exists())
                probe.create()
            self.assertEqual(attempts, 2)

    def test_readiness_retries_read_only_until_ready_and_times_out(self):
        probe = load_probe()
        with (
            mock.patch.object(probe, "command", side_effect=[RuntimeError("starting"), "", "ok"]) as command,
            mock.patch.object(probe.time, "monotonic", side_effect=[0, 1]),
            mock.patch.object(probe.time, "sleep"),
        ):
            probe.wait_ready("reboot")
        self.assertEqual([call.args[0] for call in command.call_args_list], ["systemctl", "systemctl", "curl"])
        with (
            mock.patch.object(probe, "command", side_effect=RuntimeError("not ready")),
            mock.patch.object(probe.time, "monotonic", side_effect=[0, 60]),
        ):
            with self.assertRaisesRegex(RuntimeError, "after reboot"):
                probe.wait_ready("reboot")

    def test_locked_oracle_rejects_running_app_and_unrelated_transport_failures(self):
        probe = load_probe()
        for state, code, accepted in (
            ("inactive", 7, True),
            ("active", 7, False),
            ("inactive", 0, False),
            ("inactive", 6, False),
            ("inactive", 28, False),
        ):
            with (
                self.subTest(state=state, code=code),
                mock.patch.object(probe, "command", return_value=state),
                mock.patch.object(probe.subprocess, "run", return_value=subprocess.CompletedProcess([], code)),
            ):
                if accepted:
                    probe.locked()
                else:
                    with self.assertRaises(RuntimeError):
                        probe.locked()

    def test_locked_oracle_waits_only_for_bounded_deactivation(self):
        for states, times, accepted in (
            (["deactivating", "inactive"], [0, 1], True),
            (["deactivating", "active"], [0, 1], False),
            (["deactivating"], [0, 30], False),
            (["failed"], [0], False),
        ):
            probe = load_probe()
            with (
                self.subTest(states=states),
                mock.patch.object(probe, "command", side_effect=states),
                mock.patch.object(probe.time, "monotonic", side_effect=times),
                mock.patch.object(probe.time, "sleep"),
                mock.patch.object(probe.subprocess, "run", return_value=subprocess.CompletedProcess([], 7)) as curl,
            ):
                if accepted:
                    probe.locked()
                    curl.assert_called_once()
                else:
                    with self.assertRaisesRegex(RuntimeError, "while secrets are locked"):
                        probe.locked()
                    curl.assert_not_called()

    def test_missing_baseline_cannot_qualify_a_reboot(self):
        probe = load_probe()
        with tempfile.TemporaryDirectory() as raw:
            probe.BASELINE = pathlib.Path(raw) / "missing"
            with self.assertRaises(FileNotFoundError):
                probe.verify("test reboot")

    def test_removal_preserves_unrelated_desired_state_and_rejects_incomplete_cleanup(self):
        for fault in (None, "data", "container", "inspection", "group", "projection", "symlink", "route", "write"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as raw:
                probe = load_probe()
                root = pathlib.Path(raw)
                probe.PROJECTIONS = (root / "projection",)
                if fault == "projection":
                    probe.PROJECTIONS[0].touch()
                elif fault == "symlink":
                    probe.PROJECTIONS[0].symlink_to(root / "missing")
                probe.DATA = root / "sentinel"
                probe.DATA.write_text("nas-v2-persistent-data\n")
                probe.BASELINE = root / "baseline"
                probe.BASELINE.write_text(json.dumps({"data": probe.data_state()}))
                probe.CADDY = root / "caddy"
                probe.CADDY.write_text(
                    '@fixture path "/vm-oci-persist"'
                    if fault == "route"
                    else '@unrelated path "/vm-oci-persist-other"\nreverse_proxy 127.0.0.1:18088\n# /vm-oci-persist 127.0.0.1:18089'
                )
                probe.TOKEN = root / "token"
                probe.TOKEN.write_text("test-only-token")
                probe.MANIFEST = root / "manifest"
                probe.MANIFEST.write_text('{"groups": []}')
                desired = {
                    "services": {probe.SERVICE: {}, "unrelated": {"enabled": True}},
                    "storageResources": {probe.RESOURCE: {}, "other-data": {"path": "/tank/other"}},
                }
                probe.BASELINE.write_text(
                    json.dumps(
                        {
                            "revision": "a" * 64,
                            "service": copy.deepcopy(desired["services"][probe.SERVICE]),
                            "resource": copy.deepcopy(desired["storageResources"][probe.RESOURCE]),
                            "data": probe.data_state(),
                        }
                    )
                )
                replacements = []

                def command(*argv, input_text=None):
                    if argv[1] == "replace-json-document":
                        if input_text is None:
                            self.fail("replacement did not send desired state on stdin")
                        replacements.append(json.loads(input_text))
                        if fault == "write" and len(replacements) == 1:
                            raise RuntimeError("write failed")
                        desired.clear()
                        desired.update(copy.deepcopy(replacements[-1]))
                        if fault == "data":
                            probe.DATA.write_text("lost")
                    return "inactive" if argv[:2] == ("systemctl", "show") else ""

                groups = [{"name": f"application.{probe.SERVICE}.access"}] if fault == "group" else []
                with (
                    mock.patch.object(
                        probe,
                        "document",
                        side_effect=lambda: {"revision": "a" * 64, "document": copy.deepcopy(desired)},
                    ),
                    mock.patch.object(probe, "command", side_effect=command),
                    mock.patch.object(
                        probe.subprocess,
                        "run",
                        return_value=subprocess.CompletedProcess(
                            [], 0 if fault == "container" else 125 if fault == "inspection" else 1
                        ),
                    ),
                    mock.patch.object(
                        probe.urllib.request,
                        "urlopen",
                        side_effect=lambda *args, **kwargs: io.BytesIO(json.dumps({"results": groups}).encode()),
                    ),
                ):
                    if fault:
                        with self.assertRaises(RuntimeError):
                            probe.remove()
                    else:
                        probe.remove()
                        probe.remove()
                    if fault == "write":
                        self.assertIn(probe.SERVICE, desired["services"])
                        probe.remove()
                    if fault in {"projection", "symlink"}:
                        probe.PROJECTIONS[0].unlink()
                        probe.remove()
                self.assertEqual(
                    replacements,
                    [
                        {
                            "services": {"unrelated": {"enabled": True}},
                            "storageResources": {"other-data": {"path": "/tank/other"}},
                        }
                    ]
                    * (2 if fault == "write" else 1),
                )

    def test_teardown_requires_owned_baseline_before_any_authority_write(self):
        for fault in ("missing", "invalid", "service", "resource"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as raw:
                probe = load_probe()
                probe.BASELINE = pathlib.Path(raw) / "baseline"
                desired = probe.fixture_document()
                baseline = {
                    "revision": "a" * 64,
                    "service": copy.deepcopy(desired["services"][probe.SERVICE]),
                    "resource": copy.deepcopy(desired["storageResources"][probe.RESOURCE]),
                    "data": {},
                }
                if fault == "invalid":
                    probe.BASELINE.write_text('{"data": {}}')
                elif fault != "missing":
                    probe.BASELINE.write_text(json.dumps(baseline))
                    key, section = (
                        (probe.SERVICE, "services") if fault == "service" else (probe.RESOURCE, "storageResources")
                    )
                    desired[section][key] = {"name": "unrelated replacement"}
                before = copy.deepcopy(desired)
                with (
                    mock.patch.object(
                        probe,
                        "document",
                        side_effect=lambda: {"revision": "b" * 64, "document": copy.deepcopy(desired)},
                    ),
                    mock.patch.object(probe, "command") as command,
                    self.assertRaises((RuntimeError, FileNotFoundError)),
                ):
                    probe.remove()
                command.assert_not_called()
                self.assertEqual(desired, before)

    def test_shared_resource_blocks_cleanup_before_document_mutation(self):
        probe = load_probe()
        desired = probe.fixture_document()
        expected = copy.deepcopy(desired)
        desired["services"]["another-app"] = {
            "storage": [{"resource": probe.RESOURCE, "mountPath": "/shared", "access": "read"}]
        }
        original = copy.deepcopy(desired)
        with (
            mock.patch.object(
                probe, "document", side_effect=lambda: {"revision": "a" * 64, "document": copy.deepcopy(desired)}
            ),
            mock.patch.object(probe, "command") as command,
            self.assertRaisesRegex(RuntimeError, "fixture cleanup blocked.*shared.*another-app"),
        ):
            probe.remove_declarations(expected)
        command.assert_not_called()
        self.assertEqual(desired, original)

    def test_installer_retains_fixture_for_final_browser_and_native_path_tears_it_down(self):
        installer = (ROOT / "scripts/qemu-test.sh").read_text()
        final = installer.split('log "Rebooting the switched generation for persistence verification"', 1)[1]
        self.assertIn("--oci-probe verify --stage final-reboot", final)
        self.assertNotIn("--oci-probe remove", installer)
        browser = (ROOT / "scripts/qemu-final-browser.sh").read_text()
        run = browser.split("  deterministic-browser)\n", 1)[1].split("    ;;", 1)[0]
        self.assertLess(run.index("playwright test"), run.index("--oci-probe remove"))
        native = (ROOT / "tests/nixos/integration.nix").read_text()
        self.assertLess(native.index("--oci-probe verify"), native.index("--oci-probe remove"))


if __name__ == "__main__":
    unittest.main()
