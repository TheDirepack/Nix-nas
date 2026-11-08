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
        ):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as raw:
                probe = load_probe()
                root = pathlib.Path(raw)
                probe.DATA = root / "data/sentinel"
                probe.DATA.parent.mkdir()
                probe.DATA.write_text("nas-v2-persistent-data\n")
                probe.BASELINE = root / "baseline.json"
                probe.CADDY = root / "caddy.conf"
                probe.CADDY.write_text("/vm-oci-persist/")
                value = {
                    "revision": "a" * 64,
                    "document": {
                        "services": {probe.SERVICE: {"runtime": {"image": "v2"}}},
                        "storageResources": {probe.RESOURCE: {"path": str(probe.DATA.parent)}},
                    },
                }
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

                calls = []

                def command(*argv):
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

    def test_missing_baseline_cannot_qualify_a_reboot(self):
        probe = load_probe()
        with tempfile.TemporaryDirectory() as raw:
            probe.BASELINE = pathlib.Path(raw) / "missing"
            with self.assertRaises(FileNotFoundError):
                probe.verify("test reboot")

    def test_removal_preserves_unrelated_desired_state_and_rejects_incomplete_cleanup(self):
        for fault in (None, "data", "container", "inspection", "group"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as raw:
                probe = load_probe()
                root = pathlib.Path(raw)
                probe.DATA = root / "sentinel"
                probe.DATA.write_text("nas-v2-persistent-data\n")
                probe.BASELINE = root / "baseline"
                probe.BASELINE.write_text(json.dumps({"data": probe.data_state()}))
                probe.CADDY = root / "caddy"
                probe.CADDY.write_text("")
                probe.TOKEN = root / "token"
                probe.TOKEN.write_text("test-only-token")
                probe.MANIFEST = root / "manifest"
                probe.MANIFEST.write_text('{"groups": []}')
                desired = {
                    "services": {probe.SERVICE: {}, "unrelated": {"enabled": True}},
                    "storageResources": {probe.RESOURCE: {}, "other-data": {"path": "/tank/other"}},
                }
                replacements = []

                def command(*argv, input_text=None):
                    if argv[1] == "replace-json-document":
                        if input_text is None:
                            self.fail("replacement did not send desired state on stdin")
                        replacements.append(json.loads(input_text))
                        if fault == "data":
                            probe.DATA.write_text("lost")
                    return "inactive" if argv[:2] == ("systemctl", "show") else ""

                groups = [{"name": f"application.{probe.SERVICE}.access"}] if fault == "group" else []
                with (
                    mock.patch.object(probe, "document", return_value={"revision": "a" * 64, "document": desired}),
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
                        return_value=io.BytesIO(json.dumps({"results": groups}).encode()),
                    ),
                ):
                    if fault:
                        with self.assertRaises(RuntimeError):
                            probe.remove()
                    else:
                        probe.remove()
                self.assertEqual(
                    replacements,
                    [
                        {
                            "services": {"unrelated": {"enabled": True}},
                            "storageResources": {"other-data": {"path": "/tank/other"}},
                        }
                    ],
                )

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
