#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_service_runtime_python as pyrt  # noqa: E402
import nas_v2_runtime as runtime  # noqa: E402


class V2RuntimeTests(unittest.TestCase):
    def _document(self) -> dict:
        return {
            "schemaVersion": 3,
            "services": {
                "demo": {
                    "name": "Demo",
                    "enabled": True,
                    "managed": True,
                    "workload": {"kind": "daemon", "activation": "persistent"},
                    "runtime": {
                        "type": "python",
                        "entrypoint": {"module": "demo"},
                    },
                    "routes": {
                        "main": {
                            "target": {"type": "http", "port": 8080},
                            "exposure": {"type": "path", "paths": ["/demo/"]},
                            "auth": {"mode": "identity", "capability": "application.demo.access"},
                        }
                    },
                }
            },
        }

    def test_gui_defaults_keep_native_sandbox_inherit_and_python_private(self) -> None:
        normalized = runtime.normalize_gui_document(self._document())
        service = normalized["services"]["demo"]
        self.assertEqual(service["sandbox"]["profile"], "inherit")
        self.assertEqual(service["runtime"]["interpreter"], "/run/current-system/sw/bin/python3")
        self.assertTrue(service["runtime"]["dependencies"]["requireHashes"])
        self.assertEqual(pyrt.venv_path("demo"), pathlib.Path("/var/lib/nas-control/venvs/demo"))
        self.assertNotEqual(pyrt.venv_path("demo"), pyrt.venv_path("other"))

    @mock.patch("nas_v2_runtime.discover_gpus", return_value=[])
    def test_compile_effective_is_single_projection_source(self, _discover: mock.Mock) -> None:
        document = runtime.normalize_gui_document(self._document())
        effective = runtime.compile_effective(document)
        self.assertEqual(effective["services"]["demo"]["lifecycle"], {"mode": "persistent"})
        endpoint = effective["endpoints"]["demo:main"]
        self.assertEqual(endpoint["targetPort"], 8080)
        self.assertEqual(endpoint["auth"]["mode"], "forward-auth")
        self.assertEqual(endpoint["auth"]["capability"], "application.demo.access")

    def test_python_dependency_artifacts_cannot_escape_application_root(self) -> None:
        service = self._document()["services"]["demo"]
        service["runtime"]["dependencies"] = {"requirementsFile": "/tmp/requirements.txt"}
        with self.assertRaises(pyrt.PythonRuntimeError):
            pyrt.ensure_venv("demo", service, dry_run=True)

    def test_python_runtime_dry_run_never_creates_or_installs(self) -> None:
        service = self._document()["services"]["demo"]
        with mock.patch.object(pyrt, "VENV_ROOT", pathlib.Path("/definitely/not-created")):
            with mock.patch("nas_service_runtime_python.subprocess.run") as run:
                plan = pyrt.ensure_venv("demo", service, dry_run=True)
        self.assertTrue(plan["sync"])
        run.assert_not_called()

    def test_python_unit_uses_service_private_interpreter(self) -> None:
        service = self._document()["services"]["demo"]
        text = pyrt.render_unit("demo", service)
        self.assertIn("/var/lib/nas-control/venvs/demo/bin/python -m demo", text)
        self.assertIn("NoNewPrivileges=yes", text)
        self.assertNotIn("site-packages", text)

    def test_effective_file_is_atomic_json(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = pathlib.Path(td) / "effective.json"
            runtime._atomic_json(path, {"schemaVersion": 3, "services": {}})
            self.assertTrue(path.is_file())
            self.assertEqual(path.stat().st_mode & 0o777, 0o640)


if __name__ == "__main__":
    unittest.main()
