from __future__ import annotations

import hashlib
import json
import pathlib
import stat
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_python_prepare as prepare  # noqa: E402


class V2PythonPrepareTests(unittest.TestCase):
    def make_executable(self, path: pathlib.Path, content: str) -> pathlib.Path:
        path.write_text(content, encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return path

    def make_uv(self, root: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
        log = root / "uv.log"
        uv = self.make_executable(
            root / "uv",
            """#!/usr/bin/env python3
import os
import pathlib
import stat
import sys

with pathlib.Path(os.environ["NAS_V2_UV_LOG"]).open("a", encoding="utf-8") as handle:
    handle.write(" ".join(sys.argv[1:]) + "\\n")

if len(sys.argv) > 1 and sys.argv[1] == "venv":
    venv = pathlib.Path(sys.argv[-1])
    python = venv / "bin" / "python"
    python.parent.mkdir(parents=True, exist_ok=True)
    python.write_text("#!/bin/sh\\nexit 0\\n", encoding="utf-8")
    python.chmod(python.stat().st_mode | stat.S_IXUSR)
raise SystemExit(0)
""",
        )
        return uv, log

    def descriptor(
        self,
        *,
        service_id: str,
        uv: pathlib.Path,
        interpreter: pathlib.Path,
        venv: pathlib.Path,
        requirements: pathlib.Path | None,
        require_hashes: bool = True,
        fingerprint: str = "a" * 64,
    ) -> dict[str, object]:
        value: dict[str, object] = {
            "serviceId": service_id,
            "uv": str(uv),
            "interpreter": str(interpreter),
            "venv": str(venv),
            "requireHashes": require_hashes,
            "environmentFingerprint": fingerprint,
        }
        if requirements is not None:
            value["requirementsFile"] = str(requirements)
            value["requirementsSha256"] = hashlib.sha256(requirements.read_bytes()).hexdigest()
        return value

    def test_prepare_uses_uv_hash_mode_and_second_run_is_noop(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            app_root = root / "apps"
            venv_root = root / "venvs"
            service_root = app_root / "demo"
            service_root.mkdir(parents=True)
            (venv_root / "demo").mkdir(parents=True)
            requirements = service_root / "requirements.lock"
            requirements.write_text("example==1.0 --hash=sha256:" + "1" * 64 + "\n", encoding="utf-8")
            interpreter = self.make_executable(root / "python3", "#!/bin/sh\nexit 0\n")
            uv, log = self.make_uv(root)
            value = self.descriptor(
                service_id="demo",
                uv=uv,
                interpreter=interpreter,
                venv=venv_root / "demo" / "venv",
                requirements=requirements,
            )

            with (
                mock.patch.object(prepare, "APP_ROOT", app_root),
                mock.patch.object(prepare, "VENV_ROOT", venv_root),
                mock.patch.dict("os.environ", {"NAS_V2_UV_LOG": str(log)}),
            ):
                self.assertTrue(prepare.prepare(value))
                first_commands = log.read_text(encoding="utf-8")
                self.assertFalse(prepare.prepare(value))

            commands = log.read_text(encoding="utf-8")
            self.assertEqual(commands, first_commands)
            self.assertIn("venv --no-python-downloads --python", commands)
            self.assertIn("--clear", commands)
            self.assertIn("pip sync --no-python-downloads --python", commands)
            self.assertIn("--strict --require-hashes", commands)
            state = json.loads((venv_root / "demo" / "venv" / ".nas-v2-environment.json").read_text(encoding="utf-8"))
            self.assertEqual(state["fingerprint"], "a" * 64)

    def test_prepare_can_disable_required_hash_mode_explicitly(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            app_root = root / "apps"
            venv_root = root / "venvs"
            service_root = app_root / "demo"
            service_root.mkdir(parents=True)
            (venv_root / "demo").mkdir(parents=True)
            requirements = service_root / "requirements.txt"
            requirements.write_text("example==1.0\n", encoding="utf-8")
            interpreter = self.make_executable(root / "python3", "#!/bin/sh\nexit 0\n")
            uv, log = self.make_uv(root)
            value = self.descriptor(
                service_id="demo",
                uv=uv,
                interpreter=interpreter,
                venv=venv_root / "demo" / "venv",
                requirements=requirements,
                require_hashes=False,
            )

            with (
                mock.patch.object(prepare, "APP_ROOT", app_root),
                mock.patch.object(prepare, "VENV_ROOT", venv_root),
                mock.patch.dict("os.environ", {"NAS_V2_UV_LOG": str(log)}),
            ):
                self.assertTrue(prepare.prepare(value))

            self.assertNotIn("--require-hashes", log.read_text(encoding="utf-8"))

    def test_changed_requirements_after_compile_are_rejected_before_uv_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            app_root = root / "apps"
            venv_root = root / "venvs"
            service_root = app_root / "demo"
            service_root.mkdir(parents=True)
            (venv_root / "demo").mkdir(parents=True)
            requirements = service_root / "requirements.lock"
            requirements.write_text("example==1.0\n", encoding="utf-8")
            interpreter = self.make_executable(root / "python3", "#!/bin/sh\nexit 0\n")
            uv, log = self.make_uv(root)
            value = self.descriptor(
                service_id="demo",
                uv=uv,
                interpreter=interpreter,
                venv=venv_root / "demo" / "venv",
                requirements=requirements,
            )
            requirements.write_text("example==2.0\n", encoding="utf-8")

            with (
                mock.patch.object(prepare, "APP_ROOT", app_root),
                mock.patch.object(prepare, "VENV_ROOT", venv_root),
                mock.patch.dict("os.environ", {"NAS_V2_UV_LOG": str(log)}),
                self.assertRaisesRegex(prepare.PythonPrepareError, "changed after"),
            ):
                prepare.prepare(value)

            self.assertFalse(log.exists())

    def test_requirements_symlink_escape_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            app_root = root / "apps"
            venv_root = root / "venvs"
            service_root = app_root / "demo"
            service_root.mkdir(parents=True)
            (venv_root / "demo").mkdir(parents=True)
            outside = root / "outside.lock"
            outside.write_text("example==1.0\n", encoding="utf-8")
            requirements = service_root / "requirements.lock"
            requirements.symlink_to(outside)
            interpreter = self.make_executable(root / "python3", "#!/bin/sh\nexit 0\n")
            uv, _log = self.make_uv(root)
            value = {
                "serviceId": "demo",
                "uv": str(uv),
                "interpreter": str(interpreter),
                "venv": str(venv_root / "demo" / "venv"),
                "requirementsFile": str(requirements),
                "requirementsSha256": hashlib.sha256(outside.read_bytes()).hexdigest(),
                "requireHashes": True,
                "environmentFingerprint": "a" * 64,
            }

            with (
                mock.patch.object(prepare, "APP_ROOT", app_root),
                mock.patch.object(prepare, "VENV_ROOT", venv_root),
                self.assertRaisesRegex(prepare.PythonPrepareError, "requirementsFile must resolve beneath"),
            ):
                prepare.validate_descriptor(value)


if __name__ == "__main__":
    unittest.main()
