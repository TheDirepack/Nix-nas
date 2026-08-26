from __future__ import annotations

import pathlib
import tempfile
import unittest
from unittest import mock

import nas_first_run_api as first_run_api

ROOT = pathlib.Path(__file__).resolve().parents[1]


class FirstRunApiContractTests(unittest.TestCase):
    def test_installed_system_wires_nas_first_run_api(self) -> None:
        source = (ROOT / "modules" / "nas" / "config" / "caddy-bootstrap.nix").read_text(encoding="utf-8")
        self.assertIn("nas-first-run-api", source)
        self.assertIn("nasPythonApplication", source)
        self.assertIn("--socket", source)

    def test_private_string_boundary_rejects_multiline_values(self) -> None:
        with self.assertRaises(first_run_api.RequestError):
            first_run_api._single_line("one\ntwo", "test")

    def test_job_identifier_is_strictly_bounded(self) -> None:
        with self.assertRaises(first_run_api.RequestError):
            first_run_api.job_status("../escape")

    def test_job_capability_is_root_only_and_constant_time_checked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            job_id = "a" * 24
            token = "x" * 64
            capability = root / f"{job_id}.capability.json"
            with mock.patch.object(first_run_api, "JOB_ROOT", root):
                first_run_api._write_private_new(
                    capability,
                    {"schemaVersion": 1, "jobId": job_id, "token": token},
                )
                metadata = capability.stat()
                self.assertEqual(metadata.st_mode & 0o777, 0o600)

                # The production reader must require UID 0. The unprivileged
                # hermetic CI tier cannot create root-owned fixtures, so model
                # only the ownership metadata while keeping the real descriptor,
                # file contents, permissions, and compare_digest path intact.
                root_owned = mock.Mock(st_mode=metadata.st_mode, st_uid=0, st_size=metadata.st_size)
                with mock.patch.object(first_run_api.os, "fstat", return_value=root_owned):
                    first_run_api.require_job_capability(job_id, token)
                    with self.assertRaises(first_run_api.RequestError):
                        first_run_api.require_job_capability(job_id, "y" * 64)

    def test_setup_job_capability_is_not_accepted_as_a_setup_identity(self) -> None:
        source = pathlib.Path(first_run_api.__file__).read_text(encoding="utf-8")
        dispatch = source[source.index("def _dispatch"):source.index("def do_GET")]
        self.assertIn("require_job_capability", dispatch)
        self.assertIn("self._require_authorized_identity()", dispatch)
        self.assertLess(dispatch.index("require_job_capability"), dispatch.index("self._require_authorized_identity()"))
        self.assertIn('path == "/reboot"', dispatch)
        self.assertNotIn("jobToken", source[source.index("def log_message"):])


if __name__ == "__main__":
    unittest.main()
