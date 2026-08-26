from __future__ import annotations

import pathlib
import time
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
        self.assertIn("systemd.services.nas-first-run-api = lib.mkIf cfg.firstStart.enable", source)
        self.assertIn('requires = [ "nas-first-start.service" ];', source)
        self.assertIn('after = [ "nas-first-start.service" ];', source)
        self.assertIn("PrivateDevices = true;", source)
        self.assertNotIn('"/var/lib/nas-first-start"', source)
        self.assertNotIn("nasSetup", source)

    def test_first_start_worker_uses_configured_nix_environment_without_mount_namespace(self) -> None:
        account_tools = (ROOT / "modules" / "nas" / "internal" / "account-tools.nix").read_text(encoding="utf-8")
        bootstrap = (ROOT / "modules" / "nas" / "config" / "bootstrap-security.nix").read_text(encoding="utf-8")
        source = pathlib.Path(first_run_api.__file__).read_text(encoding="utf-8")
        submit = source[source.index("def submit_setup") : source.index("def request_reboot")]

        self.assertIn("nasFirstStart = pkgs.writeShellApplication", account_tools)
        self.assertEqual(account_tools.count("text = setupEnvironment +"), 2)
        for variable in (
            "NAS_KEEPASS_DATABASE",
            "NAS_ZFS_POOL",
            "NAS_ZFS_DATASET",
            "NAS_ZFS_ROOT",
            "NAS_ZFS_ENCRYPTION_ENABLE",
            "NAS_SHARE_ROOT",
            "NAS_SYNCTHING_ENABLE",
        ):
            self.assertIn(f"export {variable}=", account_tools)
        self.assertIn('"${nasFirstStart}/bin/nas-first-start-job"', bootstrap)
        self.assertNotIn('"${nasPythonApplication}/bin/nas-first-start-job"', bootstrap)
        for mount_namespace_option in ("PrivateTmp", "ProtectSystem", "ProtectHome", "ReadWritePaths"):
            self.assertNotIn(f"--property={mount_namespace_option}", submit)
        self.assertIn("mount must become host-visible", submit)

    def test_status_reads_prepared_service_authority_without_running_setup(self) -> None:
        expected = {"schemaVersion": 3, "status": "ready"}
        with mock.patch.object(first_run_api, "_read_root_json", return_value=expected) as reader:
            self.assertEqual(first_run_api.setup_status(), expected)
        reader.assert_called_once_with(first_run_api.FIRST_START_STATUS_PATH, "Prepared first-start status")

        module_file = first_run_api.__file__
        assert module_file is not None
        source = pathlib.Path(module_file).read_text(encoding="utf-8")
        status = source[source.index("def setup_status") : source.index("def setup_complete")]
        self.assertNotIn("nas-setup", status)
        self.assertNotIn("subprocess", status)
        self.assertNotIn("_command_json", source)

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
                    {"schemaVersion": 1, "jobId": job_id, "token": token, "createdAt": int(time.time())},
                )
                metadata = capability.stat()
                self.assertEqual(metadata.st_mode & 0o777, 0o600)

                root_owned = mock.Mock(st_mode=metadata.st_mode, st_uid=0, st_size=metadata.st_size)
                with mock.patch.object(first_run_api.os, "fstat", return_value=root_owned):
                    first_run_api.require_job_capability(job_id, token)
                    with self.assertRaises(first_run_api.RequestError):
                        first_run_api.require_job_capability(job_id, "y" * 64)

                group_readable = mock.Mock(
                    st_mode=(metadata.st_mode & ~0o777) | 0o640,
                    st_uid=0,
                    st_size=metadata.st_size,
                )
                with mock.patch.object(first_run_api.os, "fstat", return_value=group_readable):
                    with self.assertRaisesRegex(first_run_api.RequestError, "unsafe ownership or mode"):
                        first_run_api.require_job_capability(job_id, token)

    def test_job_capability_expires_and_is_removed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            job_id = "b" * 24
            token = "x" * 64
            capability = root / f"{job_id}.capability.json"
            with mock.patch.object(first_run_api, "JOB_ROOT", root):
                first_run_api._write_private_new(
                    capability,
                    {
                        "schemaVersion": 1,
                        "jobId": job_id,
                        "token": token,
                        "createdAt": int(time.time()) - first_run_api.JOB_CAPABILITY_TTL_SECONDS - 1,
                    },
                )
                metadata = capability.stat()
                root_owned = mock.Mock(st_mode=metadata.st_mode, st_uid=0, st_size=metadata.st_size)
                with mock.patch.object(first_run_api.os, "fstat", return_value=root_owned):
                    with self.assertRaisesRegex(first_run_api.RequestError, "expired"):
                        first_run_api.require_job_capability(job_id, token)
                self.assertFalse(capability.exists())

    def test_setup_socket_is_caddy_owned_and_user_private(self) -> None:
        module_file = first_run_api.__file__
        assert module_file is not None
        source = pathlib.Path(module_file).read_text(encoding="utf-8")
        serve = source[source.index("def serve(") : source.index("def main()")]
        self.assertIn('pwd.getpwnam("caddy")', serve)
        self.assertIn('grp.getgrnam("caddy")', serve)
        self.assertIn("os.chmod(socket_path, 0o600)", serve)
        self.assertNotIn("0o660", serve)

    def test_non_secret_root_status_may_remain_group_readable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = pathlib.Path(tmp) / "state.json"
            state.write_text('{"status":"complete"}\n', encoding="utf-8")
            state.chmod(0o640)
            metadata = state.stat()
            root_owned = mock.Mock(st_mode=metadata.st_mode, st_uid=0, st_size=metadata.st_size)
            with mock.patch.object(first_run_api.os, "fstat", return_value=root_owned):
                self.assertEqual(first_run_api._read_root_json(state, "state")["status"], "complete")

    def test_setup_job_capability_is_not_accepted_as_a_setup_identity(self) -> None:
        module_file = first_run_api.__file__
        assert module_file is not None
        source = pathlib.Path(module_file).read_text(encoding="utf-8")
        dispatch = source[source.index("def _dispatch") : source.index("def do_GET")]
        self.assertIn("require_job_capability", dispatch)
        self.assertIn("self._require_authorized_identity()", dispatch)
        self.assertLess(dispatch.index("require_job_capability"), dispatch.index("self._require_authorized_identity()"))
        self.assertIn('path == "/reboot"', dispatch)
        self.assertNotIn("jobToken", source[source.index("def log_message") :])


if __name__ == "__main__":
    unittest.main()
