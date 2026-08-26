from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))

import nas_coding_agent as coding  # noqa: E402


class CodingAgentTests(unittest.TestCase):
    def test_workspace_allowlist_uses_resolved_paths_and_blocks_escape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary) / "allowed"
            repo = root / "repo"
            outside = pathlib.Path(temporary) / "outside"
            repo.mkdir(parents=True)
            outside.mkdir()
            self.assertEqual(coding.validate_workspace(str(repo), (root.resolve(),)), repo.resolve())
            with self.assertRaisesRegex(coding.CodingAgentError, "outside the configured allowlist"):
                coding.validate_workspace(str(outside), (root.resolve(),))
            escape = root / "escape"
            escape.symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(coding.CodingAgentError, "outside the configured allowlist"):
                coding.validate_workspace(str(escape), (root.resolve(),))

    def test_configured_roots_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            with mock.patch.dict(os.environ, {"NAS_CODING_WORKSPACE_ROOTS_JSON": json.dumps([str(root)])}, clear=True):
                self.assertEqual(coding.configured_roots(), (root.resolve(),))
            for malformed in ("not-json", "[]", '["/missing"]'):
                with (
                    self.subTest(value=malformed),
                    mock.patch.dict(os.environ, {"NAS_CODING_WORKSPACE_ROOTS_JSON": malformed}, clear=True),
                ):
                    with self.assertRaises((coding.CodingAgentError, FileNotFoundError)):
                        coding.configured_roots()

    def test_workspace_validation_rejects_missing_and_file_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            with self.assertRaisesRegex(coding.CodingAgentError, "does not exist"):
                coding.validate_workspace(str(root / "missing"), (root,))
            plain_file = root / "file"
            plain_file.write_text("", encoding="utf-8")
            with self.assertRaisesRegex(coding.CodingAgentError, "not a directory"):
                coding.validate_workspace(str(plain_file), (root,))

    def test_transient_session_command_contains_sandbox_and_only_credential_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            session_exec = root / "session-exec"
            session_exec.write_text("#!/bin/sh\n", encoding="utf-8")
            credential = root / "credential"
            credential.write_text("local-client-secret", encoding="utf-8")
            with mock.patch.dict(
                os.environ,
                {
                    "NAS_PI_SESSION_EXEC": str(session_exec),
                    "NAS_PI_CREDENTIAL": str(credential),
                    "NAS_PI_STATE_DIR": "/var/lib/nas-code-agent",
                },
                clear=True,
            ):
                command = coding.session_command(root, ["--model", "coding/default"])
            rendered = "\n".join(command)
            for marker in (
                "--uid=nas-code-agent",
                "--gid=nas-code-agent",
                "ProtectSystem=strict",
                "NoNewPrivileges=yes",
                "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
                "NetworkNamespacePath=/run/netns/pi",
                "InaccessiblePaths=/run/nas-secrets",
                f"ReadWritePaths={root}",
                f"LoadCredential=llama-swap-api-key:{credential}",
            ):
                self.assertIn(marker, command)
            self.assertNotIn("local-client-secret", rendered)

    def test_nix_integration_uses_v2_authority_and_no_uid_fallback(self) -> None:
        module = (ROOT / "modules" / "ai" / "coding-agent.nix").read_text(encoding="utf-8")
        secrets = (ROOT / "modules" / "nas" / "internal" / "secret-tools.nix").read_text(encoding="utf-8")
        source = (ROOT / "services" / "nas_coding_agent.py").read_text(encoding="utf-8")
        self.assertIn("piHostVethIp", module)
        self.assertIn("cfg.llamaSwap.port", module)
        self.assertIn('apiKey = "LLAMA_SWAP_CODING_API_KEY"', module)
        self.assertIn("PI_OFFLINE=1", module)
        self.assertIn("coding-agent-api-key", secrets)
        self.assertIn("LLAMA_SWAP_CODING_API_KEY", secrets)
        self.assertIn('CODING_CAPABILITY_GROUP = "application.ai-coding.access"', source)
        self.assertIn('CODING_SERVICE_ID = "ai-coding"', source)
        self.assertIn("NAS_AUTHENTICATED_IDENTITY_JSON", source)
        self.assertIn("NAS_MANAGED_SERVICES_CONTROL", source)
        self.assertNotIn("NAS_CODING_INSECURE_UID_AUTH", source)
        self.assertNotIn("nas-feature-control", source)
        if shutil := __import__("shutil"):
            if shutil.which("nix-instantiate"):
                result = subprocess.run(
                    ["nix-instantiate", "--parse", str(ROOT / "modules" / "ai" / "coding-agent.nix")],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                if "Permission denied" in (result.stderr or "") or "creating directory" in (result.stderr or ""):
                    self.skipTest("nix store not available on host")
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_main_wakes_v2_service_then_runs_transient_session(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            credential = root / "credential"
            credential.write_text("token", encoding="utf-8")
            session_exec = root / "session"
            session_exec.write_text("#!/bin/sh\n", encoding="utf-8")
            identity = json.dumps({"username": "alice", "groups": [coding.CODING_CAPABILITY_GROUP]})
            completed = mock.Mock(returncode=0)
            with (
                mock.patch.object(os, "geteuid", return_value=0),
                mock.patch.dict(
                    os.environ,
                    {
                        "NAS_CODING_WORKSPACE_ROOTS_JSON": json.dumps([str(root)]),
                        "NAS_PI_CREDENTIAL": str(credential),
                        "NAS_PI_SESSION_EXEC": str(session_exec),
                        "NAS_MANAGED_SERVICES_CONTROL": "/test/nas-managed-services-control",
                        "NAS_CODING_HEARTBEAT_SECONDS": "3600",
                        "NAS_AUTHENTICATED_IDENTITY_JSON": identity,
                    },
                    clear=True,
                ),
                mock.patch.object(coding, "run_checked") as wake,
                mock.patch.object(coding.subprocess, "run", return_value=completed) as run,
            ):
                self.assertEqual(coding.main([str(repo), "--", "--model", "coding/default"]), 0)
            wake.assert_called_once_with(["/test/nas-managed-services-control", "wake", "ai-coding"])
            self.assertTrue(any(call.args and call.args[0][0] == "systemd-run" for call in run.call_args_list))

    def test_llama_swap_default_uses_configurable_idle_ttl(self):
        internal = (ROOT / "modules" / "ai" / "internal.nix").read_text(encoding="utf-8")
        services = (ROOT / "modules" / "ai" / "services.nix").read_text(encoding="utf-8")
        self.assertIn("globalTTL: ${toString cfg.llamaSwap.globalTtl}", internal)
        self.assertIn("if cmp -s ${legacyDefaultConfig}", services)
        self.assertIn("path = [ pkgs.coreutils pkgs.diffutils ];", services)
        self.assertIn("chown nas-ai:nas-ai", services)
        self.assertIn("Refusing symlinked llama-swap configuration", services)

    def test_heartbeat_refreshes_v2_service_lease(self) -> None:
        stop = threading.Event()
        with mock.patch.object(coding.subprocess, "run") as run:
            with mock.patch.object(threading.Event, "wait", side_effect=[False, True]):
                coding.heartbeat(stop, "/test/nas-managed-services-control", 1)
        run.assert_called_once()
        self.assertEqual(run.call_args.args[0], ["/test/nas-managed-services-control", "wake", "ai-coding"])

    def test_identity_json_requires_canonical_capability_or_admin_role(self) -> None:
        for groups in ([coding.CODING_CAPABILITY_GROUP], [coding.ADMIN_GROUP]):
            with (
                self.subTest(groups=groups),
                mock.patch.dict(
                    os.environ,
                    {"NAS_AUTHENTICATED_IDENTITY_JSON": json.dumps({"username": "alice", "groups": groups})},
                    clear=True,
                ),
            ):
                coding._check_coding_access()

        denied = json.dumps({"username": "eve", "groups": ["nas_users"], "admin": True})
        with mock.patch.dict(os.environ, {"NAS_AUTHENTICATED_IDENTITY_JSON": denied}, clear=True):
            with self.assertRaisesRegex(coding.CodingAgentError, "application.ai-coding.access capability required"):
                coding._check_coding_access()

    def test_missing_or_malformed_identity_fails_closed(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(coding.CodingAgentError, "authenticated identity is required"):
                coding._check_coding_access()
        for value in ("not-json", '{"groups": "not-a-list"}', '{"groups": [123]}'):
            with (
                self.subTest(value=value),
                mock.patch.dict(
                    os.environ,
                    {"NAS_AUTHENTICATED_IDENTITY_JSON": value},
                    clear=True,
                ),
            ):
                with self.assertRaisesRegex(coding.CodingAgentError, "malformed identity JSON"):
                    coding._check_coding_access()

    def test_linux_uid_and_sudo_metadata_never_authorize(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"SUDO_USER": "max", "NAS_CODING_INSECURE_UID_AUTH": "1"},
            clear=True,
        ):
            with self.assertRaisesRegex(coding.CodingAgentError, "authenticated identity is required"):
                coding._check_coding_access()

    def test_main_rejects_non_root_and_missing_credential(self) -> None:
        with mock.patch.object(os, "geteuid", return_value=1000):
            self.assertEqual(coding.main(["/tmp/repo"]), 1)
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            identity = json.dumps({"username": "alice", "groups": [coding.CODING_CAPABILITY_GROUP]})
            with (
                mock.patch.object(os, "geteuid", return_value=0),
                mock.patch.dict(
                    os.environ,
                    {
                        "NAS_CODING_WORKSPACE_ROOTS_JSON": json.dumps([str(root)]),
                        "NAS_PI_CREDENTIAL": str(root / "missing"),
                        "NAS_AUTHENTICATED_IDENTITY_JSON": identity,
                    },
                    clear=True,
                ),
            ):
                self.assertEqual(coding.main([str(repo)]), 1)

    def test_run_checked_raises_on_nonzero_exit(self) -> None:
        with mock.patch.object(coding.subprocess, "run", return_value=mock.Mock(returncode=1)) as run:
            with self.assertRaisesRegex(coding.CodingAgentError, "Command failed with status 1"):
                coding.run_checked(["false"])
        run.assert_called_once_with(["false"], check=False)

    def test_session_command_requires_absolute_executable_and_clamps_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            with mock.patch.dict(os.environ, {"NAS_PI_SESSION_EXEC": "relative-exec"}, clear=True):
                with self.assertRaisesRegex(coding.CodingAgentError, "not configured"):
                    coding.session_command(root, [])
            session_exec = root / "session"
            session_exec.write_text("#!/bin/sh\n", encoding="utf-8")
            for raw, expected in (("not-a-number", "14400"), ("10", "14400"), ("7200", "7200")):
                with (
                    self.subTest(raw=raw),
                    mock.patch.dict(
                        os.environ,
                        {"NAS_PI_SESSION_EXEC": str(session_exec), "NAS_CODING_MAX_RUNTIME_SEC": raw},
                        clear=True,
                    ),
                ):
                    command = coding.session_command(root, [])
                self.assertIn(f"RuntimeMaxSec={expected}", command)


if __name__ == "__main__":
    unittest.main()
