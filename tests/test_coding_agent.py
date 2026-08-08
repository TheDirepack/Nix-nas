from __future__ import annotations

import json
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))

import nas_coding_agent as coding


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
            with mock.patch.dict(os.environ, {"NAS_CODING_WORKSPACE_ROOTS_JSON": json.dumps([str(root)])}):
                self.assertEqual(coding.configured_roots(), (root.resolve(),))
            for malformed in ("not-json", "[]", '["/missing"]'):
                with self.subTest(value=malformed), mock.patch.dict(
                    os.environ, {"NAS_CODING_WORKSPACE_ROOTS_JSON": malformed}
                ):
                    with self.assertRaises((coding.CodingAgentError, FileNotFoundError)):
                        coding.configured_roots()

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
            ):
                command = coding.session_command(root, ["--model", "coding/default"])
            rendered = "\n".join(command)
            self.assertIn("--uid=nas-code-agent", command)
            self.assertIn("--gid=nas-code-agent", command)
            self.assertIn("ProtectSystem=strict", command)
            self.assertIn("NoNewPrivileges=yes", command)
            self.assertIn("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6", command)
            # Network is via dedicated netns with proxy for llama-swap; host loopback blocked except via 10.200.1.1
            self.assertIn("NetworkNamespacePath=/run/netns/pi", command)
            self.assertNotIn("IPAddressDeny=any", command)
            self.assertIn("InaccessiblePaths=/run/nas-secrets", command)
            self.assertIn(f"ReadWritePaths={root}", command)
            self.assertIn(f"LoadCredential=llama-swap-api-key:{credential}", command)
            self.assertNotIn("local-client-secret", rendered)

    def test_nix_integration_keeps_llama_swap_authoritative_and_agent_unprivileged(self) -> None:
        module = (ROOT / "modules" / "ai" / "coding-agent.nix").read_text(encoding="utf-8")
        features = (ROOT / "modules" / "nas" / "internal" / "feature-catalog.nix").read_text(encoding="utf-8")
        capabilities = (ROOT / "modules" / "nas" / "internal" / "capability-registry.nix").read_text(encoding="utf-8")
        secrets = (ROOT / "modules" / "nas" / "internal" / "secret-tools.nix").read_text(encoding="utf-8")
        self.assertIn('baseUrl = "http://${piHostVethIp}:${toString cfg.llamaSwap.port}/v1"', module)
        self.assertIn('apiKey = "LLAMA_SWAP_CODING_API_KEY"', module)
        self.assertNotIn('defaultProjectTrust = "never"', module)
        self.assertIn('--no-extensions --no-skills --no-prompt-templates --no-themes --no-context-files', module)
        self.assertNotIn('--no-approve', module)
        self.assertIn('PI_OFFLINE=1', module)
        self.assertIn('nas-code-agent', module)
        # Network namespace is in the Python sandbox, not in secret-tools
        coding_agent_py = (ROOT / "services" / "nas_coding_agent.py").read_text(encoding="utf-8")
        self.assertIn('NetworkNamespacePath=/run/netns/pi', coding_agent_py)
        self.assertIn('parent = "aiRuntime"', features)
        self.assertIn('access = "coding"', features)
        self.assertIn('allowGroup = "nas_allow_coding"', capabilities)
        self.assertIn('coding-agent-api-key', secrets)
        self.assertIn('LLAMA_SWAP_CODING_API_KEY', secrets)
        self.assertNotIn('OPENROUTER_API_KEY', module)
        self.assertNotIn('ANTHROPIC_API_KEY', module)

    def test_main_wakes_feature_then_runs_transient_session(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            credential = root / "credential"
            credential.write_text("token", encoding="utf-8")
            session_exec = root / "session"
            session_exec.write_text("#!/bin/sh\n", encoding="utf-8")
            completed = mock.Mock(returncode=0)
            with (
                mock.patch.object(os, "geteuid", return_value=0),
                mock.patch.dict(
                    os.environ,
                    {
                        "NAS_CODING_WORKSPACE_ROOTS_JSON": json.dumps([str(root)]),
                        "NAS_PI_CREDENTIAL": str(credential),
                        "NAS_PI_SESSION_EXEC": str(session_exec),
                        "NAS_FEATURE_CONTROL": "/test/nas-feature-control",
                        "NAS_CODING_HEARTBEAT_SECONDS": "3600",
                    },
                ),
                mock.patch.object(coding, "run_checked") as wake,
                mock.patch.object(coding.subprocess, "run", return_value=completed) as run,
            ):
                self.assertEqual(coding.main([str(repo), "--", "--model", "coding/default"]), 0)
            wake.assert_called_once_with(["/test/nas-feature-control", "wake", "aiCoding"])
            self.assertTrue(any(call.args and call.args[0][0] == "systemd-run" for call in run.call_args_list))


    def test_llama_swap_default_uses_configurable_idle_ttl(self):
        internal = (ROOT / "modules" / "ai" / "internal.nix").read_text(encoding="utf-8")
        services = (ROOT / "modules" / "ai" / "services.nix").read_text(encoding="utf-8")
        self.assertIn("globalTTL: ${toString cfg.llamaSwap.globalTtl}", internal)
        self.assertIn("elif cmp -s ${legacyDefaultConfig}", services)


if __name__ == "__main__":
    unittest.main()
