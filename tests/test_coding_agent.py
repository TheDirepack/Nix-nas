from __future__ import annotations

import json
import os
import pathlib
import shutil
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
            with mock.patch.dict(os.environ, {"NAS_CODING_WORKSPACE_ROOTS_JSON": json.dumps([str(root)])}):
                self.assertEqual(coding.configured_roots(), (root.resolve(),))
            for malformed in ("not-json", "[]", '["/missing"]'):
                with (
                    self.subTest(value=malformed),
                    mock.patch.dict(os.environ, {"NAS_CODING_WORKSPACE_ROOTS_JSON": malformed}),
                ):
                    with self.assertRaises((coding.CodingAgentError, FileNotFoundError)):
                        coding.configured_roots()

    def test_session_command_uses_disposable_read_only_podman_container(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            state = root / "state"
            state.mkdir()
            credential = root / "credential"
            credential.write_text("local-client-secret", encoding="utf-8")
            with mock.patch.dict(
                os.environ,
                {
                    "NAS_PI_IMAGE": "nixos-nas-pi-agent:2.2.0-alpha.8",
                    "NAS_PI_CREDENTIAL": str(credential),
                    "NAS_PI_NETWORK": "ns:/run/netns/pi",
                    "NAS_PI_CONTAINER_UID": "954",
                    "NAS_PI_CONTAINER_GID": "954",
                    "NAS_CODING_CPUS": "4",
                    "NAS_CODING_MEMORY": "4g",
                },
            ):
                command = coding.session_command(root, state, ["--model", "coding/default"])
            rendered = "\n".join(command)
            self.assertEqual(command[:2], ["podman", "run"])
            for argument in (
                "--rm",
                "--replace",
                "--read-only",
                "--cap-drop=all",
                "--security-opt=no-new-privileges",
                "--user=954:954",
                "--network=ns:/run/netns/pi",
                "--pids-limit=512",
                "--workdir=/workspace",
            ):
                self.assertIn(argument, command)
            self.assertIn(f"{root}:/workspace:rw", command)
            self.assertIn(f"{state}:/home/pi:rw", command)
            self.assertIn(f"{credential}:/run/secrets/llama-swap-api-key:ro", command)
            self.assertIn("nixos-nas-pi-agent:2.2.0-alpha.8", command)
            self.assertNotIn("local-client-secret", rendered)
            self.assertNotIn("systemd-run", command)

    def test_user_state_is_scoped_to_authenticated_username(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            with (
                mock.patch.dict(
                    os.environ,
                    {
                        "NAS_PI_USER_STATE_ROOT": str(root),
                        "NAS_PI_CONTAINER_UID": "954",
                        "NAS_PI_CONTAINER_GID": "954",
                    },
                ),
                mock.patch.object(os, "chown") as chown,
            ):
                state = coding.ensure_user_state("alice")
            self.assertEqual(state, root.resolve() / "alice")
            self.assertTrue(state.is_dir())
            chown.assert_called_once_with(state, 954, 954)
            escape = root / "mallory"
            escape.symlink_to(root, target_is_directory=True)
            with (
                mock.patch.dict(os.environ, {"NAS_PI_USER_STATE_ROOT": str(root)}),
                self.assertRaisesRegex(coding.CodingAgentError, "real directory"),
            ):
                coding.ensure_user_state("mallory")

    def test_nix_integration_keeps_llama_swap_authoritative_and_agent_unprivileged(self) -> None:
        module = (ROOT / "modules" / "ai" / "coding-agent.nix").read_text(encoding="utf-8")
        features = (ROOT / "modules" / "nas" / "internal" / "feature-catalog.nix").read_text(encoding="utf-8")
        capabilities = (ROOT / "modules" / "nas" / "internal" / "capability-registry.nix").read_text(encoding="utf-8")
        secrets = (ROOT / "modules" / "nas" / "internal" / "secret-tools.nix").read_text(encoding="utf-8")
        coding_agent_py = (ROOT / "services" / "nas_coding_agent.py").read_text(encoding="utf-8")
        self.assertIn("piHostVethIp", module)
        self.assertIn("cfg.llamaSwap.port", module)
        self.assertIn("/v1", module)
        self.assertIn('apiKey = "LLAMA_SWAP_CODING_API_KEY"', module)
        self.assertNotIn('defaultProjectTrust = "never"', module)
        for flag in ("--no-extensions", "--no-skills", "--no-prompt-templates", "--no-themes", "--no-context-files"):
            self.assertIn(flag, module)
        self.assertNotIn("--no-approve", module)
        self.assertIn("PI_OFFLINE=1", module)
        self.assertIn("buildLayeredImage", module)
        self.assertIn("podman load", module)
        self.assertIn("NAS_PI_USER_STATE_ROOT", module)
        self.assertIn("userStateRoot", module)
        self.assertNotIn("environment.systemPackages = [ piPackage launcher ]", module)
        self.assertIn("--read-only", coding_agent_py)
        self.assertIn("--cap-drop=all", coding_agent_py)
        self.assertIn("--network=", coding_agent_py)
        self.assertNotIn("systemd-run", coding_agent_py)
        self.assertIn('parent = "aiRuntime"', features)
        self.assertIn('access = "coding"', features)
        self.assertIn('allowGroup = "nas_allow_coding"', capabilities)
        self.assertIn("coding-agent-api-key", secrets)
        self.assertIn("LLAMA_SWAP_CODING_API_KEY", secrets)
        self.assertNotIn("OPENROUTER_API_KEY", module)
        self.assertNotIn("ANTHROPIC_API_KEY", module)
        self.assertIn("NAS_AUTHENTICATED_IDENTITY_JSON", coding_agent_py)
        self.assertIn("NAS_CODING_INSECURE_UID_AUTH", coding_agent_py)
        if shutil.which("nix") and shutil.which("nix-instantiate"):
            try:
                result = subprocess.run(
                    ["nix-instantiate", "--parse", str(ROOT / "modules" / "ai" / "coding-agent.nix")],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
            except Exception as exc:  # pragma: no cover - host without nix
                self.skipTest(f"nix parse not available: {exc}")
            if "Permission denied" in (result.stderr or "") or "creating directory" in (result.stderr or ""):
                self.skipTest("nix store not available on host (VM-only check)")
            self.assertEqual(result.returncode, 0, f"nix parse failed: {result.stderr}")

    def test_main_wakes_feature_then_runs_disposable_session(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            state = root / "alice-state"
            state.mkdir()
            credential = root / "credential"
            credential.write_text("token", encoding="utf-8")
            completed = mock.Mock(returncode=0)
            identity = json.dumps({"username": "alice", "groups": ["nas_allow_coding"]})
            with (
                mock.patch.object(os, "geteuid", return_value=0),
                mock.patch.dict(
                    os.environ,
                    {
                        "NAS_CODING_WORKSPACE_ROOTS_JSON": json.dumps([str(root)]),
                        "NAS_PI_CREDENTIAL": str(credential),
                        "NAS_PI_IMAGE": "nixos-nas-pi-agent:2.2.0-alpha.8",
                        "NAS_PI_NETWORK": "ns:/run/netns/pi",
                        "NAS_FEATURE_CONTROL": "/test/nas-feature-control",
                        "NAS_CODING_HEARTBEAT_SECONDS": "3600",
                        "NAS_AUTHENTICATED_IDENTITY_JSON": identity,
                    },
                ),
                mock.patch.object(coding, "ensure_user_state", return_value=state) as ensure_state,
                mock.patch.object(coding, "run_checked") as wake,
                mock.patch.object(coding.subprocess, "run", return_value=completed) as run,
            ):
                self.assertEqual(coding.main([str(repo), "--", "--model", "coding/default"]), 0)
            wake.assert_called_once_with(["/test/nas-feature-control", "wake", "aiCoding"])
            ensure_state.assert_called_once_with("alice")
            self.assertTrue(any(call.args and call.args[0][0:2] == ["podman", "run"] for call in run.call_args_list))

    def test_llama_swap_default_uses_configurable_idle_ttl(self):
        internal = (ROOT / "modules" / "ai" / "internal.nix").read_text(encoding="utf-8")
        services = (ROOT / "modules" / "ai" / "services.nix").read_text(encoding="utf-8")
        self.assertIn("globalTTL: ${toString cfg.llamaSwap.globalTtl}", internal)
        self.assertIn("elif cmp -s ${legacyDefaultConfig}", services)

    def test_workspace_validation_rejects_missing_and_file_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            missing = root / "missing"
            with self.assertRaisesRegex(coding.CodingAgentError, "does not exist"):
                coding.validate_workspace(str(missing), (root,))
            plain_file = root / "file"
            plain_file.write_text("", encoding="utf-8")
            with self.assertRaisesRegex(coding.CodingAgentError, "not a directory"):
                coding.validate_workspace(str(plain_file), (root,))

    def test_run_checked_raises_on_nonzero_exit(self) -> None:
        with mock.patch.object(coding.subprocess, "run", return_value=mock.Mock(returncode=1)) as run:
            with self.assertRaisesRegex(coding.CodingAgentError, "Command failed with status 1"):
                coding.run_checked(["false"])
        run.assert_called_once_with(["false"], check=False)

    def test_session_command_requires_image_and_valid_network(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            state = root / "state"
            state.mkdir()
            with mock.patch.dict(os.environ, {"NAS_PI_IMAGE": ""}, clear=True):
                with self.assertRaisesRegex(coding.CodingAgentError, "image is not configured"):
                    coding.session_command(root, state, [])
            with mock.patch.dict(
                os.environ,
                {"NAS_PI_IMAGE": "image:tag", "NAS_PI_NETWORK": "bad network"},
                clear=True,
            ):
                with self.assertRaisesRegex(coding.CodingAgentError, "network is invalid"):
                    coding.session_command(root, state, [])

    def test_session_command_clamps_max_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            state = root / "state"
            state.mkdir()
            base_env = {"NAS_PI_IMAGE": "image:tag", "NAS_PI_NETWORK": "ns:/run/netns/pi"}
            with mock.patch.dict(os.environ, {**base_env, "NAS_CODING_MAX_RUNTIME_SEC": "not-a-number"}):
                command = coding.session_command(root, state, [])
            self.assertIn("--timeout=14400", command)
            with mock.patch.dict(os.environ, {**base_env, "NAS_CODING_MAX_RUNTIME_SEC": "10"}):
                command = coding.session_command(root, state, [])
            self.assertIn("--timeout=14400", command)
            with mock.patch.dict(os.environ, {**base_env, "NAS_CODING_MAX_RUNTIME_SEC": "7200"}):
                command = coding.session_command(root, state, [])
            self.assertIn("--timeout=7200", command)

    def test_heartbeat_wakes_feature_until_stopped(self) -> None:
        stop = threading.Event()
        with mock.patch.object(coding.subprocess, "run") as run:
            stop.set()
            coding.heartbeat(stop, "nas-feature-control", 1)
        run.assert_not_called()

    def test_heartbeat_loop_runs_while_not_stopped(self) -> None:
        stop = threading.Event()
        with mock.patch.object(coding.subprocess, "run") as run:
            with mock.patch.object(threading.Event, "wait", side_effect=[False, True]):
                coding.heartbeat(stop, "nas-feature-control", 1)
        self.assertTrue(run.called)
        self.assertIn("nas-feature-control", run.call_args.args[0])

    def test_identity_json_coding_capability_allowed(self) -> None:
        identity = json.dumps({"username": "alice", "groups": ["nas_allow_coding"]})
        with mock.patch.dict(os.environ, {"NAS_AUTHENTICATED_IDENTITY_JSON": identity}, clear=True):
            self.assertEqual(coding._check_coding_access(), "alice")
        admin_identity = json.dumps({"username": "bob", "groups": ["nas_admin"]})
        with mock.patch.dict(os.environ, {"NAS_AUTHENTICATED_IDENTITY_JSON": admin_identity}, clear=True):
            self.assertEqual(coding._check_coding_access(), "bob")
        admin_flag = json.dumps({"username": "carol", "groups": [], "admin": True})
        with mock.patch.dict(os.environ, {"NAS_AUTHENTICATED_IDENTITY_JSON": admin_flag}, clear=True):
            self.assertEqual(coding._check_coding_access(), "carol")

    def test_identity_json_no_capability_denied(self) -> None:
        identity = json.dumps({"username": "eve", "groups": ["nas_users"]})
        with mock.patch.dict(os.environ, {"NAS_AUTHENTICATED_IDENTITY_JSON": identity}, clear=True):
            with self.assertRaisesRegex(coding.CodingAgentError, "coding capability required"):
                coding._check_coding_access()

    def test_invalid_identity_username_denied_before_storage_selection(self) -> None:
        identity = json.dumps({"username": "../escape", "groups": ["nas_allow_coding"]})
        with mock.patch.dict(os.environ, {"NAS_AUTHENTICATED_IDENTITY_JSON": identity}, clear=True):
            with self.assertRaisesRegex(coding.CodingAgentError, "invalid username"):
                coding._check_coding_access()

    def test_sudo_user_without_identity_no_insecure_flag_denied(self) -> None:
        with mock.patch.dict(os.environ, {"SUDO_USER": "max"}, clear=True):
            with self.assertRaisesRegex(coding.CodingAgentError, "requires authenticated identity"):
                coding._check_coding_access()

    def test_sudo_user_with_insecure_flag_and_linux_group_allowed(self) -> None:
        class FakeGroup:
            def __init__(self, name: str, members: list[str]) -> None:
                self.gr_name = name
                self.gr_mem = members

        grp = mock.Mock()
        pwd = mock.Mock()
        pwd.getpwnam.return_value = mock.Mock(pw_name="max")
        grp.getgrall.return_value = [FakeGroup("nas_allow_coding", ["max"])]
        modules = {"grp": grp, "pwd": pwd}
        with mock.patch.dict(os.environ, {"SUDO_USER": "max", "NAS_CODING_INSECURE_UID_AUTH": "1"}, clear=True):
            with mock.patch.dict(sys.modules, modules):
                with mock.patch.object(
                    coding.subprocess, "run", return_value=mock.Mock(returncode=1, stdout="", stderr="")
                ):
                    self.assertEqual(coding._check_coding_access(), "max")

    def test_root_no_sudo_user_no_identity_denied(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            with mock.patch.object(os, "geteuid", return_value=0):
                with self.assertRaisesRegex(coding.CodingAgentError, "direct root invocation denied"):
                    coding._check_coding_access()

    def test_malformed_identity_json_denied(self) -> None:
        for bad in ("not-json", '{"groups": "not-a-list"}', '{"groups": [123]}'):
            with self.subTest(bad=bad):
                with mock.patch.dict(os.environ, {"NAS_AUTHENTICATED_IDENTITY_JSON": bad}, clear=True):
                    with self.assertRaisesRegex(coding.CodingAgentError, "malformed identity JSON"):
                        coding._check_coding_access()

    def test_check_coding_access_grants_admin_and_denies_others(self) -> None:
        class FakeGroup:
            def __init__(self, name: str, members: list[str]) -> None:
                self.gr_name = name
                self.gr_mem = members

        grp = mock.Mock()
        pwd = mock.Mock()
        pwd.getpwnam.return_value = mock.Mock(pw_name="max")
        grp.getgrall.return_value = []
        modules = {"grp": grp, "pwd": pwd}
        with mock.patch.dict(os.environ, {"SUDO_USER": "max", "NAS_CODING_INSECURE_UID_AUTH": "1"}, clear=True):
            with mock.patch.dict(sys.modules, modules):
                grp.getgrall.return_value = [FakeGroup("nas_admin", ["max"])]
                self.assertEqual(coding._check_coding_access(), "max")
                grp.getgrall.return_value = [FakeGroup("wheel", ["someone-else"])]
                with mock.patch.object(
                    coding.subprocess, "run", return_value=mock.Mock(returncode=0, stdout="wheel\n")
                ):
                    with self.assertRaisesRegex(coding.CodingAgentError, "not in nas_allow_coding"):
                        coding._check_coding_access()
                grp.getgrall.return_value = []
                with mock.patch.object(
                    coding.subprocess, "run", return_value=mock.Mock(returncode=0, stdout="nas_admin\n")
                ):
                    self.assertEqual(coding._check_coding_access(), "max")
                grp.getgrall.return_value = []
                with mock.patch.object(
                    coding.subprocess,
                    "run",
                    return_value=mock.Mock(returncode=1, stdout="", stderr="err"),
                ):
                    with self.assertRaisesRegex(coding.CodingAgentError, "not in nas_allow_coding"):
                        coding._check_coding_access()
                grp.getgrall.return_value = []
                pwd.getpwnam.side_effect = KeyError("max")
                with mock.patch.object(
                    coding.subprocess, "run", return_value=mock.Mock(returncode=0, stdout="wheel\n")
                ):
                    with self.assertRaisesRegex(coding.CodingAgentError, "not in nas_allow_coding"):
                        coding._check_coding_access()

    def test_check_coding_access_root_and_missing_user(self) -> None:
        with mock.patch.dict(os.environ, {"SUDO_USER": "root", "NAS_CODING_INSECURE_UID_AUTH": "0"}, clear=True):
            with self.assertRaisesRegex(coding.CodingAgentError, "requires authenticated identity"):
                coding._check_coding_access()
        with mock.patch.dict(os.environ, {"SUDO_USER": ""}, clear=True):
            with mock.patch.object(os, "geteuid", return_value=0):
                with self.assertRaisesRegex(coding.CodingAgentError, "direct root invocation denied"):
                    coding._check_coding_access()
        with mock.patch.dict(os.environ, {}, clear=True):
            with mock.patch.object(os, "geteuid", return_value=0):
                with self.assertRaisesRegex(coding.CodingAgentError, "direct root invocation denied"):
                    coding._check_coding_access()

    def test_main_non_root_and_missing_credential(self) -> None:
        with mock.patch.object(os, "geteuid", return_value=1000):
            self.assertEqual(coding.main(["/tmp/repo"]), 1)
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            missing_credential = root / "missing-cred"
            identity = json.dumps({"username": "alice", "groups": ["nas_allow_coding"]})
            with (
                mock.patch.object(os, "geteuid", return_value=0),
                mock.patch.dict(
                    os.environ,
                    {
                        "NAS_CODING_WORKSPACE_ROOTS_JSON": json.dumps([str(root)]),
                        "NAS_PI_CREDENTIAL": str(missing_credential),
                        "NAS_AUTHENTICATED_IDENTITY_JSON": identity,
                    },
                    clear=True,
                ),
            ):
                self.assertEqual(coding.main([str(repo)]), 1)


if __name__ == "__main__":
    unittest.main()
