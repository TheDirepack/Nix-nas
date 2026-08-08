from __future__ import annotations

import importlib.util
import os
import pathlib
import shlex
import tempfile
import unittest
from unittest import mock

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("nas_ai_config", ROOT / "services" / "nas_ai_config.py")
assert SPEC and SPEC.loader
ai = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ai)


class AiConfigTests(unittest.TestCase):
    def make_config(self, directory: str) -> pathlib.Path:
        path = pathlib.Path(directory) / "config.yaml"
        path.write_text(
            yaml.safe_dump(
                {
                    "healthCheckTimeout": 300,
                    "logLevel": "info",
                    "apiKeys": ["${env.LLAMA_SWAP_API_KEY}"],
                    "models": {"local-small": {"cmd": "llama-server --port ${PORT}"}},
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        os.chmod(path, 0o640)
        return path

    def test_provider_secret_is_environment_reference_and_never_plaintext(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self.make_config(temporary)
            view = ai.set_provider(
                "openrouter",
                "https://openrouter.ai/api",
                ["qwen/qwen3", "deepseek/deepseek-v3"],
                credential=True,
                timeouts={"connect": 20, "responseHeader": 120},
                filters={"stripParams": "top_k", "setParams": {"provider": {"zdr": True}}},
                path=path,
            )
            raw = path.read_text(encoding="utf-8")
            self.assertIn("${env.LLAMA_SWAP_PEER_OPENROUTER_API_KEY}", raw)
            self.assertNotIn("secret-provider-key", raw)
            provider = view["providers"][0]
            self.assertTrue(provider["credentialConfigured"])
            self.assertEqual(provider["timeouts"]["responseHeader"], 120)
            self.assertEqual(provider["filters"]["setParams"]["provider"]["zdr"], True)

    def test_plaintext_peer_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self.make_config(temporary)
            config = yaml.safe_load(path.read_text(encoding="utf-8"))
            config["peers"] = {"bad": {"proxy": "https://example.test", "models": ["m"], "apiKey": "plaintext"}}
            path.write_text(yaml.safe_dump(config), encoding="utf-8")
            with self.assertRaisesRegex(ai.AiConfigError, "plaintext provider keys are forbidden"):
                ai.load_config(path)

    def test_provider_ids_and_secret_references_are_unambiguous(self):
        self.assertEqual(ai.provider_env_name("foo-bar"), "LLAMA_SWAP_PEER_FOO_BAR_API_KEY")
        with self.assertRaisesRegex(ai.AiConfigError, "lowercase letters, digits, and hyphens"):
            ai.validate_provider_id("foo_bar")
        with tempfile.TemporaryDirectory() as temporary:
            path = self.make_config(temporary)
            config = yaml.safe_load(path.read_text(encoding="utf-8"))
            config["peers"] = {
                "cloud": {
                    "proxy": "https://cloud.example",
                    "models": ["coder"],
                    "apiKey": "${env.LLAMA_SWAP_API_KEY}",
                }
            }
            path.write_text(yaml.safe_dump(config), encoding="utf-8")
            with self.assertRaisesRegex(ai.AiConfigError, r"(must use its derived environment variable|reserved credential)"):
                ai.load_config(path)

    def test_role_routes_to_local_and_remote_targets_with_strategy(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self.make_config(temporary)
            ai.set_provider("cloud", "https://cloud.example", ["coder"], credential=False, path=path)
            view = ai.set_role(
                "coding/default",
                ["local-small", "cloud/coder"],
                strategy="spillover",
                spillover=3,
                path=path,
            )
            self.assertEqual(view["codingRoles"]["coding/default"]["targets"], ["local-small", "cloud/coder"])
            self.assertEqual(view["codingRoles"]["coding/default"]["strategy"], "spillover")
            self.assertEqual(view["codingRoles"]["coding/default"]["spillover"], 3)

    def test_selector_ids_cannot_collide_with_peer_targets(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self.make_config(temporary)
            ai.set_provider("coding", "https://cloud.example", ["default"], credential=False, path=path)
            with self.assertRaisesRegex(ai.AiConfigError, "collides with a model target"):
                ai.set_role("coding/default", ["coding/default"], path=path)

    def test_delete_provider_removes_role_targets_but_keeps_local_fallback(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self.make_config(temporary)
            ai.set_provider("cloud", "https://cloud.example", ["coder"], credential=False, path=path)
            ai.set_role("coding/default", ["cloud/coder", "local-small"], path=path)
            view = ai.delete_provider("cloud", path=path)
            self.assertEqual(view["codingRoles"]["coding/default"]["targets"], ["local-small"])

    def test_provider_validation_rejects_credential_url_and_model_whitespace(self):
        with self.assertRaises(ai.AiConfigError):
            ai.validate_proxy_url("https://user:secret@example.com")
        with self.assertRaises(ai.AiConfigError):
            ai.validate_model_id("bad model")

    def test_provider_filter_cannot_override_model(self):
        with self.assertRaisesRegex(ai.AiConfigError, "protected model"):
            ai.validate_filters({"setParams": {"model": "other"}})

    def test_advanced_runtime_exposes_model_lifecycle_controls(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self.make_config(temporary)
            view = ai.replace_advanced(
                {"globalTTL": 180, "unloadTimeout": 15, "healthCheckTimeout": 240},
                path=path,
            )
            self.assertEqual(view["advanced"]["globalTTL"], 180)
            self.assertEqual(view["advanced"]["unloadTimeout"], 15)
            config = yaml.safe_load(path.read_text(encoding="utf-8"))
            self.assertEqual(config["globalTTL"], 180)
            self.assertEqual(config["unloadTimeout"], 15)

    def test_atomic_write_syncs_parent_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self.make_config(temporary)
            config = ai.load_config(path)
            with mock.patch.object(ai.os, "fsync", wraps=ai.os.fsync) as fsync:
                ai.atomic_write(config, path)
            self.assertGreaterEqual(fsync.call_count, 2)

    def test_local_model_is_structured_and_shell_quoted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary) / "models"
            root.mkdir()
            model = root / "Qwen $(not-a-command) model.gguf"
            model.write_bytes(b"gguf")
            server = pathlib.Path(temporary) / "llama-server"
            server.write_text("", encoding="utf-8")
            path = self.make_config(temporary)
            old_root = os.environ.get("NAS_AI_MODEL_ROOT")
            old_server = os.environ.get("NAS_LLAMA_SERVER")
            os.environ["NAS_AI_MODEL_ROOT"] = str(root)
            os.environ["NAS_LLAMA_SERVER"] = str(server)
            try:
                view = ai.set_local_model(
                    "qwen-local",
                    str(model),
                    context=65536,
                    ttl=300,
                    tools=True,
                    extra_args=["--flash-attn=on", "--temp=0.4;echo-not-run"],
                    path=path,
                )
            finally:
                if old_root is None:
                    os.environ.pop("NAS_AI_MODEL_ROOT", None)
                else:
                    os.environ["NAS_AI_MODEL_ROOT"] = old_root
                if old_server is None:
                    os.environ.pop("NAS_LLAMA_SERVER", None)
                else:
                    os.environ["NAS_LLAMA_SERVER"] = old_server
            config = yaml.safe_load(path.read_text(encoding="utf-8"))
            model_config = config["models"]["qwen-local"]
            argv = shlex.split(model_config["cmd"])
            self.assertEqual(argv[0], str(server))
            self.assertEqual(argv[argv.index("--model") + 1], str(model.resolve()))
            self.assertEqual(argv[argv.index("--port") + 1], "${PORT}")
            self.assertIn("--temp=0.4;echo-not-run", argv)
            self.assertEqual(model_config["capabilities"]["context"], 65536)
            self.assertTrue(model_config["capabilities"]["tools"])
            local = next(item for item in view["localModels"] if item["id"] == "qwen-local")
            self.assertTrue(local["managed"])
            self.assertEqual(local["path"], str(model.resolve()))

    def test_local_model_rejects_path_escape_and_managed_launcher_flags(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary) / "models"
            root.mkdir()
            outside = pathlib.Path(temporary) / "outside.gguf"
            outside.write_bytes(b"gguf")
            link = root / "escape.gguf"
            link.symlink_to(outside)
            old_root = os.environ.get("NAS_AI_MODEL_ROOT")
            os.environ["NAS_AI_MODEL_ROOT"] = str(root)
            try:
                with self.assertRaisesRegex(ai.AiConfigError, "must stay beneath"):
                    ai.validate_local_model_path(str(link))
                with self.assertRaisesRegex(ai.AiConfigError, "managed by the NAS"):
                    ai.validate_local_extra_args(["--host=0.0.0.0"])
                with self.assertRaisesRegex(ai.AiConfigError, "managed by the NAS"):
                    ai.validate_local_extra_args(["--ctx-size=1048576"])
                with self.assertRaisesRegex(ai.AiConfigError, "managed by the NAS"):
                    ai.validate_local_extra_args(["-c", "1048576"])
            finally:
                if old_root is None:
                    os.environ.pop("NAS_AI_MODEL_ROOT", None)
                else:
                    os.environ["NAS_AI_MODEL_ROOT"] = old_root

    def test_delete_local_model_removes_role_target_without_deleting_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary) / "models"
            root.mkdir()
            model = root / "local.gguf"
            model.write_bytes(b"gguf")
            server = pathlib.Path(temporary) / "llama-server"
            server.write_text("", encoding="utf-8")
            path = self.make_config(temporary)
            old_root = os.environ.get("NAS_AI_MODEL_ROOT")
            old_server = os.environ.get("NAS_LLAMA_SERVER")
            os.environ["NAS_AI_MODEL_ROOT"] = str(root)
            os.environ["NAS_LLAMA_SERVER"] = str(server)
            try:
                ai.set_local_model("managed", str(model), context=8192, ttl=60, tools=False, path=path)
                ai.set_role("coding/local-worker", ["managed"], path=path)
                view = ai.delete_local_model("managed", path=path)
            finally:
                if old_root is None:
                    os.environ.pop("NAS_AI_MODEL_ROOT", None)
                else:
                    os.environ["NAS_AI_MODEL_ROOT"] = old_root
                if old_server is None:
                    os.environ.pop("NAS_LLAMA_SERVER", None)
                else:
                    os.environ["NAS_LLAMA_SERVER"] = old_server
            self.assertTrue(model.exists())
            self.assertEqual(view["codingRoles"]["coding/local-worker"]["targets"], [])

    def test_provider_secret_names_and_proxy_url_validation(self):
        self.assertEqual(ai.provider_secret_name("openrouter"), "ai-provider-openrouter")
        self.assertEqual(ai.validate_proxy_url("https://example.test/"), "https://example.test")
        for bad, match in (
            ("ftp://example.test", r"http\(s\) URL"),
            ("relative/path", r"http\(s\) URL"),
            ("https://example.test#frag", "fragment"),
            ("https://user:pass@example.test", "credentials"),
            ("https://example.test/\x07", "Provider URL is invalid"),
            ("x" * 2049, "Provider URL is invalid"),
        ):
            with self.assertRaisesRegex(ai.AiConfigError, match):
                ai.validate_proxy_url(bad)

    def test_model_and_role_id_validation_edge_cases(self):
        for bad in (None, "", "x" * 257, "with space", "with\tcontrol"):
            with self.assertRaises(ai.AiConfigError):
                ai.validate_model_id(bad)
        for bad in ("", "-bad", "bad.gguf!"):
            with self.assertRaisesRegex(ai.AiConfigError, "Local model ID"):
                ai.validate_local_model_id(bad)
        with self.assertRaisesRegex(ai.AiConfigError, "Unknown coding model role"):
            ai.validate_role("coding/nope")

    def test_local_model_root_and_llama_server_validation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary) / "models"
            root.mkdir()
            not_a_dir = pathlib.Path(temporary) / "file"
            not_a_dir.write_text("", encoding="utf-8")
            old = os.environ.get("NAS_AI_MODEL_ROOT")
            os.environ["NAS_AI_MODEL_ROOT"] = str(root)
            try:
                self.assertEqual(ai.local_model_root(), root.resolve())
            finally:
                if old is None:
                    os.environ.pop("NAS_AI_MODEL_ROOT", None)
                else:
                    os.environ["NAS_AI_MODEL_ROOT"] = old
            for env, match in (
                ("relative/models", "must be an absolute path"),
                (str(not_a_dir), "not a directory"),
            ):
                os.environ["NAS_AI_MODEL_ROOT"] = env
                try:
                    with self.assertRaisesRegex(ai.AiConfigError, match):
                        ai.local_model_root()
                finally:
                    if old is None:
                        os.environ.pop("NAS_AI_MODEL_ROOT", None)
                    else:
                        os.environ["NAS_AI_MODEL_ROOT"] = old
            old_server = os.environ.get("NAS_LLAMA_SERVER")
            os.environ["NAS_LLAMA_SERVER"] = "not/absolute"
            try:
                with self.assertRaisesRegex(ai.AiConfigError, "safe absolute path"):
                    ai.llama_server_path()
            finally:
                if old_server is None:
                    os.environ.pop("NAS_LLAMA_SERVER", None)
                else:
                    os.environ["NAS_LLAMA_SERVER"] = old_server

    def test_local_model_path_validation_rejects_bad_suffixes_and_types(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary) / "models"
            root.mkdir()
            gguf = root / "ok.gguf"
            gguf.write_bytes(b"gguf")
            not_gguf = root / "ok.txt"
            not_gguf.write_text("", encoding="utf-8")
            old = os.environ.get("NAS_AI_MODEL_ROOT")
            os.environ["NAS_AI_MODEL_ROOT"] = str(root)
            try:
                self.assertEqual(ai.validate_local_model_path(str(gguf)), gguf.resolve())
                for bad in ("", "relative/path", str(not_gguf), str(root)):
                    with self.assertRaises(ai.AiConfigError):
                        ai.validate_local_model_path(bad)
            finally:
                if old is None:
                    os.environ.pop("NAS_AI_MODEL_ROOT", None)
                else:
                    os.environ["NAS_AI_MODEL_ROOT"] = old

    def test_timeouts_and_filters_validation_edge_cases(self):
        with self.assertRaisesRegex(ai.AiConfigError, "Unknown provider timeout field"):
            ai.validate_timeouts({"nope": 1})
        for bad in (True, "10", -1, 3601):
            with self.assertRaises(ai.AiConfigError):
                ai.validate_timeouts({"connect": bad})
        with self.assertRaisesRegex(ai.AiConfigError, "Unknown provider filter field"):
            ai.validate_filters({"nope": 1})
        with self.assertRaisesRegex(ai.AiConfigError, "stripParams"):
            ai.validate_filters({"stripParams": "\x01"})
        with self.assertRaisesRegex(ai.AiConfigError, "setParams must be a JSON object"):
            ai.validate_filters({"setParams": ["a"]})
        with self.assertRaisesRegex(ai.AiConfigError, "too large"):
            ai.validate_filters({"setParams": {"pad": "x" * 70000}})
        self.assertEqual(ai.validate_timeouts({}), {})
        self.assertEqual(ai.validate_filters({"stripParams": " top_k "})["stripParams"], "top_k")

    def test_selector_strategy_validation(self):
        with self.assertRaisesRegex(ai.AiConfigError, "warm, pin, or spillover"):
            ai.validate_selector_settings("auto", 1)
        for bad in (True, "3", 0, 129):
            with self.assertRaisesRegex(ai.AiConfigError, "Spillover"):
                ai.validate_selector_settings("spillover", bad)
        self.assertEqual(ai.validate_selector_settings("warm", 5), ("warm", {}))

    def test_load_config_rejects_bad_yaml_and_unreadable_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            bad = pathlib.Path(temporary) / "bad.yaml"
            bad.write_text("{unclosed", encoding="utf-8")
            with self.assertRaisesRegex(ai.AiConfigError, "invalid YAML"):
                ai.load_config(bad)
            with self.assertRaisesRegex(ai.AiConfigError, "Unable to read"):
                ai.load_config(pathlib.Path(temporary) / "missing.yaml")

    def test_load_config_rejects_oversized_and_malformed_schemas(self):
        with tempfile.TemporaryDirectory() as temporary:
            big = pathlib.Path(temporary) / "big.yaml"
            big.write_text("# pad\n" * 600000, encoding="utf-8")
            with self.assertRaisesRegex(ai.AiConfigError, "unexpectedly large"):
                ai.load_config(big)
            weird = pathlib.Path(temporary) / "weird.yaml"
            weird.write_text('peers: ["not", "a", "dict"]\nmodels: {}\nselectors: {}\n', encoding="utf-8")
            with self.assertRaisesRegex(ai.AiConfigError, "must be an object"):
                ai.load_config(weird)

    def test_validate_selector_namespace_self_targeting(self):
        with self.assertRaisesRegex(ai.AiConfigError, "cannot target itself"):
            ai.validate_selector_namespace(
                {"models": {}, "peers": {}, "selectors": {"coding/default": {"targets": ["coding/default"]}}}
            )
        # non-string selector IDs are rejected by _require_mapping earlier
        with self.assertRaisesRegex(ai.AiConfigError, "must be an object"):
            ai.validate_selector_namespace({"models": {}, "peers": {}, "selectors": {1: {}}})

    def test_atomic_write_rejects_unsafe_parent_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            blocker = pathlib.Path(temporary) / "blocker"
            blocker.write_text("", encoding="utf-8")
            unsafe = blocker / "config.yaml"
            with self.assertRaisesRegex(ai.AiConfigError, "Unsafe llama-swap configuration directory"):
                ai.atomic_write({"models": {}}, unsafe)

    def test_provider_credential_staged_reads_secret_env(self):
        with tempfile.TemporaryDirectory() as temporary:
            secret_root = pathlib.Path(temporary)
            env_file = secret_root / "ai" / "llama-swap.env"
            env_file.parent.mkdir(parents=True)
            env_file.write_text("LLAMA_SWAP_PEER_OPENROUTER_API_KEY=staged\n", encoding="utf-8")
            old = os.environ.get("NAS_SECRET_ROOT")
            os.environ["NAS_SECRET_ROOT"] = str(secret_root)
            try:
                self.assertTrue(ai._provider_credential_staged("openrouter"))
                self.assertFalse(ai._provider_credential_staged("nope"))
                self.assertIsNone(ai._provider_credential_staged("bad_provider"))
            finally:
                if old is None:
                    os.environ.pop("NAS_SECRET_ROOT", None)
                else:
                    os.environ["NAS_SECRET_ROOT"] = old
            os.environ["NAS_SECRET_ROOT"] = str(pathlib.Path(temporary) / "empty")
            try:
                self.assertFalse(ai._provider_credential_staged("openrouter"))
            finally:
                if old is None:
                    os.environ.pop("NAS_SECRET_ROOT", None)
                else:
                    os.environ["NAS_SECRET_ROOT"] = old

    def test_public_view_defaults_for_missing_roles_and_non_selector_settings(self):
        config = {
            "models": {"local-small": {"cmd": "echo hi"}},
            "peers": {
                "cloud": {
                    "proxy": "https://cloud.example",
                    "models": ["coder"],
                    "apiKey": "${env.LLAMA_SWAP_API_KEY}",
                }
            },
            "selectors": {
                "coding/default": {"targets": ["cloud/coder"], "strategy": "warm", "settings": "not-a-dict"}
            },
        }
        view = ai.public_view(config)
        self.assertEqual(view["codingRoles"]["coding/default"]["spillover"], 1)
        self.assertEqual(view["codingRoles"]["coding/cheap"]["targets"], [])
        self.assertEqual(view["providers"][0]["credentialEnv"], "LLAMA_SWAP_API_KEY")

    def test_validate_with_llama_swap_falls_back_when_binary_missing(self):
        with tempfile.TemporaryDirectory() as temporary:
            candidate = pathlib.Path(temporary) / "candidate.yaml"
            candidate.write_text("models: {}\n", encoding="utf-8")
            with mock.patch.object(ai.shutil, "which", return_value=None):
                self.assertIsNone(ai._validate_with_llama_swap(candidate))
            with mock.patch.object(ai.shutil, "which", return_value=str(pathlib.Path(temporary) / "missing-bin")):
                self.assertIsNone(ai._validate_with_llama_swap(candidate))

    def test_validate_with_llama_swap_parses_binary_probe_results(self):
        with tempfile.TemporaryDirectory() as temporary:
            candidate = pathlib.Path(temporary) / "candidate.yaml"
            candidate.write_text("models: {}\n", encoding="utf-8")
            exe = pathlib.Path(temporary) / "llama-swap"
            exe.write_text("", encoding="utf-8")
            with mock.patch.object(ai.shutil, "which", return_value=str(exe)):
                ok = mock.Mock(returncode=0, stderr=b"", stdout=b"")
                with mock.patch.object(ai.subprocess, "run", return_value=ok) as run:
                    self.assertIsNone(ai._validate_with_llama_swap(candidate))
                self.assertEqual(run.call_count, 1)
                unknown_flag = mock.Mock(returncode=2, stderr=b"unknown flag: --validate", stdout=b"")
                with mock.patch.object(ai.subprocess, "run", return_value=unknown_flag):
                    self.assertIsNone(ai._validate_with_llama_swap(candidate))
                rejected = mock.Mock(returncode=1, stderr=b"models: yaml error", stdout=b"")
                with mock.patch.object(ai.subprocess, "run", return_value=rejected):
                    with self.assertRaisesRegex(ai.AiConfigError, "llama-swap rejected"):
                        ai._validate_with_llama_swap(candidate)
                with mock.patch.object(ai.subprocess, "run", side_effect=ai.subprocess.TimeoutExpired("probe", 5)):
                    self.assertIsNone(ai._validate_with_llama_swap(candidate))
                with mock.patch.object(ai.subprocess, "run", side_effect=OSError("boom")):
                    self.assertIsNone(ai._validate_with_llama_swap(candidate))

    def test_set_provider_preserves_old_timeouts_filters_and_api_key(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self.make_config(temporary)
            ai.set_provider(
                "cloud",
                "https://cloud.example",
                ["coder"],
                credential=True,
                timeouts={"connect": 30},
                filters={"stripParams": "top_k"},
                path=path,
            )
            view = ai.set_provider("cloud", "https://cloud.example", ["coder"], credential=False, path=path)
            provider = view["providers"][0]
            self.assertEqual(provider["timeouts"]["connect"], 30)
            self.assertEqual(provider["filters"]["stripParams"], "top_k")
            self.assertEqual(provider["credentialEnv"], "LLAMA_SWAP_PEER_CLOUD_API_KEY")
            self.assertTrue(provider["credentialReferenceConfigured"])

    def test_delete_provider_removes_role_that_has_no_remaining_targets(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self.make_config(temporary)
            ai.set_provider("solo", "https://solo.example", ["only"], credential=False, path=path)
            ai.set_role("coding/research", ["solo/only"], path=path)
            view = ai.delete_provider("solo", path=path)
            self.assertEqual(view["codingRoles"]["coding/research"]["targets"], [])
            # second delete is a no-op
            view = ai.delete_provider("solo", path=path)
            self.assertEqual(view["providers"], [])

    def test_set_local_model_validation_and_managed_overwrite_guard(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary) / "models"
            root.mkdir()
            model = root / "m.gguf"
            model.write_bytes(b"gguf")
            path = self.make_config(temporary)
            old_root = os.environ.get("NAS_AI_MODEL_ROOT")
            os.environ["NAS_AI_MODEL_ROOT"] = str(root)
            try:
                for overrides, match in (
                    ({"context": 512}, "context"),
                    ({"context": True}, "context"),
                    ({"ttl": 9999999}, "TTL"),
                    ({"tools": "yes"}, "boolean"),
                ):
                    args = {"context": 8192, "ttl": 60, "tools": False}
                    args.update(overrides)
                    with self.assertRaisesRegex(ai.AiConfigError, match):
                        ai.set_local_model("m", str(model), path=path, **args)
                config = yaml.safe_load(path.read_text(encoding="utf-8"))
                config.setdefault("models", {})["admin-model"] = {"cmd": "echo hi", "metadata": {}}
                path.write_text(yaml.safe_dump(config), encoding="utf-8")
                with self.assertRaisesRegex(ai.AiConfigError, "cannot be overwritten"):
                    ai.set_local_model("admin-model", str(model), context=8192, ttl=60, tools=False, path=path)
            finally:
                if old_root is None:
                    os.environ.pop("NAS_AI_MODEL_ROOT", None)
                else:
                    os.environ["NAS_AI_MODEL_ROOT"] = old_root

    def test_delete_local_model_guards(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self.make_config(temporary)
            with self.assertRaisesRegex(ai.AiConfigError, "does not exist"):
                ai.delete_local_model("missing", path=path)
            config = yaml.safe_load(path.read_text(encoding="utf-8"))
            config.setdefault("models", {})["admin-model"] = {"cmd": "echo hi", "metadata": {}}
            path.write_text(yaml.safe_dump(config), encoding="utf-8")
            with self.assertRaisesRegex(ai.AiConfigError, "cannot be deleted"):
                ai.delete_local_model("admin-model", path=path)

    def test_set_role_requires_targets_and_known_targets(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self.make_config(temporary)
            with self.assertRaisesRegex(ai.AiConfigError, "at least one target"):
                ai.set_role("coding/default", [], path=path)
            ai.set_provider("cloud", "https://cloud.example", ["coder"], credential=False, path=path)
            with self.assertRaisesRegex(ai.AiConfigError, "Unknown model target"):
                ai.set_role("coding/default", ["cloud/nope"], path=path)

    def test_replace_advanced_rejects_invalid_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self.make_config(temporary)
            for values, match in (
                ({"healthCheckTimeout": 5}, "healthCheckTimeout"),
                ({"globalTTL": True}, "globalTTL"),
                ({"globalTTL": -1}, "globalTTL"),
                ({"unloadTimeout": True}, "unloadTimeout"),
                ({"logLevel": "verbose"}, "logLevel"),
                ({"captureBuffer": "big"}, "captureBuffer"),
                ({"metricsMaxInMemory": -1}, "metricsMaxInMemory"),
            ):
                with self.assertRaisesRegex(ai.AiConfigError, match):
                    ai.replace_advanced(values, path=path)

    def test_main_cli_dispatch_and_error_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self.make_config(temporary)
            with mock.patch.object(ai, "load_config", return_value={"models": {}, "peers": {}, "selectors": {}}):
                with mock.patch.object(ai, "public_view", return_value={"ok": True}) as public_view:
                    self.assertEqual(ai.main(["show"]), 0)
                    self.assertTrue(public_view.called)
            with mock.patch.object(ai, "load_config", side_effect=ai.AiConfigError("boom")):
                self.assertEqual(ai.main(["show"]), 1)
            with mock.patch.object(ai, "set_provider", return_value={"ok": True}) as set_provider:
                self.assertEqual(ai.main(["set-provider", "openrouter", "https://x.test", "[]", "--credential"]), 0)
                self.assertTrue(set_provider.called)
            self.assertEqual(ai.main(["set-provider", "bad_id", "https://x.test", "[]"]), 1)
            with mock.patch.object(ai, "load_config", return_value={"models": {}, "peers": {}, "selectors": {}}):
                with mock.patch.object(ai, "atomic_write"), mock.patch.object(ai, "public_view", return_value={"ok": True}):
                    self.assertEqual(ai.main(["delete-provider", "openrouter"]), 0)
            self.assertEqual(ai.main(["set-role", "coding/default", "not-json"]), 1)
            self.assertEqual(ai.main(["set-advanced", "[]"]), 1)
            self.assertEqual(ai.main(["set-advanced", '{"logLevel": "info"}']), 1)
            self.assertEqual(ai.main(["set-local-model", "m", "/tmp/m.gguf", "--context", "8192"]), 1)
            self.assertEqual(ai.main(["delete-local-model", "m"]), 1)

    def test_local_model_root_missing_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            old = os.environ.get("NAS_AI_MODEL_ROOT")
            os.environ["NAS_AI_MODEL_ROOT"] = str(pathlib.Path(temporary) / "does-not-exist")
            try:
                with self.assertRaisesRegex(ai.AiConfigError, "does not exist"):
                    ai.local_model_root()
            finally:
                if old is None:
                    os.environ.pop("NAS_AI_MODEL_ROOT", None)
                else:
                    os.environ["NAS_AI_MODEL_ROOT"] = old

    def test_extra_args_validation_edge_cases(self):
        with self.assertRaisesRegex(ai.AiConfigError, "list of at most"):
            ai.validate_local_extra_args({"not": "a list"})
        with self.assertRaisesRegex(ai.AiConfigError, "list of at most"):
            ai.validate_local_extra_args(["ok"] * 65)
        with self.assertRaisesRegex(ai.AiConfigError, "short non-empty strings"):
            ai.validate_local_extra_args(["", ])
        with self.assertRaisesRegex(ai.AiConfigError, "short non-empty strings"):
            ai.validate_local_extra_args(["x" * 513])
        with self.assertRaisesRegex(ai.AiConfigError, "short non-empty strings"):
            ai.validate_local_extra_args(["\x01bad"])
        self.assertEqual(ai.validate_local_extra_args(None), [])
        self.assertEqual(ai.validate_local_extra_args([]), [])

    def test_validate_models_rejects_bad_shapes(self):
        with self.assertRaisesRegex(ai.AiConfigError, "between 1 and"):
            ai.validate_models("not-a-list")
        with self.assertRaisesRegex(ai.AiConfigError, "between 1 and"):
            ai.validate_models([])
        with self.assertRaisesRegex(ai.AiConfigError, "between 1 and"):
            ai.validate_models(["m"] * 257)
        self.assertEqual(ai.validate_models(["a", "a", "b"]), ["a", "b"])

    def test_validate_with_llama_swap_file_not_found(self):
        with tempfile.TemporaryDirectory() as temporary:
            candidate = pathlib.Path(temporary) / "candidate.yaml"
            candidate.write_text("models: {}\n", encoding="utf-8")
            exe = pathlib.Path(temporary) / "llama-swap"
            exe.write_text("", encoding="utf-8")
            with mock.patch.object(ai.shutil, "which", return_value=str(exe)):
                with mock.patch.object(ai.subprocess, "run", side_effect=FileNotFoundError):
                    self.assertIsNone(ai._validate_with_llama_swap(candidate))

    def test_atomic_write_chowns_and_rejects_oversized_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self.make_config(temporary)
            config = ai.load_config(path)
            with mock.patch.object(ai.os, "geteuid", return_value=0), mock.patch.object(ai.os, "chown") as chown:
                ai.atomic_write(config, path)
            self.assertTrue(chown.called)
            huge = {"models": {"m": {"cmd": "x" * (2 * 1024 * 1024)}}}
            with self.assertRaisesRegex(ai.AiConfigError, "unexpectedly large"):
                ai.atomic_write(huge, path)

    def test_public_view_with_invalid_provider_id_is_fail_closed(self):
        config = {
            "models": {},
            "peers": {"bad_provider": {"proxy": "https://x.test", "models": ["m"]}},
            "selectors": {},
        }
        view = ai.public_view(config)
        self.assertFalse(view["providers"][0]["credentialConfigured"])
        self.assertFalse(view["providers"][0]["credentialReferenceConfigured"])

    def test_delete_local_model_keeps_remaining_targets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary) / "models"
            root.mkdir()
            first = root / "first.gguf"
            first.write_bytes(b"gguf")
            second = root / "second.gguf"
            second.write_bytes(b"gguf")
            server = pathlib.Path(temporary) / "llama-server"
            server.write_text("", encoding="utf-8")
            path = self.make_config(temporary)
            old_root = os.environ.get("NAS_AI_MODEL_ROOT")
            old_server = os.environ.get("NAS_LLAMA_SERVER")
            os.environ["NAS_AI_MODEL_ROOT"] = str(root)
            os.environ["NAS_LLAMA_SERVER"] = str(server)
            try:
                ai.set_local_model("first", str(first), context=8192, ttl=60, tools=False, path=path)
                ai.set_local_model("second", str(second), context=8192, ttl=60, tools=False, path=path)
                ai.set_role("coding/default", ["first", "second"], path=path)
                view = ai.delete_local_model("first", path=path)
                self.assertEqual(view["codingRoles"]["coding/default"]["targets"], ["second"])
            finally:
                if old_root is None:
                    os.environ.pop("NAS_AI_MODEL_ROOT", None)
                else:
                    os.environ["NAS_AI_MODEL_ROOT"] = old_root
                if old_server is None:
                    os.environ.pop("NAS_LLAMA_SERVER", None)
                else:
                    os.environ["NAS_LLAMA_SERVER"] = old_server

    def test_replace_advanced_remaining_validation_branches(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self.make_config(temporary)
            for values, match in (
                ({"logLevel": "verbose"}, "logLevel"),
                ({"captureBuffer": 2048}, "captureBuffer"),
                ({"metricsMaxInMemory": -1}, "metricsMaxInMemory"),
            ):
                with self.assertRaisesRegex(ai.AiConfigError, match):
                    ai.replace_advanced(values, path=path)
            view = ai.replace_advanced(
                {"logLevel": "debug", "captureBuffer": 128, "metricsMaxInMemory": 5000},
                path=path,
            )
            self.assertEqual(view["advanced"]["logLevel"], "debug")
            self.assertEqual(view["advanced"]["captureBuffer"], 128)
            self.assertEqual(view["advanced"]["metricsMaxInMemory"], 5000)

    def test_main_set_role_dispatch(self):
        with mock.patch.object(ai, "load_config", return_value={"models": {}, "peers": {}, "selectors": {}}):
            with mock.patch.object(ai, "set_role", return_value={"ok": True}) as set_role:
                self.assertEqual(ai.main(["set-role", "coding/default", '["local-small"]', "--strategy", "pin"]), 0)
                self.assertTrue(set_role.called)

    def test_probe_provider_credential_tri_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            secret_root = pathlib.Path(tmp) / "secrets"
            env_file = secret_root / "ai" / "llama-swap.env"
            env_file.parent.mkdir(parents=True)
            env_file.write_text("LLAMA_SWAP_PEER_FOO_API_KEY=old-secret\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {"NAS_SECRET_ROOT": str(secret_root), "NAS_SKIP_LLAMA_SWAP_RESTART": "1"}):
                state, value = ai._probe_provider_credential("foo")
                self.assertEqual(state, ai.CREDENTIAL_PRESENT)
                self.assertEqual(value, "old-secret")
                state, value = ai._probe_provider_credential("bar")
                self.assertEqual(state, ai.CREDENTIAL_ABSENT)
                self.assertIsNone(value)
                with mock.patch.object(pathlib.Path, "read_text", side_effect=PermissionError("denied")):
                    state, _ = ai._probe_provider_credential("foo")
                    self.assertEqual(state, ai.CREDENTIAL_UNKNOWN)
                self.assertEqual(ai._provider_credential_staged("foo"), True)
                self.assertEqual(ai._provider_credential_staged("bar"), False)
                with mock.patch.object(pathlib.Path, "read_text", side_effect=PermissionError("denied")):
                    self.assertIsNone(ai._provider_credential_staged("foo"))

    def test_set_provider_unknown_aborts_before_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.make_config(tmp)
            orig = path.read_bytes()
            with mock.patch.dict(os.environ, {"NAS_SKIP_LLAMA_SWAP_RESTART": "1"}):
                with mock.patch.object(ai, "_probe_provider_credential", return_value=(ai.CREDENTIAL_UNKNOWN, None)):
                    with self.assertRaisesRegex(ai.AiConfigError, "Unable to determine prior credential"):
                        ai.set_provider("openrouter", "https://example.test", ["m"], credential=False, path=path)
                self.assertEqual(path.read_bytes(), orig)

    def test_set_provider_absent_proceeds(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.make_config(tmp)
            with mock.patch.dict(os.environ, {"NAS_SKIP_LLAMA_SWAP_RESTART": "1"}):
                with mock.patch.object(ai, "_probe_provider_credential", return_value=(ai.CREDENTIAL_ABSENT, None)):
                    view = ai.set_provider("openrouter", "https://example.test", ["m"], credential=False, path=path)
            self.assertTrue(any(p["id"] == "openrouter" for p in view["providers"]))

    def test_set_provider_present_restores_on_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.make_config(tmp)
            secret_root = pathlib.Path(tmp) / "secrets"
            env_file = secret_root / "ai" / "llama-swap.env"
            env_file.parent.mkdir(parents=True)
            env_file.write_text("LLAMA_SWAP_PEER_OPENROUTER_API_KEY=old-secret\n", encoding="utf-8")
            orig_bytes = path.read_bytes()
            with mock.patch.dict(os.environ, {"NAS_SECRET_ROOT": str(secret_root), "NAS_SKIP_LLAMA_SWAP_RESTART": "1"}):
                with mock.patch.object(ai, "_probe_provider_credential", return_value=(ai.CREDENTIAL_PRESENT, "old-secret")):
                    with mock.patch.object(ai, "atomic_write", side_effect=[None, ai.AiConfigError("restart failed")]) as aw:
                        def fake_atomic(*args, **kwargs):
                            if aw.call_count == 1:
                                return None
                            raise ai.AiConfigError("restart failed")
                        with mock.patch.object(ai, "_maybe_restart_and_healthcheck", side_effect=ai.AiConfigError("restart failed")):
                            with self.assertRaises(ai.AiConfigError):
                                ai.set_provider("openrouter", "https://example.test", ["m"], credential=True, path=path)
                    self.assertEqual(path.read_bytes(), orig_bytes)
                    self.assertIn("old-secret", env_file.read_text(encoding="utf-8"))
                # Now simulate failure after write via restart mock
                with mock.patch.object(ai, "_probe_provider_credential", return_value=(ai.CREDENTIAL_PRESENT, "old-secret")):
                    with mock.patch.object(ai, "_maybe_restart_and_healthcheck", side_effect=ai.AiConfigError("health failed")):
                        with self.assertRaises(ai.AiConfigError):
                            ai.set_provider("openrouter2", "https://example2.test", ["m2"], credential=False, path=path)
                    self.assertEqual(path.read_bytes(), orig_bytes)

    def test_set_provider_normal_success_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.make_config(tmp)
            with mock.patch.dict(os.environ, {"NAS_SKIP_LLAMA_SWAP_RESTART": "1"}):
                view = ai.set_provider("cloud", "https://cloud.example", ["coder"], credential=True, path=path)
                self.assertTrue(view["providers"][0]["credentialReferenceConfigured"])
                view2 = ai.set_provider("cloud", "https://cloud.example", ["coder2"], credential=False, path=path)
                self.assertEqual(view2["providers"][0]["credentialEnv"], "LLAMA_SWAP_PEER_CLOUD_API_KEY")

    def test_delete_provider_present_restores_on_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.make_config(tmp)
            secret_root = pathlib.Path(tmp) / "secrets"
            env_file = secret_root / "ai" / "llama-swap.env"
            env_file.parent.mkdir(parents=True)
            env_file.write_text("LLAMA_SWAP_PEER_CLOUD_API_KEY=keep-me\n", encoding="utf-8")
            ai.set_provider("cloud", "https://cloud.example", ["coder"], credential=False, path=path)
            orig_bytes = path.read_bytes()
            with mock.patch.dict(os.environ, {"NAS_SECRET_ROOT": str(secret_root), "NAS_SKIP_LLAMA_SWAP_RESTART": "1"}):
                with mock.patch.object(ai, "_probe_provider_credential", return_value=(ai.CREDENTIAL_PRESENT, "keep-me")):
                    with mock.patch.object(ai, "_maybe_restart_and_healthcheck", side_effect=ai.AiConfigError("restart fail")):
                        with self.assertRaises(ai.AiConfigError):
                            ai.delete_provider("cloud", path=path)
                    self.assertEqual(path.read_bytes(), orig_bytes)
                    self.assertIn("keep-me", env_file.read_text(encoding="utf-8"))

    def test_replace_advanced_restores_on_restart_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.make_config(tmp)
            orig = path.read_bytes()
            with mock.patch.dict(os.environ, {"NAS_SKIP_LLAMA_SWAP_RESTART": "1"}):
                with mock.patch.object(ai, "_maybe_restart_and_healthcheck", side_effect=ai.AiConfigError("boom")):
                    with self.assertRaises(ai.AiConfigError):
                        ai.replace_advanced({"logLevel": "debug"}, path=path)
                    self.assertEqual(path.read_bytes(), orig)


if __name__ == "__main__":
    unittest.main()
