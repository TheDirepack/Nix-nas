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


if __name__ == "__main__":
    unittest.main()
