from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "lib" / "render-alertmanager-ntfy-config.py"
SPEC = importlib.util.spec_from_file_location("render_alertmanager_ntfy_config", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
renderer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(renderer)


class AlertmanagerNtfyConfigTests(unittest.TestCase):
    def test_renderer_reads_private_files_and_writes_private_runtime_config(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            topic = root / "topic"
            password = root / "password"
            output = root / "runtime" / "config.yml"
            topic.write_text("nas_private_topic", encoding="utf-8")
            password.write_text("abcdefghijklmnopqrstuvwx", encoding="utf-8")
            topic.chmod(0o400)
            password.chmod(0o400)

            old = tuple(getattr(renderer, name) for name in ("TOPIC_PATH", "PASSWORD_PATH", "OUTPUT_PATH"))
            try:
                setattr(renderer, "TOPIC_PATH", topic)
                setattr(renderer, "PASSWORD_PATH", password)
                setattr(renderer, "OUTPUT_PATH", output)
                self.assertEqual(renderer.main(), 0)
            finally:
                for name, value in zip(("TOPIC_PATH", "PASSWORD_PATH", "OUTPUT_PATH"), old, strict=True):
                    setattr(renderer, name, value)

            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["ntfy"]["notification"]["topic"], "nas_private_topic")
            self.assertEqual(payload["ntfy"]["auth"]["basic"]["username"], "admin")
            self.assertEqual(payload["ntfy"]["auth"]["basic"]["password"], "abcdefghijklmnopqrstuvwx")
            self.assertEqual(os.stat(output).st_mode & 0o777, 0o400)

    def test_renderer_rejects_non_private_input(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            secret = pathlib.Path(raw) / "secret"
            secret.write_text("nas_private_topic", encoding="utf-8")
            secret.chmod(0o440)
            with self.assertRaises(RuntimeError):
                renderer.read_private(secret, renderer.TOPIC_RE, "topic")

    def test_renderer_rejects_symlink_input(self) -> None:
        if not hasattr(os, "O_NOFOLLOW"):
            self.skipTest("O_NOFOLLOW is unavailable on this platform")
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            target = root / "target"
            link = root / "link"
            target.write_text("nas_private_topic", encoding="utf-8")
            target.chmod(0o400)
            link.symlink_to(target)
            with self.assertRaises(RuntimeError):
                renderer.read_private(link, renderer.TOPIC_RE, "topic")


if __name__ == "__main__":
    unittest.main()
