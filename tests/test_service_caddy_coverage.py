from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))

import nas_service_caddy as caddy  # noqa: E402


def endpoint(*, transport: str = "http", exposure: dict | None = None, available: bool | None = None) -> dict:
    result = {
        "transport": transport,
        "targetPort": 8443,
        "exposure": exposure or {"type": "hostname", "value": "app.example"},
        "auth": {"mode": "public"},
    }
    if available is not None:
        result["available"] = available
    return result


class CaddyCoverageTests(unittest.TestCase):
    def test_explicitly_unavailable_endpoint_is_not_routed(self) -> None:
        effective = {
            "endpoints": {
                "enabled:web": endpoint(
                    exposure={"type": "hostname", "value": "enabled.example"},
                    available=True,
                ),
                "disabled:web": endpoint(
                    exposure={"type": "hostname", "value": "disabled.example"},
                    available=False,
                ),
            }
        }
        fragment = caddy.generate_caddy_fragment(effective)
        self.assertEqual([route["id"] for route in fragment["routes"]], ["nas-managed-enabled-web"])
        rendered = caddy.generate_caddyfile(effective)
        self.assertIn("https://enabled.example", rendered)
        self.assertNotIn("disabled.example", rendered)

    def test_https_and_exact_path_rendering_cover_proxy_variants(self) -> None:
        effective = {
            "endpoints": {
                "secure": endpoint(transport="https"),
                "exact": endpoint(exposure={"type": "path", "value": "/exact", "prefix": False}),
                "coerced": endpoint(exposure={"type": "path", "value": "/coerced", "prefix": "yes"}),
            }
        }
        rendered = caddy.generate_caddyfile(effective)
        self.assertIn("transport http", rendered)
        self.assertIn("tls_insecure_skip_verify", rendered)
        self.assertIn("@nas_nas-managed-exact path /exact", rendered)
        self.assertNotIn("strip_prefix /exact", rendered)
        self.assertIn("strip_prefix /coerced", rendered)

    def test_real_caddy_validation_success_path_is_exercised(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = pathlib.Path(temporary) / "managed.caddy"
            completed = SimpleNamespace(returncode=0, stdout="", stderr="")
            with (
                mock.patch.object(
                    caddy.shutil, "which", side_effect=lambda name: "/bin/caddy" if name == "caddy" else None
                ),
                mock.patch.object(caddy.subprocess, "run", return_value=completed) as run,
                mock.patch.dict(caddy.os.environ, {"NAS_SKIP_CADDY_RELOAD": "1"}, clear=False),
            ):
                caddy.write_caddy_fragment(target, {"endpoints": {}})
            self.assertEqual(run.call_count, 2)
            self.assertEqual(run.call_args_list[0].args[0][1:3], ["fmt", "--overwrite"])
            self.assertEqual(run.call_args_list[1].args[0][1], "adapt")

    def test_caddy_format_failure_preserves_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = pathlib.Path(temporary) / "managed.caddy"
            target.write_text("old-content\n", encoding="utf-8")
            failed = SimpleNamespace(returncode=1, stdout="", stderr="bad format")
            with (
                mock.patch.object(
                    caddy.shutil, "which", side_effect=lambda name: "/bin/caddy" if name == "caddy" else None
                ),
                mock.patch.object(caddy.subprocess, "run", return_value=failed),
                mock.patch.dict(caddy.os.environ, {"NAS_SKIP_CADDY_RELOAD": "1"}, clear=False),
            ):
                with self.assertRaisesRegex(caddy.CaddyError, "Caddy fmt failed"):
                    caddy.write_caddy_fragment(target, {"endpoints": {}})
            self.assertEqual(target.read_text(encoding="utf-8"), "old-content\n")

    def test_reload_failure_rolls_back_previous_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = pathlib.Path(temporary) / "managed.caddy"
            target.write_text("previous\n", encoding="utf-8")
            failed = SimpleNamespace(returncode=1, stdout="", stderr="reload failed")
            success = SimpleNamespace(returncode=0, stdout="", stderr="")
            with (
                mock.patch.object(
                    caddy.shutil, "which", side_effect=lambda name: "/bin/systemctl" if name == "systemctl" else None
                ),
                mock.patch.object(caddy.subprocess, "run", side_effect=[failed, success]) as run,
                mock.patch.dict(caddy.os.environ, {"NAS_SKIP_CADDY_VALIDATE": "1"}, clear=False),
            ):
                with self.assertRaisesRegex(caddy.CaddyError, "Caddy reload failed"):
                    caddy.write_caddy_fragment(target, {"endpoints": {}})
            self.assertEqual(run.call_count, 2)
            self.assertEqual(target.read_text(encoding="utf-8"), "previous\n")


if __name__ == "__main__":
    unittest.main()
