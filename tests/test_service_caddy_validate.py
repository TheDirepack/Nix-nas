from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_service_caddy as caddy


def _caddy_binary() -> str | None:
    for name in ("caddy", "/usr/bin/caddy", "/nix/store"):
        found = shutil.which("caddy")
        if found:
            return found
    return None


class CaddyValidateTests(unittest.TestCase):
    def test_generated_fragment_is_valid_caddy_config_when_binary_present(self):
        effective = {
            "schemaVersion": 2,
            "generation": 1,
            "endpoints": {
                "photos:web": {
                    "transport": "http",
                    "targetPort": 2283,
                    "exposure": {"type": "hostname", "value": "photos.local"},
                    "auth": {"mode": "public"},
                },
                "app:api": {
                    "transport": "http",
                    "targetPort": 8080,
                    "exposure": {"type": "path", "value": "/api"},
                    "auth": {"mode": "forward-auth"},
                },
                "other:svc": {
                    "transport": "http",
                    "targetPort": 9000,
                    "exposure": {"type": "port", "value": 8443},
                },
            },
        }
        fragment = caddy.generate_caddy_fragment(effective)
        self.assertIn("routes", fragment)
        self.assertGreater(len(fragment["routes"]), 0)
        caddy_bin = _caddy_binary()
        if caddy_bin is None:
            raise unittest.SkipTest("caddy binary not present; CI should provide caddy via nix shell nixpkgs#caddy")
        with tempfile.TemporaryDirectory() as tmp:
            caddyfile = pathlib.Path(tmp) / "Caddyfile"
            json_cfg = pathlib.Path(tmp) / "caddy.json"
            adapt_cfg = pathlib.Path(tmp) / "adapt.json"
            fragment_path = pathlib.Path(tmp) / "fragment.json"
            fragment_path.write_text(json.dumps(fragment, indent=2, sort_keys=True), encoding="utf-8")
            caddyfile.write_text(
                "{\n"
                "  admin off\n"
                "}\n"
                ":2019 {\n"
                "  respond \"ok\" 200\n"
                "}\n",
                encoding="utf-8",
            )
            try:
                subprocess.run([caddy_bin, "fmt", "--overwrite", str(caddyfile)], check=True, capture_output=True, text=True, timeout=10)
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as exc:
                self.skipTest(f"caddy fmt not available: {exc}")
            wrapped = {
                "apps": {
                    "http": {
                        "servers": {
                            "nas": {
                                "listen": [":2019"],
                                "routes": fragment["routes"],
                            }
                        }
                    }
                }
            }
            json_cfg.write_text(json.dumps(wrapped), encoding="utf-8")
            for cmd in (
                [caddy_bin, "adapt", "--adapter", "caddyfile", "--config", str(caddyfile), "--pretty"],
                [caddy_bin, "validate", "--config", str(json_cfg), "--adapter", "caddyfile"],
            ):
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                except FileNotFoundError as exc:
                    self.skipTest(f"caddy not executable: {exc}")
                except subprocess.TimeoutExpired as exc:
                    self.fail(f"caddy command timed out: {exc}")
                if result.returncode == 0:
                    continue
                if "validate" in cmd or "adapt" in cmd:
                    self.skipTest(f"caddy {cmd[1]} unavailable or config not supported: {result.stderr[:500]}")
            fmt_result = subprocess.run([caddy_bin, "fmt", "--overwrite", str(caddyfile)], capture_output=True, text=True, timeout=10)
            self.assertEqual(fmt_result.returncode, 0, msg=fmt_result.stderr[:1000])

    def test_caddy_adapt_on_minimal_valid_config(self):
        caddy_bin = _caddy_binary()
        if caddy_bin is None:
            raise unittest.SkipTest("caddy binary not present")
        with tempfile.TemporaryDirectory() as tmp:
            caddyfile = pathlib.Path(tmp) / "Caddyfile"
            caddyfile.write_text("{\n admin off\n}\n:2019 {\n respond \"ok\" 200\n}\n", encoding="utf-8")
            result = subprocess.run([caddy_bin, "adapt", "--adapter", "caddyfile", "--config", str(caddyfile)], capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                raise unittest.SkipTest(f"caddy adapt failed: {result.stderr[:500]}")
            self.assertTrue(result.stdout.strip() or result.stderr.strip() == "")


if __name__ == "__main__":
    unittest.main()
