from __future__ import annotations

import os
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
    configured = os.environ.get("CADDY_BIN")
    if configured and pathlib.Path(configured).is_file():
        return configured
    found = shutil.which("caddy")
    if found:
        return found
    nix = shutil.which("nix")
    if nix:
        try:
            result = subprocess.run(
                [nix, "build", "--no-link", "--print-out-paths", "nixpkgs#caddy"],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if result.returncode == 0 and result.stdout.strip():
            candidate = pathlib.Path(result.stdout.splitlines()[-1].strip()) / "bin" / "caddy"
            if candidate.is_file():
                return str(candidate)
    return None


class CaddyValidateTests(unittest.TestCase):
    def test_generated_caddyfile_is_accepted_by_real_caddy(self):
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
                    "exposure": {"type": "path", "value": "/managed-api"},
                    "auth": {"mode": "forward-auth"},
                },
                "other:svc": {
                    "transport": "http",
                    "targetPort": 9000,
                    "exposure": {"type": "port", "value": 8443},
                    "auth": {"mode": "public"},
                },
            },
        }
        fragment = caddy.generate_caddy_fragment(effective)
        self.assertEqual(len(fragment["routes"]), 3)
        rendered = caddy.generate_caddyfile(effective)
        self.assertIn("(nas_managed_paths)", rendered)
        self.assertIn("https://photos.local", rendered)
        self.assertIn("https://nas.local:8443", rendered)

        caddy_bin = _caddy_binary()
        if caddy_bin is None:
            raise unittest.SkipTest("caddy binary not available")
        with tempfile.TemporaryDirectory() as tmp:
            caddyfile = pathlib.Path(tmp) / "Caddyfile"
            caddyfile.write_text(rendered, encoding="utf-8")
            fmt = subprocess.run(
                [caddy_bin, "fmt", "--overwrite", str(caddyfile)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(fmt.returncode, 0, msg=fmt.stderr[:1000])
            adapt = subprocess.run(
                [caddy_bin, "adapt", "--adapter", "caddyfile", "--config", str(caddyfile)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(adapt.returncode, 0, msg=adapt.stderr[:2000])

    def test_caddy_adapt_on_minimal_valid_config(self):
        caddy_bin = _caddy_binary()
        if caddy_bin is None:
            raise unittest.SkipTest("caddy binary not present")
        with tempfile.TemporaryDirectory() as tmp:
            caddyfile = pathlib.Path(tmp) / "Caddyfile"
            caddyfile.write_text("{\n admin off\n}\n:2019 {\n respond \"ok\" 200\n}\n", encoding="utf-8")
            result = subprocess.run(
                [caddy_bin, "adapt", "--adapter", "caddyfile", "--config", str(caddyfile)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, msg=result.stderr[:1000])


if __name__ == "__main__":
    unittest.main()
