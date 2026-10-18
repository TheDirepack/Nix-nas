from __future__ import annotations

import pathlib
import shutil
import subprocess
import tempfile
import types
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
PATCH = ROOT / "cockpit/patches/cockpit-frame-ancestors.patch"


class CockpitCspPatchTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.tree = pathlib.Path(temporary.name)
        source = self.tree / "src/cockpit/packages.py"
        source.parent.mkdir(parents=True)
        shutil.copyfile(ROOT / "tests/fixtures/cockpit-362/packages.py.txt", source)
        if PATCH.exists():
            subprocess.run(["git", "apply", str(PATCH)], cwd=self.tree, check=True, capture_output=True)
        namespace = {}
        exec(compile(source.read_text(), str(source), "exec"), namespace)
        self.package = namespace["Package"]()
        self.package.path = self.tree
        self.package.manifest = types.SimpleNamespace(csp="")

    def policy(self):
        return {
            key: value
            for part in self.package.get_content_security_policy().split(";")
            if (directive := part.strip())
            for key, _, value in [directive.partition(" ")]
        }

    def test_default_policy_retains_native_directives_and_same_origin_frames(self):
        self.assertEqual(
            self.policy(),
            {
                "default-src": "'self'",
                "connect-src": "'self'",
                "form-action": "'self'",
                "base-uri": "'self'",
                "object-src": "'none'",
                "font-src": "'self' data:",
                "img-src": "'self' data:",
                "frame-ancestors": "'self'",
                "block-all-mixed-content": "",
            },
        )

    def test_html_file_receives_native_policy_without_changing_content(self):
        payload = b"<!doctype html><title>Native package page</title>"
        (self.tree / "index.html").write_bytes(payload)
        document = self.package.load_file("index.html")
        with document.data:
            self.assertEqual(document.data.read(), payload)
        self.assertEqual(document.content_type, "text/html")
        self.assertIn("frame-ancestors 'self';", document.content_security_policy)

    def test_non_html_assets_do_not_receive_an_html_policy(self):
        (self.tree / "index.js").write_text("export const healthy = true;\n")
        document = self.package.load_file("index.js")
        with document.data:
            self.assertIsNone(document.content_security_policy)
            self.assertEqual(document.data.read(), b"export const healthy = true;\n")

    def test_stricter_package_policy_and_nonce_are_preserved(self):
        self.package.manifest.csp = "frame-ancestors 'none'; script-src 'self' 'nonce-private'; img-src 'none'"
        policy = self.policy()
        self.assertEqual(policy["frame-ancestors"], "'none'")
        self.assertEqual(policy["script-src"], "'self' 'nonce-private'")
        self.assertEqual(policy["img-src"], "'none'")
        self.assertEqual(policy["connect-src"], "'self'")

    def test_missing_files_remain_errors(self):
        with self.assertRaises(FileNotFoundError):
            self.package.load_file("missing.html")

    def test_running_bridge_package_applies_the_source_patch(self):
        source = (ROOT / "modules/nas/config/application-services.nix").read_text()
        package = source.split("cockpitPatched = pkgs.cockpit.overrideAttrs", 1)[1].split("  cockpitWebService =", 1)[0]
        self.assertIn("../../../cockpit/patches/cockpit-frame-ancestors.patch", package)
        self.assertIn("old.patches or", package)
        self.assertIn("${cockpitPatched}/bin/cockpit-bridge", source)
