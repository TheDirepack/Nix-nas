from __future__ import annotations

import base64
from email import policy
from email.parser import BytesHeaderParser
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/cockpit-362/native"
PATCH = ROOT / "cockpit/patches/cockpit-error-csp.patch"


class CockpitErrorCspTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.tree = Path(cls.temporary.name)
        manifest = json.loads((FIXTURE / "upstream.json").read_text())
        for name, expected in manifest["files"].items():
            raw = (FIXTURE / (name + ".txt")).read_bytes()
            if hashlib.sha256(raw).hexdigest() != expected["sha256"]:
                raise AssertionError(f"Upstream fixture changed: {name}")
            if hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() != expected["gitBlob"]:
                raise AssertionError(f"Upstream Git blob mismatch: {name}")
            destination = cls.tree / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(raw)
        if PATCH.exists():
            subprocess.run(["git", "apply", "--check", str(PATCH)], cwd=cls.tree, check=True, capture_output=True)
            subprocess.run(["git", "apply", str(PATCH)], cwd=cls.tree, check=True, capture_output=True)
        cls.html = (cls.tree / "src/common/fail.html").read_text()
        embedded = subprocess.run(
            [sys.executable, str(cls.tree / "tools/escape-to-c"), "cockpit_webresponse_fail_html_text"],
            input=cls.html,
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        (cls.tree / "fail-html.c").write_text(embedded.stdout)
        (cls.tree / "config.h").write_text("")
        flags = subprocess.run(
            ["pkg-config", "--cflags", "--libs", "gio-2.0", "json-glib-1.0"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        cls.executable = cls.tree / "error-response"
        result = subprocess.run(
            [
                "cc",
                "-D_GNU_SOURCE",
                "-std=gnu11",
                "-ffunction-sections",
                "-fdata-sections",
                "-Wl,--gc-sections",
                "-I" + str(cls.tree),
                "-I" + str(cls.tree / "src"),
                "-I" + str(cls.tree / "src/ws"),
                str(ROOT / "tests/fixtures/cockpit-362/error-response-probe.c"),
                *(
                    str(cls.tree / "src/ws" / name)
                    for name in ("cockpitwebresponse.c", "cockpitwebfilter.c", "cockpitflow.c", "cockpithash.c")
                ),
                str(cls.tree / "fail-html.c"),
                "-o",
                str(cls.executable),
                *shlex.split(flags.stdout),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)

    def response(self, *, method="GET", code=404, headers="none", reason="Not Found", body="html"):
        result = subprocess.run(
            [str(self.executable), method, str(code), headers, reason, body],
            capture_output=True,
            check=True,
            timeout=10,
        )
        self.assertEqual(result.stderr, b"")
        head, payload = result.stdout.split(b"\r\n\r\n", 1)
        status, header_lines = head.split(b"\r\n", 1)
        parsed = BytesHeaderParser(policy=policy.HTTP).parsebytes(header_lines + b"\r\n\r\n")
        if method == "HEAD":
            self.assertEqual(payload, b"")
            return status.decode(), parsed, b""
        decoded = bytearray()
        while payload:
            size, payload = payload.split(b"\r\n", 1)
            length = int(size, 16)
            if length == 0:
                self.assertEqual(payload, b"\r\n")
                break
            decoded.extend(payload[:length])
            self.assertEqual(payload[length : length + 2], b"\r\n")
            payload = payload[length + 2 :]
        return status.decode(), parsed, bytes(decoded)

    def expected_policy(self):
        result = {
            "default-src": "'none'",
            "base-uri": "'none'",
            "form-action": "'none'",
            "frame-ancestors": "'self'",
            "font-src": "'self'",
            "object-src": "'none'",
        }
        for tag, directive in (("script", "script-src"), ("style", "style-src")):
            blocks = re.findall(rf"<{tag}>(.*?)</{tag}>", self.html, re.DOTALL)
            self.assertEqual(len(blocks), 1)
            digest = base64.b64encode(hashlib.sha256(blocks[0].encode()).digest()).decode()
            result[directive] = f"'sha256-{digest}'"
        return result

    def assert_default_policy(self, headers):
        self.assertEqual(len(headers.get_all("Content-Security-Policy", [])), 1)
        value = headers["Content-Security-Policy"]
        directives = dict(part.strip().split(" ", 1) for part in value.split(";") if part.strip())
        self.assertEqual(directives, self.expected_policy())
        self.assertEqual(headers["X-Frame-Options"].lower(), "sameorigin")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")

    def test_generated_errors_without_headers_have_hash_bound_policy_and_unchanged_body(self):
        for code in (400, 401, 403, 404, 405, 500, 502):
            with self.subTest(code=code):
                status, headers, body = self.response(code=code)
                self.assertEqual(status, f"HTTP/1.1 {code} Not Found")
                self.assert_default_policy(headers)
                self.assertEqual(body.decode(), self.html.replace("@@message@@", "Not Found"))

    def test_generated_error_adds_only_missing_policy_to_existing_headers(self):
        _, headers, _ = self.response(headers="other")
        self.assert_default_policy(headers)
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_head_uses_the_same_error_policy_without_a_body(self):
        _, headers, body = self.response(method="HEAD")
        self.assert_default_policy(headers)
        self.assertEqual(body, b"")

    def test_explicit_stricter_response_policies_are_not_replaced(self):
        for name in ("strict", "lower-strict"):
            with self.subTest(name=name):
                _, headers, _ = self.response(headers=name)
                self.assertEqual(headers["Content-Security-Policy"], "default-src 'none'; frame-ancestors 'none'")
                self.assertEqual(len(headers.get_all("Content-Security-Policy", [])), 1)

    def test_custom_json_error_body_and_policy_ownership_are_unchanged(self):
        for name in ("none", "strict"):
            with self.subTest(name=name):
                _, headers, body = self.response(headers=name, body="json")
                self.assertEqual(body, b'{"problem":"not-found"}')
                self.assertEqual(headers["Content-Type"], "application/json")
                self.assertEqual(headers["Content-Security-Policy"] is not None, name == "strict")

    def test_hostile_reason_cannot_change_authorized_script_or_style(self):
        reason = "</script><script>globalThis.pwned=1</script>"
        _, headers, body = self.response(reason=reason)
        self.assert_default_policy(headers)
        self.assertNotIn(reason.encode(), body)
        for tag in ("script", "style"):
            pattern = rf"<{tag}>(.*?)</{tag}>"
            self.assertEqual(re.findall(pattern, body.decode(), re.DOTALL), re.findall(pattern, self.html, re.DOTALL))

    def test_running_native_package_and_test_shell_use_the_existing_paths(self):
        source = (ROOT / "modules/nas/config/application-services.nix").read_text()
        package = source.split("cockpitPatched = pkgs.cockpit.overrideAttrs", 1)[1].split("  cockpitWebService =", 1)[0]
        self.assertIn("../../../cockpit/patches/cockpit-error-csp.patch", package)
        self.assertIn("../../../cockpit/patches/cockpit-frame-ancestors.patch", package)
        shell = (
            (ROOT / "flake.nix")
            .read_text()
            .split("devShells.x86_64-linux.test =", 1)[1]
            .split("devShells.x86_64-linux.qemu-test =", 1)[0]
        )
        for dependency in ("pkgs.pkg-config", "pkgs.glib", "pkgs.json-glib"):
            self.assertIn(dependency, shell)


if __name__ == "__main__":
    unittest.main()
