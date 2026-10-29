from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from repo_test_utils import text


class ExternalProbeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.bash = self.host_tool("bash")
        (self.bin / "python3").symlink_to(sys.executable)
        (self.bin / "timeout").symlink_to(self.host_tool("timeout"))
        self.marker = self.root / "probe-launched"
        self.args = self.root / "probe-args"
        self.probe = self.root / "inert probe"
        self.probe.write_text(
            f'#!{self.bash}\nset -euo pipefail\nprintf launched > "$MARKER"\n'
            'printf \'%s\\0\' "$@" > "$PROBE_ARGS"\nexit "${PROBE_EXIT:-0}"\n',
            encoding="utf-8",
        )
        self.probe.chmod(0o755)
        source = text("scripts/update-nas.sh")
        self.function = (
            "external_management_probe() {"
            + source.split("external_management_probe() {", 1)[1].split("\nhealth_check() {", 1)[0]
        )

    @staticmethod
    def host_tool(name: str) -> str:
        tool = shutil.which(name)
        assert tool is not None, f"test tool unavailable: {name}"
        return tool

    def run_probe(
        self,
        raw: str,
        *,
        decoder: str | None = None,
        conditional: bool = False,
        local_only: bool = False,
        probe_exit: int = 0,
    ):
        if decoder is not None:
            python = self.bin / "python3"
            python.unlink()
            python.write_text(f"#!{self.bash}\nset -euo pipefail\n" + decoder, encoding="utf-8")
            python.chmod(0o755)
        invocation = "external_management_probe"
        if conditional:
            invocation = "if external_management_probe; then exit 0; else exit $?; fi"
        command = (
            "set -Eeuo pipefail\nallow_local_health_only="
            + ("true" if local_only else "false")
            + "\n"
            + self.function
            + "\n"
            + invocation
            + "\n"
        )
        # The only executable target is a temporary argv-recording fixture, never a deployment or network probe.
        return subprocess.run(
            [self.bash, "--noprofile", "--norc", "-c", command],
            cwd=self.root,
            env={
                "PATH": str(self.bin),
                "LC_ALL": "C",
                "MARKER": str(self.marker),
                "PROBE_ARGS": str(self.args),
                "PROBE": str(self.probe),
                "PROBE_EXIT": str(probe_exit),
                "NAS_UPDATE_EXTERNAL_PROBE_COMMAND_JSON": raw,
            },
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    def assert_blocked(self, result: subprocess.CompletedProcess[str], code: int):
        recorded = self.args.read_bytes() if self.args.exists() else None
        self.assertFalse(
            self.marker.exists(),
            f"invalid/failed decoder launched the probe: exit={result.returncode}, argv={recorded!r}\n{result.stderr}",
        )
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        self.assertFalse(self.args.exists())

    def test_late_nul_rejects_the_entire_probe(self):
        result = self.run_probe(json.dumps([str(self.probe), "accepted-prefix", "bad\0tail"]))
        self.assert_blocked(result, 1)
        self.assertIn("external probe argument contains NUL", result.stderr)

    def test_late_unencodable_string_rejects_the_entire_probe(self):
        result = self.run_probe(json.dumps([str(self.probe), "accepted-prefix", "\ud800"]))
        self.assert_blocked(result, 1)
        self.assertIn("UnicodeEncodeError", result.stderr)

    def test_decoder_failure_after_output_never_launches_prefix(self):
        result = self.run_probe(
            "[]", decoder="printf '%s\\0' \"$PROBE\" accepted-prefix\nprintf 'decoder failed\\n' >&2\nexit 47\n"
        )
        self.assert_blocked(result, 47)
        self.assertIn("decoder failed", result.stderr)

    def test_decoder_failure_without_output_preserves_native_exit(self):
        result = self.run_probe("[]", decoder="exit 47\n")
        self.assert_blocked(result, 47)

    def test_decoder_failure_remains_fatal_in_conditional_context(self):
        result = self.run_probe("[]", decoder="printf '%s\\0' \"$PROBE\" accepted-prefix\nexit 47\n", conditional=True)
        self.assert_blocked(result, 47)

    def test_local_only_override_does_not_allow_invalid_nonempty_probe(self):
        result = self.run_probe(json.dumps([str(self.probe), "accepted-prefix", "bad\0tail"]), local_only=True)
        self.assert_blocked(result, 1)

    def test_valid_probe_preserves_argument_boundaries(self):
        args = ["space ; $(not-code)", 'quote"\\value', "line\nbreak", "unicode-✓"]
        result = self.run_probe(json.dumps([str(self.probe), *args]))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.marker.exists())
        self.assertEqual(self.args.read_bytes(), b"".join(arg.encode() + b"\0" for arg in args))

    def test_valid_probe_preserves_its_own_failure(self):
        result = self.run_probe(json.dumps([str(self.probe), "probe-failure"]), probe_exit=23)
        self.assertEqual(result.returncode, 23, result.stdout + result.stderr)
        self.assertEqual(self.args.read_bytes(), b"probe-failure\0")

    def test_invalid_json_or_shape_never_launches(self):
        for raw in ("not-json", "null", "{}", "[]", '"text"', '[""]', "[17]", '["\\u0000"]'):
            with self.subTest(raw=raw):
                self.assert_blocked(self.run_probe(raw), 1)

    def test_independent_probe_remains_required(self):
        result = self.run_probe("")
        self.assert_blocked(result, 1)
        self.assertIn("Persistent deployment requires NAS_UPDATE_EXTERNAL_PROBE_COMMAND_JSON", result.stderr)

    def test_explicit_local_only_override_retains_warning(self):
        result = self.run_probe("", local_only=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("WARNING: persisting after local-only management checks by explicit override", result.stderr)
        self.assertFalse(self.marker.exists())


if __name__ == "__main__":
    unittest.main()
