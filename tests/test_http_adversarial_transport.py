from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class HttpAdversarialTransportTests(unittest.TestCase):
    def scenario(self, code: str, *, transport_exit: int = 0) -> tuple[subprocess.CompletedProcess[str], dict | None]:
        source = (ROOT / "scripts/qemu-final-browser.sh").read_text(encoding="utf-8")
        function = source[source.index("run_http_adversarial_contracts() {") : source.index('\ncase "$WORKLOAD" in')]
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            evidence = root / "result.json"
            script = "\n".join(
                [
                    "set -Eeuo pipefail",
                    "HTTPS_PORT=8443",
                    'die() { printf "%s\\n" "$*" >&2; exit 1; }',
                    "log() { :; }",
                    """curl() {
  local output= blocked=0
  while (($#)); do
    case "$1" in
      --output) output=$2; shift ;;
      -H) blocked=1 ;;
    esac
    shift
  done
  printf 'fixture-response-body\\n' > "$output"
  if ((blocked)); then printf 403; return 0; fi
  printf '%s' "$FIXTURE_HTTP_CODE"
  if ((FIXTURE_TRANSPORT_EXIT)); then printf 'fixture-curl-error\\n' >&2; fi
  return "$FIXTURE_TRANSPORT_EXIT"
}""",
                    function,
                    'run_http_adversarial_contracts "$FIXTURE_EVIDENCE"',
                ]
            )
            result = subprocess.run(
                ["bash", "-c", script],
                env={
                    **os.environ,
                    "TMPDIR": str(root),
                    "FIXTURE_HTTP_CODE": code,
                    "FIXTURE_TRANSPORT_EXIT": str(transport_exit),
                    "FIXTURE_EVIDENCE": str(evidence),
                },
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            payload = json.loads(evidence.read_text()) if evidence.exists() else None
            return result, payload

    def test_transport_failure_never_writes_success_evidence(self) -> None:
        for code, status in (("000", 7), ("200", 28)):
            with self.subTest(code=code, status=status):
                result, payload = self.scenario(code, transport_exit=status)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(payload)
                self.assertIn("fixture-curl-error", result.stderr)
                self.assertIn("fixture-response-body", result.stderr)
                self.assertIn(f"exit {status}", result.stderr)

    def test_invalid_status_never_writes_success_evidence(self) -> None:
        for code in ("000", "099", "600", "", "garbage"):
            with self.subTest(code=code):
                result, payload = self.scenario(code)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(payload)

    def test_server_errors_remain_fatal_with_the_response_body(self) -> None:
        for code in ("500", "503", "599"):
            with self.subTest(code=code):
                result, payload = self.scenario(code)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(payload)
                self.assertIn(f"server error HTTP {code}", result.stderr)
                self.assertIn("fixture-response-body", result.stderr)

    def test_real_non_server_responses_keep_complete_request_counts(self) -> None:
        for code in ("200", "302", "400", "404"):
            with self.subTest(code=code):
                result, payload = self.scenario(code)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(
                    payload,
                    {"ok": True, "engine": "curl", "requests": 11, "spoofedIdentityPathsBlocked": 7},
                )
