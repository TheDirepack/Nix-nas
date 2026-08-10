from __future__ import annotations

import io
import json
import os
import pathlib
import shlex
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
TESTS = ROOT / "tests"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

try:
    from hypothesis import HealthCheck, event, given, settings, strategies as st
except ImportError:
    HAS_HYPOTHESIS = False
else:
    HAS_HYPOTHESIS = True
    import nas_logging
    from fuzz_harness import identifier_candidates, secret_key_names

LIBRARY = ROOT / "scripts/lib/nas-secret-transaction.sh"


if HAS_HYPOTHESIS:

    class SecretSecurityFuzzTests(unittest.TestCase):  # pyright: ignore[reportRedeclaration]
        @settings(max_examples=500, deadline=None)
        @given(secret_key_names())
        def test_secret_key_naming_variants_never_leak_values(self, key: str) -> None:
            sentinel = "SENTINEL-SECRET-DO-NOT-LOG"
            event("separator:dash" if "-" in key else "separator:other")
            event("case:mixed" if key != key.lower() else "case:lower")
            sanitized = nas_logging.sanitize({key: sentinel})
            self.assertEqual(sanitized[key], "[redacted]")
            self.assertNotIn(sentinel, json.dumps(sanitized))

        @settings(max_examples=400, deadline=None)
        @given(st.text(max_size=1024))
        def test_nested_hostile_secret_values_never_escape_structured_log_redaction(self, suffix: str) -> None:
            sentinel = "SENTINEL-SECRET-DO-NOT-LOG:"
            value = sentinel + suffix
            payload = {
                "request": {
                    "clientSecret": value,
                    "provider": {"apiKey": value},
                    "headers": {"authorization": value, "cookie": value},
                },
                "safe": "visible",
            }
            stream = io.StringIO()
            nas_logging.log_event("fuzz", stream=stream, payload=payload)
            raw = stream.getvalue()
            self.assertEqual(len(raw.splitlines()), 1)
            decoded = json.loads(raw)
            encoded = json.dumps(decoded)
            self.assertNotIn(sentinel, encoded)
            self.assertEqual(decoded["payload"]["request"]["clientSecret"], "[redacted]")
            self.assertEqual(decoded["payload"]["request"]["provider"]["apiKey"], "[redacted]")

        @settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.too_slow])
        @given(identifier_candidates(max_size=24))
        def test_transaction_path_generation_never_accepts_root_overlap(self, component: str) -> None:
            with tempfile.TemporaryDirectory() as directory:
                base = pathlib.Path(directory)
                valid_root = base / "live"
                valid_stage = base / "tx" / "new"
                valid_previous = base / "tx" / "previous"
                valid_directory = base / "tx"
                unsafe_component = component.replace("/", "_").replace("\\", "_") or "empty"
                cases: list[tuple[str, str, str, str]] = [
                    ("relative", str(valid_stage), str(valid_previous), str(valid_directory)),
                    ("/", str(valid_stage), str(valid_previous), str(valid_directory)),
                    (str(valid_root), str(valid_root / "new"), str(valid_previous), ""),
                    (str(valid_root), str(valid_stage), str(valid_stage / "previous"), ""),
                    (str(valid_root), str(valid_stage), str(valid_previous), str(valid_root / "tx")),
                    (str(valid_root), str(base / "outside" / "new"), str(valid_previous), str(valid_directory)),
                    (str(valid_root), str(valid_root / unsafe_component), str(valid_previous), ""),
                ]
                lines = [
                    "set -Eeuo pipefail",
                    'export NAS_SECRET_TX_PRIVILEGE=""',
                    f"source {shlex.quote(str(LIBRARY))}",
                    "failures=0",
                ]
                for root, stage, previous, txdir in cases:
                    values = (root, stage, previous, "nas-protected-services.target", txdir)
                    command = "nas_secret_tx_init " + " ".join(shlex.quote(value) for value in values)
                    lines.append(f"if {command} >/dev/null 2>&1; then failures=$((failures+1)); fi")
                lines.append('[[ "$failures" -eq 0 ]]')
                result = subprocess.run(
                    ["bash", "-c", "\n".join(lines)],
                    cwd=base,
                    env=os.environ.copy(),
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=20,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        @settings(max_examples=80, deadline=None, suppress_health_check=[HealthCheck.too_slow])
        @given(identifier_candidates(max_size=48))
        def test_transaction_target_never_accepts_non_target_or_option_units(self, value: str) -> None:
            bad = [
                "--root=/tmp.target",
                "-x.target",
                "bad.service",
                "bad.socket",
                "bad target.target",
                "bad.target\nnext.target",
                "bad.target\rnext.target",
                "../bad.target",
                value + ".service",
            ]
            with tempfile.TemporaryDirectory() as directory:
                base = pathlib.Path(directory)
                root, stage, previous = base / "root", base / "stage", base / "previous"
                script = [
                    "set -Eeuo pipefail",
                    'export NAS_SECRET_TX_PRIVILEGE=""',
                    f"source {shlex.quote(str(LIBRARY))}",
                    f"root={shlex.quote(str(root))}",
                    f"stage={shlex.quote(str(stage))}",
                    f"previous={shlex.quote(str(previous))}",
                    "failures=0",
                ]
                for target in bad:
                    script.append(
                        f'if nas_secret_tx_init "$root" "$stage" "$previous" {shlex.quote(target)} >/dev/null 2>&1; then failures=$((failures+1)); fi'
                    )
                script.append('[[ "$failures" -eq 0 ]]')
                result = subprocess.run(
                    ["bash", "-c", "\n".join(script)],
                    cwd=base,
                    env=os.environ.copy(),
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=20,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
else:

    @unittest.skip("Hypothesis is not installed; CI runs this suite in the Nix test environment")
    class SecretSecurityFuzzTests(unittest.TestCase):  # pyright: ignore[reportRedeclaration]
        def test_hypothesis_tier_placeholder(self) -> None:
            pass


if __name__ == "__main__":
    unittest.main()
