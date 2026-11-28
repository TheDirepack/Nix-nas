from __future__ import annotations

import json
import os
import pathlib
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
    from fuzz_strategies import identifier_candidates, secret_key_names
    from zig_binaries import harness_bin_dir


def harness_safe_component(value: str) -> str:
    """Keep generated path structure hostile within the harness's tab/line protocol."""

    value = value.replace("/", "_").replace("\\", "_")
    value = "".join("_" if ord(character) < 32 or ord(character) == 127 else character for character in value)
    return value or "empty"


def harness_init_statuses(base: pathlib.Path, cases: list[tuple[str, ...]]) -> list[int]:
    """Run `init` for each case through the Zig transaction; return the statuses."""
    script = "\n".join("\t".join(("init", *case)) for case in cases) + "\n"
    result = subprocess.run(
        [str(harness_bin_dir() / "nas-secret-tx-harness")],
        input=script,
        cwd=base,
        env={**os.environ, "NAS_SECRET_TX_PRIVILEGE": "", "NAS_SECRET_TX_SYSTEMCTL": "/bin/false"},
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    return [int(line.split(" ", 1)[1]) for line in result.stdout.splitlines() if line.startswith("init ")]


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
            raw = json.dumps(nas_logging.sanitize({"payload": payload}))
            self.assertEqual(len(raw.splitlines()), 1)
            decoded = json.loads(raw)
            encoded = json.dumps(decoded)
            self.assertNotIn(sentinel, encoded)
            self.assertEqual(decoded["payload"]["request"]["clientSecret"], "[redacted]")
            self.assertEqual(decoded["payload"]["request"]["provider"]["apiKey"], "[redacted]")

        @settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.too_slow])
        @given(identifier_candidates(max_size=24))
        def test_transaction_path_generation_never_accepts_root_overlap(self, component: str) -> None:
            with tempfile.TemporaryDirectory() as directory:
                base = pathlib.Path(directory)
                valid_root = base / "live"
                valid_stage = base / "tx" / "new"
                valid_previous = base / "tx" / "previous"
                valid_directory = base / "tx"
                valid_directory.mkdir()
                generated_component = harness_safe_component(component)
                target = "nas-protected-services.target"
                cases: list[tuple[str, ...]] = [
                    ("relative", str(valid_stage), str(valid_previous), target, str(valid_directory)),
                    ("/", str(valid_stage), str(valid_previous), target, str(valid_directory)),
                    (str(valid_root), str(valid_root / "new"), str(valid_previous)),
                    (str(valid_root), str(valid_stage), str(valid_stage / "previous")),
                    (str(valid_root), str(valid_stage), str(valid_previous), target, str(valid_root / "tx")),
                    (str(valid_root), str(base / "outside" / "new"), str(valid_previous), target, str(valid_directory)),
                    (str(valid_root), str(valid_root / generated_component), str(valid_previous)),
                ]
                statuses = harness_init_statuses(base, cases)
                self.assertEqual(len(statuses), len(cases))
                self.assertNotIn(0, statuses)

        @settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow])
        @given(identifier_candidates(max_size=48))
        def test_transaction_target_never_accepts_non_target_or_option_units(self, value: str) -> None:
            # Newline/CR-bearing targets cannot cross the harness's line protocol;
            # zig/src/validate.zig fuzzes UnitName/TargetName directly for those.
            generated = harness_safe_component(value)
            bad = [
                "--root=/tmp.target",
                "-x.target",
                "bad.service",
                "bad.socket",
                "bad target.target",
                "../bad.target",
                generated + ".service",
            ]
            with tempfile.TemporaryDirectory() as directory:
                base = pathlib.Path(directory)
                cases = [(str(base / "root"), str(base / "stage"), str(base / "previous"), target) for target in bad]
                statuses = harness_init_statuses(base, cases)
                self.assertEqual(len(statuses), len(cases))
                self.assertNotIn(0, statuses)
else:

    @unittest.skip("Hypothesis is not installed; CI runs this suite in the Nix test environment")
    class SecretSecurityFuzzTests(unittest.TestCase):  # pyright: ignore[reportRedeclaration]
        def test_hypothesis_tier_placeholder(self) -> None:
            pass


if __name__ == "__main__":
    unittest.main()
