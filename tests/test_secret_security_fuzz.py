from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
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
    from fuzz_strategies import secret_key_names

    import tests  # noqa: F401  (builds nas-keepass-setup)


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

        @settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])
        @given(
            st.text(alphabet=st.characters(min_codepoint=0x20, blacklist_categories=("Cs", "Cc")), max_size=40),
            st.one_of(
                st.none(),
                st.text(
                    alphabet=st.characters(min_codepoint=0x20, blacklist_categories=("Cs", "Cc")),
                    min_size=1,
                    max_size=40,
                ),
            ),
        )
        def test_go_strength_floor_matches_the_specification(self, password: str, administrator: str | None) -> None:
            """Differential: StrongKeePassPassword agrees with the written rule."""
            if not password:
                return
            if "NAS_KEEPASS_SETUP_BIN" not in os.environ:
                self.skipTest("nas-keepass-setup is unavailable")
            payload = password + "\n" + ("" if administrator is None else administrator + "\n")
            result = subprocess.run(
                [os.environ["NAS_KEEPASS_SETUP_BIN"], "check-strength"],
                input=payload,
                text=True,
                capture_output=True,
                check=False,
                timeout=30,
            )
            expected = (
                len(password) >= 16
                and len(set(password)) >= 6
                and (administrator is None or password.casefold() != administrator.casefold())
            )
            event("strong" if expected else "weak")
            self.assertEqual(result.returncode == 0, expected, result.stderr)
            if len(password) >= 8:
                self.assertNotIn(password, result.stderr)

else:

    @unittest.skip("Hypothesis is not installed; CI runs this suite in the Nix test environment")
    class SecretSecurityFuzzTests(unittest.TestCase):  # pyright: ignore[reportRedeclaration]
        def test_hypothesis_tier_placeholder(self) -> None:
            pass


if __name__ == "__main__":
    unittest.main()
