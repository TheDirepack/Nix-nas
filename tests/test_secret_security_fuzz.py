from __future__ import annotations

import io
import json
import os
import pathlib
import random
import string
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_logging

LIBRARY = ROOT / "scripts/lib/nas-secret-transaction.sh"


class SecretSecurityFuzzTests(unittest.TestCase):
    def test_secret_key_naming_variants_never_leak_values(self) -> None:
        rng = random.Random(0x534543524554)
        bases = (
            "password",
            "passwd",
            "token",
            "secret",
            "api_key",
            "access_key",
            "private_key",
            "client_secret",
            "access_token",
            "refresh_token",
            "session_token",
            "cookie",
        )
        sentinel = "SENTINEL-SECRET-DO-NOT-LOG"

        def camel(value: str) -> str:
            head, *tail = value.split("_")
            return head + "".join(part[:1].upper() + part[1:] for part in tail)

        for index in range(500):
            base = rng.choice(bases)
            style = rng.randrange(5)
            if style == 0:
                key = base
            elif style == 1:
                key = base.replace("_", "-")
            elif style == 2:
                key = base.replace("_", ".")
            elif style == 3:
                key = camel(base)
            else:
                key = f"provider_{base}"
            if rng.random() < 0.5:
                key = key[:1].upper() + key[1:]
            with self.subTest(index=index, key=key):
                sanitized = nas_logging.sanitize({key: sentinel})
                self.assertEqual(sanitized[key], "[redacted]")
                self.assertNotIn(sentinel, json.dumps(sanitized))

    def test_nested_hostile_secret_values_never_escape_structured_log_redaction(self) -> None:
        rng = random.Random(0x4B444258)
        alphabet = string.ascii_letters + string.digits + "\r\n\x00'\"\\$`;|&<>"
        for index in range(250):
            value = "".join(rng.choice(alphabet) for _ in range(rng.randrange(1, 512)))
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
            with self.subTest(index=index):
                self.assertEqual(len(raw.splitlines()), 1)
                decoded = json.loads(raw)
                encoded = json.dumps(decoded)
                self.assertNotIn(value, encoded)
                self.assertEqual(decoded["payload"]["request"]["clientSecret"], "[redacted]")
                self.assertEqual(decoded["payload"]["request"]["provider"]["apiKey"], "[redacted]")

    def test_transaction_path_fuzz_rejects_relative_root_overlap_and_filesystem_root(self) -> None:
        rng = random.Random(0x5452414E53414354)
        with tempfile.TemporaryDirectory() as directory:
            base = pathlib.Path(directory)
            valid_root = base / "live"
            valid_stage = base / "tx" / "new"
            valid_previous = base / "tx" / "previous"
            valid_directory = base / "tx"
            cases: list[tuple[str, str, str, str]] = [
                ("relative", str(valid_stage), str(valid_previous), str(valid_directory)),
                ("/", str(valid_stage), str(valid_previous), str(valid_directory)),
                (str(valid_root), str(valid_root / "new"), str(valid_previous), ""),
                (str(valid_root), str(valid_stage), str(valid_stage / "previous"), ""),
                (str(valid_root), str(valid_stage), str(valid_previous), str(valid_root / "tx")),
                (str(valid_root), str(base / "outside" / "new"), str(valid_previous), str(valid_directory)),
            ]
            for _ in range(100):
                component = "".join(rng.choice(string.ascii_letters + string.digits + "._-") for _ in range(12))
                cases.append((str(valid_root), str(valid_root / component), str(valid_previous), ""))
            lines = [
                "set -Eeuo pipefail",
                'export NAS_SECRET_TX_PRIVILEGE=""',
                f"source {LIBRARY!s}",
                "failures=0",
            ]
            for root, stage, previous, txdir in cases:
                target = "nas-protected-services.target"
                command = "nas_secret_tx_init " + " ".join(
                    subprocess.list2cmdline([value]) for value in (root, stage, previous, target, txdir)
                )
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

    def test_transaction_target_fuzz_never_accepts_option_or_non_target_units(self) -> None:
        rng = random.Random(0x554E4954)
        bad = [
            "--root=/tmp.target",
            "-x.target",
            "bad.service",
            "bad.socket",
            "bad target.target",
            "bad.target\nnext.target",
            "bad.target\rnext.target",
            "../bad.target",
            "",
        ]
        bad.extend(
            "".join(rng.choice(string.ascii_letters + string.digits + "/ \\;$") for _ in range(24)) + ".service"
            for _ in range(100)
        )
        with tempfile.TemporaryDirectory() as directory:
            base = pathlib.Path(directory)
            root, stage, previous = base / "root", base / "stage", base / "previous"
            script = ["set -Eeuo pipefail", 'export NAS_SECRET_TX_PRIVILEGE=""', f"source {LIBRARY!s}"]
            script.append(f"root={subprocess.list2cmdline([str(root)])}")
            script.append(f"stage={subprocess.list2cmdline([str(stage)])}")
            script.append(f"previous={subprocess.list2cmdline([str(previous)])}")
            script.append("failures=0")
            for target in bad:
                quoted = subprocess.list2cmdline([target])
                script.append(
                    f'if nas_secret_tx_init "$root" "$stage" "$previous" {quoted} >/dev/null 2>&1; then failures=$((failures+1)); fi'
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


if __name__ == "__main__":
    unittest.main()
