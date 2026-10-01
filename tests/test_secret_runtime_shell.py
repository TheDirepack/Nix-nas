from __future__ import annotations

import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
LIBRARY = ROOT / "scripts" / "lib" / "nas-secret-runtime.sh"


class SecretRuntimeShellTests(unittest.TestCase):
    def run_shell(self, body: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", "-c", f"set -euo pipefail; source {LIBRARY!s}; {body}"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_library_is_sourceable_and_not_an_executable_surface(self) -> None:
        self.assertFalse(LIBRARY.read_bytes().startswith(b"#!"))
        result = subprocess.run(["bash", "-n", str(LIBRARY)], cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_generic_atom_and_hex_validation(self) -> None:
        self.assertEqual(self.run_shell("nas_secret_require_atom 'safe-token_123' token 8 64").returncode, 0)
        self.assertNotEqual(self.run_shell("nas_secret_require_atom $'bad\\nvalue' token 8 64").returncode, 0)
        self.assertEqual(self.run_shell("nas_secret_require_hex 'abcdef0123456789' 16 key").returncode, 0)
        self.assertNotEqual(self.run_shell("nas_secret_require_hex 'xyz' 3 key").returncode, 0)

    def test_service_specific_validation(self) -> None:
        self.assertEqual(self.run_shell("nas_secret_require_ntfy_topic private_topic-123").returncode, 0)
        self.assertNotEqual(self.run_shell("nas_secret_require_ntfy_topic 'bad/topic'").returncode, 0)
        self.assertEqual(self.run_shell("nas_secret_require_huggingface_token ''").returncode, 0)
        self.assertEqual(self.run_shell("nas_secret_require_huggingface_token hf_abcdefghijklmnopqrst").returncode, 0)
        self.assertNotEqual(self.run_shell("nas_secret_require_huggingface_token hf_short").returncode, 0)


if __name__ == "__main__":
    unittest.main()
