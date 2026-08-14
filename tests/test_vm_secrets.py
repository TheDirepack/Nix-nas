from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "lib" / "nas-vm-secret-input.sh"


class VmSecretInputTests(unittest.TestCase):
    def test_hostile_secret_is_forwarded_as_stdin_data(self) -> None:
        secret = "quote' \" slash\\ dollar$HOME $(touch marker) `id` ;\nsecond line"
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "received"
            marker = pathlib.Path(temporary) / "marker"
            receiver = 'cat > "$1"'
            script = (
                'set -Eeuo pipefail; source "$1"; '
                'nas_vm_run_with_secret_stdin "$2" bash -c \'' + receiver + '\' receiver "$3"'
            )
            result = subprocess.run(
                ["bash", "-c", script, "secret-test", str(HELPER), secret, str(output)],
                cwd=ROOT,
                env={**os.environ, "MARKER": str(marker)},
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output.read_text(encoding="utf-8"), secret + "\n")
            self.assertFalse(marker.exists())

    def test_guest_wrappers_use_the_shared_stdin_boundary(self) -> None:
        for name in ("guest-test.sh", "encrypted-guest-test.sh"):
            with self.subTest(name=name):
                source = (ROOT / "tests" / "vm" / name).read_text(encoding="utf-8")
                self.assertIn("nas_vm_run_with_secret_stdin", source)
                self.assertNotIn("printf '%s\\n' \"$KEEPASS_PASSWORD\" | runuser", source)


if __name__ == "__main__":
    unittest.main()
