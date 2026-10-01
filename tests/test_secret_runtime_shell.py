from __future__ import annotations

import pathlib
import subprocess
import tempfile
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

    def test_secret_command_sources_one_canonical_runtime_library(self) -> None:
        source = (ROOT / "modules/nas/internal/secret-tools.nix").read_text()
        self.assertIn("source ${../../../scripts/lib/nas-secret-runtime.sh}", source)
        for function in (
            "require_secret_atom",
            "require_secret_hex",
            "require_ntfy_topic",
            "require_huggingface_token",
            "install_secret",
        ):
            self.assertNotIn(function + "() {", source)

    def test_private_install_rejects_unsafe_sources_before_sudo(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            secret = root / "secret"
            secret.write_text("private-value")
            link = root / "link"
            link.symlink_to(secret)
            for path in (link, root / "missing", root):
                with self.subTest(path=path):
                    result = self.run_shell(
                        "sudo() { echo unexpected-sudo; return 99; }; "
                        f'install_secret "{path}" "{root / "target"}" owner group'
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn("unexpected-sudo", result.stdout)
                    self.assertIn("Refusing to install", result.stderr)

    def test_private_install_preserves_contents_and_owner_only_read_mode(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            source = root / "source"
            target = root / "target"
            source.write_text("private-value")
            result = self.run_shell(
                f'sudo() {{ shift; install -m 0400 -- "$8" "$9"; }}; install_secret "{source}" "{target}" owner group'
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(target.read_text(), "private-value")
            self.assertEqual(target.stat().st_mode & 0o777, 0o400)

    def test_generic_atom_and_hex_validation(self) -> None:
        self.assertEqual(self.run_shell("require_secret_atom 'safe-token_123' token 8 64").returncode, 0)
        self.assertNotEqual(self.run_shell("require_secret_atom $'bad\\nvalue' token 8 64").returncode, 0)
        self.assertEqual(self.run_shell("require_secret_hex 'abcdef0123456789' 16 key").returncode, 0)
        self.assertNotEqual(self.run_shell("require_secret_hex 'xyz' 3 key").returncode, 0)

    def test_service_specific_validation(self) -> None:
        self.assertEqual(self.run_shell("require_ntfy_topic private_topic-123").returncode, 0)
        self.assertNotEqual(self.run_shell("require_ntfy_topic 'bad/topic'").returncode, 0)
        self.assertEqual(self.run_shell("require_huggingface_token ''").returncode, 0)
        self.assertEqual(self.run_shell("require_huggingface_token hf_abcdefghijklmnopqrst").returncode, 0)
        self.assertNotEqual(self.run_shell("require_huggingface_token hf_short").returncode, 0)


if __name__ == "__main__":
    unittest.main()
