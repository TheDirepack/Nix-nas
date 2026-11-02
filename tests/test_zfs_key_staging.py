from __future__ import annotations

import hashlib
import os
import pathlib
import pty
import subprocess
import tempfile
import threading
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

PROMPT = b"KeePass database password: "
PASSWORD = b"fixture-password"


def extract_shell_function(source: str, name: str) -> str:
    """Extract one nas-secrets shell function from the Nix string literal."""
    lines = source.splitlines()
    marker = f"      {name}() {{"
    try:
        start = lines.index(marker)
    except ValueError as exc:
        raise AssertionError(f"{name} is missing from secret-tools.nix") from exc
    for end in range(start + 1, len(lines)):
        if lines[end] == "      }":
            block = lines[start : end + 1]
            return "\n".join(line[6:] if line.startswith("      ") else line for line in block)
    raise AssertionError(f"{name} is not terminated in secret-tools.nix")


class ZfsKeyStagingTests(unittest.TestCase):
    def reader_script(self) -> str:
        """Build the nas-secrets reader from the real prompt and key commands.

        Only the KeePassXC database access is stubbed. The prompt, its terminal
        handling, the key emission, and the newline that follows a password
        entry are the production code paths, so prompt output that reaches
        stdout makes the captured key unusable and fails these tests.
        """
        source = (ROOT / "modules/nas/internal/secret-tools.nix").read_text()
        functions = "\n\n".join(
            extract_shell_function(source, name)
            for name in (
                "prompt_unlock",
                "command_show_zfs_key",
                "command_show_zfs_key_stdin",
            )
        ).replace("''${", "${")
        return (
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            'database="$PWD/fixture.kdbx"\n'
            'key_file=""\n'
            "password_from_stdin=false\n"
            'keepass_password=""\n'
            "require_database() { :; }\n"
            "keepassxc-cli() { return 0; }\n"
            "get_secret() { printf '%s' \"$TEST_KEY\"; }\n"
            f"{functions}\n"
            'case "${1:-}" in\n'
            "  show-zfs-key) command_show_zfs_key ;;\n"
            "  show-zfs-key-stdin) command_show_zfs_key_stdin ;;\n"
            '  *) echo "unexpected reader action: ${1:-}" >&2; exit 2 ;;\n'
            "esac\n"
        )

    def run_key_path(self, *, export: bool, fail_install: bool = False, tty: bool = False):
        source = (ROOT / "modules/nas/internal/zfs-tools.nix").read_text()
        if export:
            block = source.split("nasZfsExportRecoveryKey =", 1)[1]
            boundary = "      if [[ -t 0 ]]; then"
            body = boundary + block.split(boundary, 1)[1].split("    '';", 1)[0]
            body = body.replace("${nasSecrets}/bin/nas-secrets", "$secret_reader")
        else:
            block = source.split("nasZfsCreateEncryptedDataset =", 1)[1]
            boundary = '      key="$($secret_reader'
            body = boundary + block.split(boundary, 1)[1].split("    '';", 1)[0]
        body = body.replace("''${", "${").replace("${zfsKeyFingerprintProperty}", "org.nixos:key")
        with tempfile.TemporaryDirectory() as raw:
            work = pathlib.Path(raw)
            key = "ab" * 32
            fingerprint = hashlib.sha256(key.encode()).hexdigest()
            harness = """
set -euo pipefail
key="$TEST_KEY"
stored_fingerprint="$TEST_FINGERPRINT"
dataset=tank/nas
root=/tank
algorithm=aes-256-gcm
final_keylocation=file:///run/nas-secrets/zfs/key
output="$PWD/recovery.key"
created_dataset=false
bootstrap_committed=false
secret_reader="$PWD/reader"
zfs=zfs_stub
zfs_stub() {
  printf '%s\\n' "$*" >> zfs.log
  [[ "$1" != get ]] || printf 'no\\n'
}
mktemp() { echo 'UNPRIVILEGED_MKTEMP' >&2; return 91; }
sudo() {
  case "$1" in -n) shift ;; esac
  case "$1" in
    mktemp) command mktemp "$PWD/runtime.XXXXXX" ;;
    install)
      shift
      [[ "${FAIL_INSTALL:-0}" != 1 ]] || return 92
      command install -m 0400 "${@: -2:1}" "${@: -1}"
      ;;
    *) "$@" ;;
  esac
}
"""
            (work / "reader").write_text(self.reader_script())
            (work / "reader").chmod(0o700)
            env = {
                **os.environ,
                "TEST_KEY": key,
                "TEST_FINGERPRINT": fingerprint,
                "FAIL_INSTALL": "1" if fail_install else "0",
            }
            if tty:
                result, password_sent, _ = self._run_on_terminal(["bash", "-c", harness + body], work, env, timeout=20)
                self.assertTrue(password_sent, "interactive reader never displayed its prompt")
                self.assertIn(PROMPT.decode(), result.stdout)
                self.assertNotIn(PASSWORD.decode(), result.stdout)
            else:
                result = subprocess.run(
                    ["bash", "-c", harness + body],
                    cwd=work,
                    input=PASSWORD.decode() + "\n",
                    capture_output=True,
                    text=True,
                    timeout=20,
                    env=env,
                )
            self.assertEqual(list(work.glob("runtime.*")), [])
            if export and not fail_install and result.returncode == 0:
                output = work / "recovery.key"
                self.assertEqual(output.read_text(), key)
                self.assertEqual(output.stat().st_mode & 0o777, 0o400)
            if not export and result.returncode == 0:
                # The bootstrap only accepts a key that survives the hex check,
                # which fails when the reader leaks a newline into stdout.
                self.assertIn(f"org.nixos:key={fingerprint}", (work / "zfs.log").read_text())
            self.assertNotIn(key, result.stdout + result.stderr)
            return result

    def _run_on_terminal(self, argv, cwd, env, timeout, capture_stdout=False):
        """Run argv on a pseudo-terminal and type the password at the prompt.

        Bash only prints the ``read -p`` prompt on a terminal, so a pipe would
        leave the prompt and terminal echo untreated.
        """
        master, slave = pty.openpty()
        proc = subprocess.Popen(
            argv,
            stdin=slave,
            stdout=subprocess.PIPE if capture_stdout else slave,
            stderr=slave,
            cwd=cwd,
            env=env,
        )
        os.close(slave)
        chunks = []

        def drain():
            while True:
                try:
                    chunk = os.read(master, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
                if proc.poll() is not None:
                    while True:
                        try:
                            extra = os.read(master, 4096)
                        except OSError:
                            break
                        if not extra:
                            break
                        chunks.append(extra)
                    break

        thread = threading.Thread(target=drain, daemon=True)
        thread.start()

        password_sent = False
        deadline = time.time() + timeout
        while time.time() < deadline and not password_sent:
            if PROMPT in b"".join(chunks):
                try:
                    os.write(master, PASSWORD + b"\n")
                except OSError:
                    pass
                password_sent = True
            time.sleep(0.01)

        if not password_sent:
            # Unblock a reader that may be waiting on the terminal so the
            # process can terminate instead of hanging the test.
            try:
                os.close(master)
            except OSError:
                pass

        captured = b""
        if capture_stdout and proc.stdout is not None:
            captured = proc.stdout.read()
            proc.stdout.close()
        proc.wait(timeout=timeout)
        thread.join(timeout=5)
        try:
            os.close(master)
        except OSError:
            pass

        transcript = b"".join(chunks).decode(errors="replace")
        result = subprocess.CompletedProcess(
            args=argv,
            returncode=proc.returncode,
            stdout=transcript,
            stderr="",
        )
        return result, password_sent, captured

    def test_bootstrap_streams_key_without_an_operator_tempfile(self):
        result = self.run_key_path(export=False)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_export_streams_key_without_an_operator_tempfile(self):
        result = self.run_key_path(export=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_bootstrap_interactive_tty_exercises_reader_prompt(self):
        result = self.run_key_path(export=False, tty=True)
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_export_interactive_tty_exercises_reader_prompt(self):
        result = self.run_key_path(export=True, tty=True)
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_interactive_reader_writes_only_the_key_to_stdout(self):
        """A password prompt must not contaminate the captured ZFS key."""
        with tempfile.TemporaryDirectory() as raw:
            work = pathlib.Path(raw)
            key = "cd" * 32
            (work / "reader").write_text(self.reader_script())
            (work / "reader").chmod(0o700)
            env = {**os.environ, "TEST_KEY": key, "TEST_FINGERPRINT": "unused"}
            result, password_sent, captured = self._run_on_terminal(
                ["bash", str(work / "reader"), "show-zfs-key"],
                work,
                env,
                timeout=20,
                capture_stdout=True,
            )
        self.assertTrue(password_sent, "reader never displayed its prompt")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn(PROMPT.decode(), result.stdout)
        self.assertEqual(captured.decode(), key)

    def test_failed_install_cleans_runtime_key_and_returns_failure(self):
        for export in (False, True):
            with self.subTest(export=export):
                result = self.run_key_path(export=export, fail_install=True)
                self.assertEqual(result.returncode, 92, result.stderr)


if __name__ == "__main__":
    unittest.main()
