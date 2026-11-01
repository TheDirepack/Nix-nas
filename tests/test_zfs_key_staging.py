from __future__ import annotations

import hashlib
import os
import pathlib
import pty
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class ZfsKeyStagingTests(unittest.TestCase):
    def key_body(self, *, export: bool) -> str:
        source = (ROOT / "modules/nas/internal/zfs-tools.nix").read_text()
        block = source.split("nasZfsExportRecoveryKey =" if export else "nasZfsCreateEncryptedDataset =", 1)[1]
        marker = "      if [[ -t 0 ]]; then"
        body = marker + block.split(marker, 1)[1].split("    '';", 1)[0]
        return (
            body.replace("''${", "${")
            .replace("${zfsKeyFingerprintProperty}", "org.nixos:key")
            .replace("${nasSecrets}/bin/nas-secrets", '"$secret_reader"')
        )

    def test_bootstrap_key_path_passes_shellcheck(self):
        result = subprocess.run(
            ["shellcheck", "--shell=bash", "-"],
            input="secret_reader=reader; zfs=zfs; dataset=tank/nas; algorithm=aes-256-gcm; root=/tank; "
            "final_keylocation=file:///fixture/key\n" + self.key_body(export=False),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_real_secret_reader_prompt_keeps_captured_zfs_key_clean(self):
        source = (ROOT / "modules/nas/internal/secret-tools.nix").read_text()
        functions = (
            "require_database() {"
            + source.split("require_database() {", 1)[1].split("ensure_group() {", 1)[0]
            + "get_secret() {"
            + source.split("get_secret() {", 1)[1].split("get_secret_optional() {", 1)[0]
            + "command_show_zfs_key() {"
            + source.split("command_show_zfs_key() {", 1)[1].split("command_show_authentik_bootstrap() {", 1)[0]
        ).replace("''${", "${")
        with tempfile.TemporaryDirectory() as raw:
            directory = pathlib.Path(raw)
            (directory / "database.kdbx").touch()
            for command in ("command_show_zfs_key", "command_show_zfs_key_stdin"):
                with self.subTest(command=command):
                    script = (
                        """
set -euo pipefail
database=database.kdbx
key_file=''
secret_group=fixture
keepass_password=''
password_from_stdin=false
keepassxc-cli() {
  local supplied
  IFS= read -r supplied
  [[ "$supplied" == fixture-password ]] || return 93
  if [[ "$1" == show ]]; then printf 'ab%.0s' {1..32}; fi
}
"""
                        + functions
                        + f'\nkey="$({command})"\n'
                        + """
[[ "$key" =~ ^[A-Fa-f0-9]{64}$ ]]
printf 'key-valid\n'
"""
                    )
                    result = subprocess.run(
                        ["bash", "-c", script],
                        cwd=directory,
                        input="fixture-password\n",
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout, "key-valid\n")
                    self.assertNotIn("fixture-password", result.stdout + result.stderr)

    def run_key_path(self, *, export: bool, fail_install: bool = False, terminal: bool = False, reader_status: int = 0):
        body = self.key_body(export=export)
        with tempfile.TemporaryDirectory() as raw:
            work = pathlib.Path(raw)
            key = "ab" * 32
            script = """
set -euo pipefail
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
            (work / "reader").write_text(
                '#!/bin/sh\nprintf "%s\\n" "$@" >> reader.log\n'
                'test "$READER_STATUS" = 0 || exit "$READER_STATUS"\nprintf "%s" "$TEST_KEY"\n'
            )
            (work / "reader").chmod(0o700)
            master, slave = pty.openpty() if terminal else (None, None)
            try:
                result = subprocess.run(
                    ["bash", "-c", script + body],
                    cwd=work,
                    stdin=slave if terminal else subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    env={
                        **os.environ,
                        "TEST_KEY": key,
                        "TEST_FINGERPRINT": hashlib.sha256(key.encode()).hexdigest(),
                        "FAIL_INSTALL": "1" if fail_install else "0",
                        "READER_STATUS": str(reader_status),
                    },
                )
            finally:
                if master is not None:
                    os.close(master)
                if slave is not None:
                    os.close(slave)
            self.assertEqual(
                (work / "reader.log").read_text().splitlines(),
                ["show-zfs-key" if terminal else "show-zfs-key-stdin"],
            )
            if reader_status:
                self.assertFalse((work / "zfs.log").exists())
                self.assertFalse((work / "recovery.key").exists())
            self.assertEqual(list(work.glob("runtime.*")), [])
            output = work / "recovery.key"
            if export and not fail_install and result.returncode == 0:
                self.assertEqual(output.read_text(), key)
                self.assertEqual(output.stat().st_mode & 0o777, 0o400)
            self.assertNotIn(key, result.stdout + result.stderr)
            return result

    def test_bootstrap_streams_key_without_an_operator_tempfile(self):
        result = self.run_key_path(export=False)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_export_streams_key_without_an_operator_tempfile(self):
        result = self.run_key_path(export=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_terminal_key_selection_is_preserved_for_bootstrap_and_export(self):
        for export in (False, True):
            with self.subTest(export=export):
                result = self.run_key_path(export=export, terminal=True)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_reader_failure_stops_before_key_staging_or_dataset_mutation(self):
        for export in (False, True):
            for terminal in (False, True):
                with self.subTest(export=export, terminal=terminal):
                    result = self.run_key_path(export=export, terminal=terminal, reader_status=93)
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertIn("KeePassXC ZFS key is missing", result.stderr)

    def test_failed_install_cleans_runtime_key_and_returns_failure(self):
        for export in (False, True):
            with self.subTest(export=export):
                result = self.run_key_path(export=export, fail_install=True)
                self.assertEqual(result.returncode, 92, result.stderr)


if __name__ == "__main__":
    unittest.main()
