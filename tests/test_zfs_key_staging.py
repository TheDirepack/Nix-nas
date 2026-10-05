from __future__ import annotations

import hashlib
import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class ZfsKeyStagingTests(unittest.TestCase):
    def run_key_path(self, *, export: bool, fail_install: bool = False):
        source = (ROOT / "modules/nas/internal/zfs-tools.nix").read_text()
        block = source.split("nasZfsExportRecoveryKey =" if export else "nasZfsCreateEncryptedDataset =", 1)[1]
        body = block.split("      key_fingerprint=" if export else '      key="$($secret_reader', 1)[1]
        body = ("      key_fingerprint=" if export else '      key="$($secret_reader') + body.split("    '';", 1)[0]
        body = body.replace("''${", "${").replace("${zfsKeyFingerprintProperty}", "org.nixos:key")
        with tempfile.TemporaryDirectory() as raw:
            work = pathlib.Path(raw)
            key = "ab" * 32
            script = """
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
            (work / "reader").write_text('#!/bin/sh\nprintf "%s" "$TEST_KEY"\n')
            (work / "reader").chmod(0o700)
            result = subprocess.run(
                ["bash", "-c", script + body],
                cwd=work,
                capture_output=True,
                text=True,
                timeout=10,
                env={
                    **os.environ,
                    "TEST_KEY": key,
                    "TEST_FINGERPRINT": hashlib.sha256(key.encode()).hexdigest(),
                    "FAIL_INSTALL": "1" if fail_install else "0",
                },
            )
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

    def test_failed_install_cleans_runtime_key_and_returns_failure(self):
        for export in (False, True):
            with self.subTest(export=export):
                result = self.run_key_path(export=export, fail_install=True)
                self.assertEqual(result.returncode, 92, result.stderr)


if __name__ == "__main__":
    unittest.main()
