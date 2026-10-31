"""Command-level safety tests for destructive live drills; no real ZFS/Restic used."""
from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
DRILL = ROOT / "scripts" / "live-validation.sh"


class LiveValidationSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.log = self.root / "commands.log"
        self.mount = self.root / "mountpoint"
        self.mount.mkdir()
        self.source = self.root / "restic-source"
        self.source.mkdir()
        self.restore = self.root / "restic-restore"
        self.restore.mkdir()
        self.env = dict(
            os.environ,
            PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
            NAS_TEST_LOG=str(self.log),
            NAS_TEST_MOUNT=str(self.mount),
            NAS_LIVE_CONFIRM="SYNCOID_DRILL,RESTIC_DRILL",
            NAS_SYNCOID_SOURCE="tank/source",
            NAS_SYNCOID_TARGET="tank/target",
            NAS_RESTIC_SOURCE=str(self.source),
            NAS_RESTIC_RESTORE_TARGET=str(self.restore),
            RESTIC_REPOSITORY="test-repository",
            RESTIC_PASSWORD_FILE=str(self.root / "password"),
        )
        self._command(
            "zfs",
            """#!/bin/bash
set -euo pipefail
printf 'zfs %s\\n' "$*" >> "$NAS_TEST_LOG"
case "$1" in
  list)
    printf '%s\\n' 'tank/source' 'tank/target'
    if [[ -n "${NAS_TEST_EXISTING_CLONE:-}" ]]; then printf '%s\\n' "$NAS_TEST_EXISTING_CLONE"; fi
    ;;
  create)
    if [[ "${NAS_TEST_CREATE_FAIL:-}" == 1 ]]; then exit 20; fi ;;
  get) printf '%s\\n' "$NAS_TEST_MOUNT" ;;
  snapshot|clone|destroy) ;;
  *) exit 64 ;;
esac
""",
        )
        self._command(
            "syncoid",
            """#!/bin/bash
set -euo pipefail
printf 'syncoid %s\\n' "$*" >> "$NAS_TEST_LOG"
if [[ "${NAS_TEST_SYNCOID_FAIL:-}" == 1 ]]; then exit 21; fi
""",
        )

    def _command(self, name: str, script: str) -> None:
        file = self.bin / name
        file.write_text(script, encoding="utf-8")
        file.chmod(0o755)

    def run_drill(self, mode: str, **overrides: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(DRILL), mode],
            env={**self.env, **overrides},
            capture_output=True, text=True, check=False, timeout=15,
        )

    def commands(self) -> list[str]:
        return self.log.read_text(encoding="utf-8").splitlines() if self.log.exists() else []

    def test_preexisting_clone_is_refused_before_any_mutation(self) -> None:
        result = self.run_drill(
            "syncoid", NAS_SYNCOID_LOCAL_CLONE="tank/preexisting",
            NAS_TEST_EXISTING_CLONE="tank/preexisting",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("clone dataset already exists", result.stderr)
        self.assertFalse(any(row.startswith(("zfs create", "zfs destroy", "syncoid ")) for row in self.commands()))

    def test_remote_existing_clone_is_rejected_without_remote_cleanup(self) -> None:
        self._command(
            "ssh",
            """#!/bin/bash
set -euo pipefail
printf 'ssh %s\\n' "$*" >> "$NAS_TEST_LOG"
# Remote ZFS helper invokes: ssh -o BatchMode=yes host bash -s -- action name [name].
if [[ "$1" == -o && "$2" == BatchMode=yes ]]; then shift 3; fi
exec "$@"
""",
        )
        result = self.run_drill(
            "syncoid", NAS_SYNCOID_TARGET="remotehost:tank/target",
            NAS_SYNCOID_REMOTE_CLONE="tank/preexisting",
            NAS_TEST_EXISTING_CLONE="tank/preexisting",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("clone dataset already exists", result.stderr)
        rows = self.commands()
        self.assertTrue(any(row.startswith("ssh ") for row in rows))
        self.assertFalse(any(row.startswith(("zfs create", "zfs destroy", "syncoid ")) for row in rows))

    def test_failed_source_create_does_not_destroy_anything(self) -> None:
        result = self.run_drill("syncoid", NAS_TEST_CREATE_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        rows = self.commands()
        self.assertEqual(len([row for row in rows if row.startswith("zfs create ")]), 1)
        self.assertFalse(any(row.startswith("zfs destroy") for row in rows))

    def test_failed_replication_only_removes_owned_source(self) -> None:
        result = self.run_drill("syncoid", NAS_TEST_SYNCOID_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        rows = self.commands()
        creates = [row for row in rows if row.startswith("zfs create -- ")]
        self.assertEqual(len(creates), 1)
        source = creates[0].removeprefix("zfs create -- ")
        destroys = [row for row in rows if row.startswith("zfs destroy")]
        self.assertEqual(destroys, ["zfs destroy -r -- " + source])
        self.assertEqual(len([r for r in rows if r.startswith("syncoid ")]), 1)

    def test_successful_replication_only_cleans_its_own_names(self) -> None:
        result = self.run_drill("syncoid")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        rows = self.commands()
        creates = [row for row in rows if row.startswith("zfs create -- ")]
        self.assertEqual(len(creates), 1)
        source = creates[0].removeprefix("zfs create -- ")
        source_destroy = "zfs destroy -r -- " + source
        self.assertEqual(rows.count(source_destroy), 1)
        self.assertTrue(any(row.startswith("zfs clone -- ") for row in rows))
        self.assertTrue(any(row.startswith("zfs destroy -r -- tank/target/nas-live-") for row in rows))
        self.assertFalse(any(row == "zfs destroy -r -- tank/target" for row in rows))

    def test_restic_preserves_preexisting_restore_directory_and_cleans_owned_paths(self) -> None:
        existing = self.restore / "nas-live-existing"
        existing.mkdir()
        sentinel = existing / "untouched"
        sentinel.write_bytes(b"original")
        self._command(
            "restic",
            """#!/bin/bash
set -euo pipefail
printf 'restic %s\\n' "$*" >> "$NAS_TEST_LOG"
case "$1" in
  backup) echo '{"message_type":"summary","snapshot_id":"test-snapshot"}' ;;
  restore)
    dest="$4"
    mkdir -p -- "$dest$NAS_RESTIC_SOURCE"
    cp -- "$NAS_RESTIC_SOURCE"/.nas-live-* "$dest$NAS_RESTIC_SOURCE/"
    ;;
  *) exit 64 ;;
esac
""",
        )
        self._command(
            "jq",
            """#!/usr/bin/env python3
import json, sys
for line in sys.stdin:
    obj = json.loads(line)
    if obj.get("message_type") == "summary":
        print(obj["snapshot_id"])
""",
        )
        result = self.run_drill("restic")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(sentinel.read_bytes(), b"original")
        self.assertEqual(list(self.restore.iterdir()), [existing])
        self.assertEqual(list(self.source.glob(".nas-live-*")), [])


if __name__ == "__main__":
    unittest.main()
