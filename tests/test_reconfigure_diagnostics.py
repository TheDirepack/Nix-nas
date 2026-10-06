from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class RebuildFailureDiagnosticsTests(unittest.TestCase):
    def rebuild(self, status: int, diagnostic_status: int = 0):
        source = (ROOT / "tests/vm/reconfigure-system.sh").read_text(encoding="utf-8")
        definitions = source.split('[[ -f "$SOURCE/flake.nix" ]]', 1)[0]
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            calls = root / "calls"
            for name in ("nixos-rebuild", "systemctl", "journalctl", "zfs", "stat", "cat"):
                executable = root / name
                executable.write_text(
                    "#!/usr/bin/env python3\n"
                    "import os, pathlib, sys\n"
                    "name = pathlib.Path(sys.argv[0]).name\n"
                    "with open(os.environ['DIAGNOSTIC_CALLS'], 'a') as handle:\n"
                    "    handle.write(name + ' ' + ' '.join(sys.argv[1:]) + '\\n')\n"
                    "print({'zfs': 'tank/nas@autosnap_live_hourly\\tcreation\\t123\\t-',\n"
                    "       'cat': 'tank/nas@autosnap_cached_daily\\tcreation\\t100\\t-',\n"
                    "       'stat': 'snapshot-cache-mtime=100',\n"
                    "       'journalctl': 'SANOID-JOURNAL',\n"
                    "       'systemctl': 'FAILED-UNITS'}.get(name, 'REBUILD-OUTPUT'))\n"
                    "sys.exit(int(os.environ['REBUILD_STATUS' if name == 'nixos-rebuild' else 'DIAGNOSTIC_STATUS']))\n",
                    encoding="utf-8",
                )
                executable.chmod(0o755)
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    definitions
                    + '\nnas_vm_kill_after_seconds() { echo 1; }\nrebuild switch --flake "path:/reviewed#nas-qemu"\n',
                ],
                env={
                    **os.environ,
                    "PATH": str(root) + os.pathsep + os.environ.get("PATH", ""),
                    "REBUILD_STATUS": str(status),
                    "DIAGNOSTIC_STATUS": str(diagnostic_status),
                    "DIAGNOSTIC_CALLS": str(calls),
                },
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            return result, calls.read_text(encoding="utf-8").splitlines()

    def test_failed_rebuild_captures_live_and_cached_inventory_without_masking_exit(self):
        result, calls = self.rebuild(4)
        self.assertEqual(result.returncode, 4, result.stderr)
        for evidence in (
            "autosnap_live_hourly",
            "autosnap_cached_daily",
            "snapshot-cache-mtime",
            "SANOID-JOURNAL",
            "FAILED-UNITS",
        ):
            self.assertIn(evidence, result.stderr)
        self.assertIn("zfs get -Hrpt snapshot creation", calls)
        self.assertIn("cat /var/cache/sanoid/snapshots.txt", calls)
        self.assertTrue(any("nas-zfs-snapshot-health.service" in call for call in calls))

    def test_diagnostic_failures_do_not_replace_failed_rebuild_status(self):
        result, calls = self.rebuild(124, diagnostic_status=23)
        self.assertEqual(result.returncode, 124, result.stderr)
        self.assertIn("autosnap_live_hourly", result.stderr)
        self.assertIn("autosnap_cached_daily", result.stderr)
        self.assertEqual(len(calls), 6)

    def test_success_does_not_collect_failure_diagnostics(self):
        result, calls = self.rebuild(0)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, ["nixos-rebuild switch --flake path:/reviewed#nas-qemu --option warn-dirty false"])
        self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
