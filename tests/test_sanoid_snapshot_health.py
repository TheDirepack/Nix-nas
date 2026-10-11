from __future__ import annotations

import os
import pathlib
import re
import shlex
import shutil
import subprocess
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SANOID = os.environ.get("SANOID_BIN") or shutil.which("sanoid")
DEFAULTS = pathlib.Path(os.environ.get("SANOID_DEFAULTS", "/etc/sanoid/sanoid.defaults.conf"))


def snapshot_health_arguments() -> list[str]:
    source = (ROOT / "modules/nas/config/systemd-services.nix").read_text(encoding="utf-8")
    match = re.search(r'ExecStart = "\$\{pkgs.sanoid\}/bin/sanoid (--monitor-snapshots[^"\n]+)";', source)
    if match is None:
        raise AssertionError("native snapshot-health command is unavailable")
    return shlex.split(match.group(1).replace("${sanoidMonitorConfig}", "CONFIG"))


class SanoidSnapshotHealthTests(unittest.TestCase):
    def test_native_snapshot_health_requires_live_inventory(self):
        self.assertEqual(
            snapshot_health_arguments(), ["--monitor-snapshots", "--force-update", "--configdir", "CONFIG"]
        )

    def run_monitor(self, *, cached: bool, live: bool) -> subprocess.CompletedProcess[str]:
        assert SANOID is not None
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            config = root / "config"
            cache = root / "cache"
            binaries = root / "bin"
            for directory in (config, cache, binaries):
                directory.mkdir()
            shutil.copyfile(DEFAULTS, config / "sanoid.defaults.conf")
            (config / "sanoid.conf").write_text(
                "[tank/nas]\nmonitor = yes\nrecursive = no\nhourly = 24\n"
                "daily = 0\nweekly = 0\nmonthly = 0\nyearly = 0\nfrequently = 0\n",
                encoding="utf-8",
            )
            row = f"tank/nas@autosnap_fixture_hourly\tcreation\t{int(time.time())}\t-\n"
            (cache / "snapshots.txt").write_text(row if cached else "", encoding="utf-8")
            live_inventory = root / "live-snapshots"
            live_inventory.write_text(row if live else "", encoding="utf-8")
            calls = root / "zfs-calls"
            zfs = binaries / "zfs"
            zfs.write_text(
                "#!/bin/sh\n"
                f"printf '%s\\n' \"$*\" >> {shlex.quote(str(calls))}\n"
                'test "$*" = "get -Hrpt snapshot creation" || exit 9\n'
                f"exec cat {shlex.quote(str(live_inventory))}\n",
                encoding="utf-8",
            )
            zfs.chmod(0o755)
            arguments = [str(config) if item == "CONFIG" else item for item in snapshot_health_arguments()]
            result = subprocess.run(
                [SANOID, *arguments, "--cache-dir", str(cache), "--run-dir", str(root / "run")],
                env={**os.environ, "PATH": str(binaries) + os.pathsep + os.environ.get("PATH", "")},
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertTrue(calls.exists(), "snapshot health relied on its cache without querying ZFS")
            self.assertEqual(calls.read_text(encoding="utf-8"), "get -Hrpt snapshot creation\n")
            return result

    @unittest.skipUnless(SANOID and DEFAULTS.is_file(), "Sanoid executable and defaults are unavailable")
    def test_stale_missing_snapshot_cache_does_not_create_false_alarm(self):
        result = self.run_monitor(cached=False, live=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(SANOID and DEFAULTS.is_file(), "Sanoid executable and defaults are unavailable")
    def test_stale_fresh_snapshot_cache_does_not_hide_missing_snapshots(self):
        result = self.run_monitor(cached=True, live=False)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("has no hourly snapshots", result.stdout)


if __name__ == "__main__":
    unittest.main()
