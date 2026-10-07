from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class GuestProxyDiagnosticsTests(unittest.TestCase):
    def exercise(self, *, alive: bool, log_present: bool):
        source = (ROOT / "tests/vm/guest-test.sh").read_text(encoding="utf-8")
        handler = "on_error() {" + source.split("on_error() {", 1)[1].split("trap on_error ERR", 1)[0]
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            log = root / "proxy.log"
            if log_present:
                log.write_text("PROXY-FAILURE-EVIDENCE\n", encoding="utf-8")
            for command in ("systemctl", "journalctl", "zpool", "ss", "curl"):
                path = root / command
                path.write_text(
                    """#!/bin/sh
echo "DIAGNOSTIC-$0 $*" >&2
exit 23
""",
                    encoding="utf-8",
                )
                path.chmod(0o755)
            process = "sleep 30 &" if alive else "(exit 42) &"
            script = (
                handler
                + '\nBROWSER_PORT_FORWARD_LOG="$1"\nPUBLIC_HOST=nas-test.local\nAUTHENTIK_PUBLIC_HOST=nas-test.local:8443\n'
                + process
                + "\nBROWSER_PORT_FORWARD_PID=$!\n"
                + ("trap 'kill \"$BROWSER_PORT_FORWARD_PID\" 2>/dev/null || true' EXIT\n" if alive else "sleep 0.1\n")
                + "(exit 51)\non_error\n"
            )
            result = subprocess.run(
                ["bash", "-c", script, "probe", str(log)],
                env={**os.environ, "PATH": str(root) + os.pathsep + os.environ.get("PATH", "")},
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            return result

    def test_dead_proxy_exit_and_log_survive_failed_diagnostics(self):
        result = self.exercise(alive=False, log_present=True)
        self.assertEqual(result.returncode, 51)
        self.assertIn("browser callback proxy exit status: 42", result.stderr)
        self.assertIn("PROXY-FAILURE-EVIDENCE", result.stderr)
        self.assertIn("DIAGNOSTIC-", result.stderr)
        self.assertIn("https://nas-test.local/identity/", result.stderr)
        self.assertIn("https://nas-test.local:8443/identity/", result.stderr)

    def test_live_proxy_is_not_waited_on_and_missing_log_preserves_failure(self):
        result = self.exercise(alive=True, log_present=False)
        self.assertEqual(result.returncode, 51)
        self.assertIn("browser callback proxy still running", result.stderr)
        self.assertIn("browser callback listener diagnostics", result.stderr)


if __name__ == "__main__":
    unittest.main()
