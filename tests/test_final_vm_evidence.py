from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile
import unittest

from repo_test_utils import ROOT, text


class FinalVmEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = pathlib.Path(self.directory.name)
        self.state = self.root / "cache/state"
        self.state.mkdir(parents=True)
        for name in ("nixos-nas-os.qcow2", "nixos-nas-zfs.qcow2", "installer-admin-ed25519"):
            (self.state / name).write_text("fixture\n", encoding="utf-8")
        self.bin = self.root / "bin"
        self.bin.mkdir()
        commands = {
            "qemu-img": 'touch "${@: -1}"',
            "qemu-system-x86_64": """
printf 'qemu-start\n' >> "$FIXTURE_EVENTS"
while (($#)); do
  case "$1" in
    -serial) printf '%s\n' "$FIXTURE_MARKER" > "${2#file:}" ;;
    -pidfile) if [[ -n "${FIXTURE_CLEANUP_PID:-}" ]]; then echo "$FIXTURE_CLEANUP_PID" > "$2"; fi ;;
  esac
  shift
done
exit "${FIXTURE_BOOT_EXIT:-0}"
""",
            "ssh": """
case "$*" in
  *'-O exit'*) printf 'close-master\n' >> "$FIXTURE_EVENTS" ;;
  *'sudo -n bash -s'*)
    printf 'guest-diagnostics\n' >> "$FIXTURE_EVENTS"
    bash ;;
  *'nas-vm-guest-test --setup-reboot-e2e --verify'*)
    printf 'verify\n' >> "$FIXTURE_EVENTS"
    exit "${FIXTURE_VERIFY_EXIT:-0}" ;;
esac
""",
            "systemctl": """
printf 'systemctl %s\n' "$*"
case "$*" in
  *--failed*) printf 'nas-health-alert@authentik-migrate.service.service failed\n' ;;
  *show*) printf 'Result=exit-code\nExecMainStatus=23\nInvocationID=fixture-invocation\n' ;;
  *) exit 99 ;;
esac
exit "${FIXTURE_DIAGNOSTICS_EXIT:-0}"
""",
            "journalctl": """
printf 'journalctl %s\n' "$*"
printf 'original migration/notifier journal\n'
exit "${FIXTURE_DIAGNOSTICS_EXIT:-0}"
""",
            "timeout": """
printf 'timeout %s\n' "$*" >> "$FIXTURE_EVENTS"
[[ "${FIXTURE_DIAGNOSTICS_EXIT:-0}" != 124 ]] || exit 124
shift 4
exec "$@"
""",
            "curl": ":",
            "npm": """
output="$FIXTURE_ROOT/unscoped-results"
while (($#)); do
  if [[ "$1" == --output ]]; then output=$2; shift; fi
  shift
done
report=${PLAYWRIGHT_HTML_OUTPUT_DIR:-$FIXTURE_ROOT/unscoped-report}
mkdir -p "$output/failed-attempt" "$report"
printf '%s\n' "$FIXTURE_MARKER" > "$output/failed-attempt/error-context.md"
printf '%s\n' "$FIXTURE_MARKER" > "$report/index.html"
printf 'browser\n' >> "$FIXTURE_EVENTS"
if [[ "${FIXTURE_SIGNAL:-}" == TERM ]]; then kill -TERM "$PPID"; fi
exit "${FIXTURE_WORKLOAD_EXIT:-0}"
""",
        }
        for name, body in commands.items():
            path = self.bin / name
            path.write_text("#!/usr/bin/env bash\nset -euo pipefail\n" + body + "\n", encoding="utf-8")
            path.chmod(0o755)

    def run_workload(self, *, script: pathlib.Path | None = None, **overrides: str) -> subprocess.CompletedProcess[str]:
        env = {key: value for key, value in os.environ.items() if not key.startswith(("NAS_", "PLAYWRIGHT_"))}
        return subprocess.run(
            ["bash", str(script or ROOT / "scripts/qemu-final-browser.sh")],
            cwd=self.root,
            env={
                **env,
                "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
                "NAS_QEMU_CACHE_DIR": str(self.state.parent),
                "NAS_FINAL_VM_EVIDENCE_DIR": str(self.root / "evidence"),
                "FIXTURE_ROOT": str(self.root),
                "FIXTURE_EVENTS": str(self.root / "events"),
                "FIXTURE_MARKER": "initial-install",
                **overrides,
            },
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    def evidence(self) -> list[pathlib.Path]:
        return sorted((self.root / "evidence").glob("deterministic-browser.*"))

    def test_each_invocation_retains_its_retry_artifacts_and_console_outside_the_checkout(self) -> None:
        for marker in ("initial-install", "package-upgrade"):
            with self.subTest(marker=marker):
                result = self.run_workload(FIXTURE_MARKER=marker)
                self.assertEqual(result.returncode, 0, result.stderr)
        evidence = self.evidence()
        self.assertEqual(len(evidence), 2, "later Playwright runs must not replace first-run or retry evidence")
        markers = set()
        for path in evidence:
            self.assertEqual(path.stat().st_mode & 0o777, 0o700)
            marker = (path / "browser-console.log").read_text().strip()
            markers.add(marker)
            for relative in ("test-results/failed-attempt/error-context.md", "playwright-report/index.html"):
                self.assertEqual((path / relative).read_text().strip(), marker)
                self.assertEqual((path / relative).stat().st_mode & 0o077, 0)
        self.assertEqual(markers, {"initial-install", "package-upgrade"})
        self.assertFalse((self.root / "unscoped-results").exists())
        self.assertFalse((self.state / "browser-console.log").exists())

    def test_diagnostics_run_before_cleanup_and_never_replace_the_workload_exit(self) -> None:
        for workload, diagnostics in ((0, 0), (73, 0), (73, 23), (0, 23), (73, 124)):
            with self.subTest(workload=workload, diagnostics=diagnostics):
                before = set(self.evidence())
                result = self.run_workload(
                    FIXTURE_WORKLOAD_EXIT=str(workload), FIXTURE_DIAGNOSTICS_EXIT=str(diagnostics)
                )
                self.assertEqual(result.returncode, workload, result.stderr)
                created = set(self.evidence()) - before
                self.assertEqual(len(created), 1, "each exit needs invocation-bound evidence")
                path = created.pop()
                status = dict(line.split("\t") for line in (path / "result.tsv").read_text().splitlines())
                self.assertEqual(status["workload"], "deterministic-browser")
                self.assertEqual(status["workloadExit"], str(workload))
                self.assertEqual(status["guestDiagnosticsExit"], str(diagnostics))
                self.assertEqual(status["cleanupExit"], "0")
                log = (path / "guest-diagnostics.log").read_text()
                if diagnostics != 124:
                    self.assertIn("nas-health-alert@authentik-migrate.service.service failed", log)
                    self.assertIn("original migration/notifier journal", log)
                    self.assertIn("InvocationID=fixture-invocation", log)
                    self.assertIn("-b", log)
                events = (self.root / "events").read_text().splitlines()
                self.assertIn("--kill-after=5s 30s", "\n".join(events))
                if diagnostics != 124:
                    self.assertLess(len(events) - 1 - events[::-1].index("guest-diagnostics"), len(events) - 1)
                self.assertEqual(events[-1], "close-master")
                self.assertEqual(events.count("verify"), len(self.evidence()))

    def test_activation_failure_still_collects_diagnostics_without_running_the_browser(self) -> None:
        result = self.run_workload(FIXTURE_VERIFY_EXIT="71")
        self.assertEqual(result.returncode, 71, result.stderr)
        paths = self.evidence()
        self.assertEqual(len(paths), 1)
        self.assertIn("original migration/notifier journal", (paths[0] / "guest-diagnostics.log").read_text())
        self.assertNotIn("browser", (self.root / "events").read_text().splitlines())

    def test_boot_failure_records_unavailable_diagnostics_without_trying_guest_ssh(self) -> None:
        result = self.run_workload(FIXTURE_BOOT_EXIT="72")
        self.assertEqual(result.returncode, 72, result.stderr)
        paths = self.evidence()
        self.assertEqual(len(paths), 1)
        self.assertIn("guestDiagnosticsExit\t125\n", (paths[0] / "result.tsv").read_text())
        self.assertNotIn("guest-diagnostics", (self.root / "events").read_text().splitlines())

    def test_default_evidence_root_is_private_and_outside_the_checkout(self) -> None:
        result = self.run_workload(NAS_FINAL_VM_EVIDENCE_DIR="")
        self.assertEqual(result.returncode, 0, result.stderr)
        paths = list((self.state.parent / "evidence").glob("deterministic-browser.*"))
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0].stat().st_mode & 0o777, 0o700)
        self.assertTrue((paths[0] / "result.tsv").is_file())

    def test_termination_is_recorded_as_failure_even_when_the_child_exits_zero(self) -> None:
        result = self.run_workload(FIXTURE_SIGNAL="TERM")
        self.assertEqual(result.returncode, 143, result.stderr)
        paths = self.evidence()
        self.assertEqual(len(paths), 1)
        self.assertIn("workloadExit\t143\n", (paths[0] / "result.tsv").read_text())

    def test_cleanup_refusal_is_fatal_but_preserves_an_existing_failure(self) -> None:
        for workload in (0, 73):
            with self.subTest(workload=workload):
                (self.state / "browser-qemu.pid").unlink(missing_ok=True)
                result = self.run_workload(FIXTURE_CLEANUP_PID=str(os.getpid()), FIXTURE_WORKLOAD_EXIT=str(workload))
                self.assertEqual(result.returncode, workload or 1, result.stderr)
                self.assertIn("refusing to signal", result.stderr)

    def test_preboot_cleanup_refusal_retains_its_original_exit(self) -> None:
        pidfile = self.state / "browser-qemu.pid"
        pidfile.write_text(str(os.getpid()), encoding="utf-8")
        result = self.run_workload()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("refusing to signal", result.stderr)
        paths = self.evidence()
        self.assertEqual(len(paths), 1)
        self.assertTrue((paths[0] / "result.tsv").is_file(), "preboot cleanup failure needs exit evidence")
        status = dict(line.split("\t") for line in (paths[0] / "result.tsv").read_text().splitlines())
        self.assertEqual(status["workloadExit"], "1")
        self.assertEqual(status["guestDiagnosticsExit"], "125")
        self.assertEqual(status["cleanupExit"], "1")
        self.assertFalse((self.root / "events").exists())
        self.assertEqual(pidfile.read_text(), str(os.getpid()))

    def test_evidence_path_resolves_outside_the_checkout_before_creating_any_files(self) -> None:
        link = self.root / "inside-link"
        link.symlink_to(ROOT, target_is_directory=True)
        for path in (ROOT / "forbidden-evidence", link / "forbidden-evidence"):
            with self.subTest(path=path):
                result = self.run_workload(NAS_FINAL_VM_EVIDENCE_DIR=str(path))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("evidence path must be outside the checkout", result.stderr)
                self.assertFalse((self.root / "events").exists())
                self.assertFalse((ROOT / "forbidden-evidence").exists())

    def test_symlinked_checkout_cannot_bypass_external_evidence_path_validation(self) -> None:
        checkout = self.root / "checkout"
        (checkout / "scripts/lib").mkdir(parents=True)
        for relative in ("scripts/qemu-final-browser.sh", "scripts/lib/nas-qemu-process.sh"):
            (checkout / relative).write_text(text(relative), encoding="utf-8")
        link = self.root / "checkout-link"
        link.symlink_to(checkout, target_is_directory=True)
        result = self.run_workload(
            script=link / "scripts/qemu-final-browser.sh",
            NAS_FINAL_VM_EVIDENCE_DIR=str(checkout / "forbidden-evidence"),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("evidence path must be outside the checkout", result.stderr)
        self.assertFalse((checkout / "forbidden-evidence").exists())

    def test_diagnostics_only_read_native_state_and_never_reset_or_restart_units(self) -> None:
        source = text("scripts/qemu-final-browser.sh")
        self.assertIn("GUEST_DIAGNOSTICS", source)
        script = source.split("<<'GUEST_DIAGNOSTICS'", 1)[1].split("\nGUEST_DIAGNOSTICS", 1)[0]
        for expected in ("systemctl --failed", "systemctl show", "journalctl -b", "InvocationID", "authentik-migrate"):
            self.assertIn(expected, script)
        for forbidden in ("reset-failed", " restart ", " start ", "Environment", "ExecStart=", "/run/nas-secret"):
            self.assertNotIn(forbidden, script)


if __name__ == "__main__":
    unittest.main()
