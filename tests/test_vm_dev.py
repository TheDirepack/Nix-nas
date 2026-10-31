from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class VmDevTests(unittest.TestCase):
    def run_fixture(
        self,
        *,
        codes: tuple[str, ...] = ("302",),
        curl_status: int = 0,
        service_ready_after: int = 1,
        start_status: int = 0,
        cache: bool = False,
        state: bool = False,
        xdg: bool = True,
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, list]]:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            scripts = root / "repo/scripts"
            scripts.mkdir(parents=True)
            for name in ("vm-dev.sh", "vm-run.sh"):
                shutil.copy2(ROOT / "scripts" / name, scripts / name)
            bindir = root / "bin"
            bindir.mkdir()
            logdir = root / "logs"
            logdir.mkdir()
            env = {
                key: value
                for key, value in os.environ.items()
                if not key.startswith("NAS_QEMU_") and key not in {"HOME", "XDG_CACHE_HOME", "BASH_ENV", "ENV"}
            }
            env.update(
                HOME=str(root / "home"),
                PATH=str(bindir) + os.pathsep + os.environ["PATH"],
                FIXTURE_LOGS=str(logdir),
                FIXTURE_CODES=json.dumps(codes),
                FIXTURE_CURL_STATUS=str(curl_status),
                FIXTURE_SERVICE_READY_AFTER=str(service_ready_after),
                FIXTURE_START_STATUS=str(start_status),
                NAS_QEMU_SSH_PORT="2288",
                NAS_QEMU_HTTPS_PORT="8844",
            )
            default_cache = root / "home/.cache/nixos-nas-qemu"
            if xdg:
                env["XDG_CACHE_HOME"] = str(root / "xdg cache")
                default_cache = root / "xdg cache/nixos-nas-qemu"
            if cache:
                env["NAS_QEMU_CACHE_DIR"] = str(root / "custom cache")
            cache_dir = pathlib.Path(env.get("NAS_QEMU_CACHE_DIR", str(default_cache)))
            if state:
                env["NAS_QEMU_STATE_DIR"] = str(root / "explicit state")
            state_dir = pathlib.Path(env.get("NAS_QEMU_STATE_DIR", str(cache_dir / "state")))
            state_dir.mkdir(parents=True)
            key = state_dir / "installer-admin-ed25519"
            key.write_text("synthetic-fixture-key\n")
            env["FIXTURE_EXPECTED_KEY"] = str(key)
            stub = (
                f"#!{sys.executable}\n"
                + """import json
import os
import pathlib
import sys

name = pathlib.Path(sys.argv[0]).name
if name == "vm-start.sh":
    name = "start"
log = pathlib.Path(os.environ["FIXTURE_LOGS"]) / (name + ".jsonl")
with log.open("a") as stream:
    stream.write(json.dumps(sys.argv[1:]) + "\\n")
attempt = len(log.read_text().splitlines())
if name == "start":
    sys.exit(int(os.environ["FIXTURE_START_STATUS"]))
if name == "ssh":
    args = sys.argv[1:]
    if "-i" not in args or args[args.index("-i") + 1] != os.environ["FIXTURE_EXPECTED_KEY"]:
        sys.exit(255)
    ready_after = int(os.environ["FIXTURE_SERVICE_READY_AFTER"])
    if ready_after and attempt >= ready_after:
        print("active\\nactive\\nactive\\nactive")
    else:
        print("inactive\\ninactive\\ninactive\\ninactive")
        sys.exit(3)
if name == "curl":
    codes = json.loads(os.environ["FIXTURE_CODES"])
    print(codes[min(attempt - 1, len(codes) - 1)], end="")
    sys.exit(int(os.environ["FIXTURE_CURL_STATUS"]))
"""
            )
            for program in (scripts / "vm-start.sh", *(bindir / name for name in ("ssh", "curl", "sleep"))):
                program.write_text(stub)
                program.chmod(0o700)
            result = subprocess.run(
                ["bash", str(scripts / "vm-dev.sh")],
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            calls = {
                name: [json.loads(line) for line in (logdir / f"{name}.jsonl").read_text().splitlines()]
                if (logdir / f"{name}.jsonl").exists()
                else []
                for name in ("start", "ssh", "curl", "sleep")
            }
            return result, calls

    def test_console_exhaustion_is_fatal_without_a_ready_banner(self) -> None:
        result, calls = self.run_fixture(codes=("503",))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertNotIn("VM ready", result.stdout)
        self.assertIn("Console", result.stderr)
        self.assertEqual(len(calls["curl"]), 30)
        self.assertEqual(calls["sleep"], [["2"]] * 30)

    def test_console_transport_failures_are_fatal(self) -> None:
        result, calls = self.run_fixture(codes=("000",), curl_status=7)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertNotIn("VM ready", result.stdout)
        self.assertEqual(len(calls["curl"]), 30)

    def test_accepted_console_codes_stop_probing_and_publish_the_configured_urls(self) -> None:
        for code in ("200", "302"):
            with self.subTest(code=code):
                result, calls = self.run_fixture(codes=(code,))
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("VM ready", result.stdout)
                self.assertIn("https://nas-test.local:8844/console/", result.stdout)
                self.assertEqual(len(calls["curl"]), 1)
                self.assertIn("nas-test.local:8844:127.0.0.1", calls["curl"][0])
                self.assertEqual(calls["sleep"], [])

    def test_console_may_become_ready_on_the_last_existing_attempt(self) -> None:
        result, calls = self.run_fixture(codes=("503",) * 29 + ("302",))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("VM ready", result.stdout)
        self.assertEqual(len(calls["curl"]), 30)
        self.assertEqual(calls["sleep"], [["2"]] * 29)

    def test_service_exhaustion_remains_fatal_before_console_probes(self) -> None:
        result, calls = self.run_fixture(service_ready_after=0)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertNotIn("VM ready", result.stdout)
        self.assertIn("Services did not become active", result.stderr)
        self.assertEqual(len(calls["ssh"]), 90)
        self.assertEqual(calls["sleep"], [["3"]] * 90)
        self.assertEqual(calls["curl"], [])

    def test_start_failure_is_preserved_without_probing(self) -> None:
        result, calls = self.run_fixture(start_status=73)
        self.assertEqual(result.returncode, 73, result.stdout + result.stderr)
        self.assertEqual(calls["start"], [[]])
        self.assertEqual(calls["ssh"], [])
        self.assertEqual(calls["curl"], [])
        self.assertNotIn("VM ready", result.stdout)

    def test_custom_cache_selects_the_same_key_as_vm_run(self) -> None:
        result, calls = self.run_fixture(cache=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(calls["ssh"]), 1)

    def test_state_override_and_default_cache_precedence_are_preserved(self) -> None:
        for cache, state, xdg in ((False, True, True), (True, True, True), (False, False, True), (False, False, False)):
            with self.subTest(cache=cache, state=state, xdg=xdg):
                result, calls = self.run_fixture(cache=cache, state=state, xdg=xdg)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(len(calls["ssh"]), 1)

    def test_readiness_ssh_uses_the_existing_noninteractive_policy(self) -> None:
        result, calls = self.run_fixture()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        args = calls["ssh"][0]
        for option in ("IdentitiesOnly=yes", "PasswordAuthentication=no", "KbdInteractiveAuthentication=no"):
            self.assertIn(option, args)
        self.assertEqual(args[args.index("-p") + 1], "2288")
        self.assertIn("admin@127.0.0.1", args)
        self.assertEqual(args[-1], "systemctl is-active caddy authentik nas-cockpit-sso nas-authentik-proxy-outpost")
