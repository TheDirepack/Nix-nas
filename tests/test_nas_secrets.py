"""Black-box tests of `nas-secrets` (zig/src/nas_secrets.zig).

The harness build relocates every configured path under NAS_SECRETS_TEST_ROOT.
Fakes stand in for keepassxc-cli (a JSON "database" that saves by replacing
the file, like KeePassXC), sudo (drops -o/-g so an unprivileged user can run
it), systemctl, curl and the operation coordinator. Every fake records its
argv so the tests can assert that no secret ever reaches a command line.
"""

from __future__ import annotations

import json
import os
import pathlib
import signal
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from zig_binaries import harness_bin_dir, release_bin_dir  # noqa: E402

PASSWORD = "correct horse battery staple"
DATABASE = "/var/lib/nas-control-plane/nas-secrets/NAS.kdbx"
SECRET_ROOT = "/run/nas-secrets"
BOOT_DIR = "/var/lib/nas-control-plane/bootstrap/authentik"

FAKE_KEEPASS = textwrap.dedent(
    """\
    #!/usr/bin/env python3
    import json, os, sys, tempfile
    with open(os.environ["FAKE_ARGV_LOG"], "a") as log:
        log.write(json.dumps(["keepassxc-cli", *sys.argv[1:]]) + "\\n")
    args = sys.argv[1:]
    cmd, rest = args[0], args[1:]
    positional, flags, i = [], set(), 0
    while i < len(rest):
        a = rest[i]
        if a in ("-a", "--key-file"):
            i += 2
            continue
        if a.startswith("-"):
            flags.add(a)
        else:
            positional.append(a)
        i += 1
    db = positional[0]
    password = sys.stdin.readline().rstrip("\\n")
    with open(db) as f:
        data = json.load(f)
    if password != data["password"]:
        print("Error while reading the database: Invalid credentials were provided", file=sys.stderr)
        sys.exit(1)
    def save():
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(db))
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
        os.chmod(tmp, 0o644)
        os.replace(tmp, db)
    if cmd == "db-info":
        sys.exit(0)
    if cmd == "ls":
        if "--flatten" in flags and os.environ.get("FAKE_KP_LS_FAIL") == "1":
            sys.exit(7)
        group = positional[1]
        if group not in data["groups"]:
            sys.exit(1)
        if "--flatten" in flags:
            for path in sorted(data["entries"]):
                if path.startswith(group + "/"):
                    print(path[len(group) + 1:])
        sys.exit(0)
    if cmd == "mkdir":
        if os.environ.get("FAKE_KP_MKDIR_FAIL") == "1":
            sys.exit(2)
        data["groups"].append(positional[1]); save(); sys.exit(0)
    if cmd == "show":
        path = positional[1]
        if path not in data["entries"]:
            print("Could not find entry", file=sys.stderr); sys.exit(1)
        print(data["entries"][path]); sys.exit(0)
    if cmd in ("add", "edit"):
        value = sys.stdin.readline().rstrip("\\n")
        data["entries"][positional[1]] = value; save(); sys.exit(0)
    if cmd == "rm":
        data["entries"].pop(positional[1], None); save(); sys.exit(0)
    sys.exit(2)
    """
)

FAKE_SUDO = textwrap.dedent(
    """\
    #!/usr/bin/env python3
    import json, os, sys
    with open(os.environ["FAKE_ARGV_LOG"], "a") as log:
        log.write(json.dumps(["sudo", *sys.argv[1:]]) + "\\n")
    args = sys.argv[1:]
    if args == ["-v"]:
        sys.exit(0)
    if args[:1] == ["--"]:
        args = args[1:]
    if os.path.basename(args[0]) == "install":
        out, skip = [], False
        for a in args:
            if skip:
                skip = False
                continue
            if a in ("-o", "-g"):
                skip = True
                continue
            out.append(a)
        args = out
    if os.path.basename(args[0]) == "chown":
        sys.exit(0)
    os.execvp(args[0], args)
    """
)

FAKE_SYSTEMCTL = textwrap.dedent(
    """\
    #!/usr/bin/env python3
    import json, os, sys
    with open(os.environ["FAKE_ARGV_LOG"], "a") as log:
        log.write(json.dumps(["systemctl", *sys.argv[1:]]) + "\\n")
    marker = os.environ["FAKE_TARGET_ACTIVE"]
    args = sys.argv[1:]
    cmd = args[0]
    target = "nas-protected-services.target"
    failing = os.environ.get("FAKE_SYSTEMCTL_FAIL", "").split()
    if cmd == "show":
        print("LoadState=loaded")
        print("ActiveState=" + ("active" if os.path.exists(marker) else "inactive"))
        print("Job=")
    elif cmd == "stop":
        if target in args and os.path.exists(marker):
            os.unlink(marker)
    elif cmd == "start":
        if any(unit in failing for unit in args):
            sys.exit(1)
        if target in args:
            open(marker, "w").close()
    elif cmd == "is-failed":
        sys.exit(1)
    sys.exit(0)
    """
)

FAKE_CURL = textwrap.dedent(
    """\
    #!/usr/bin/env python3
    import json, os, sys, time
    with open(os.environ["FAKE_ARGV_LOG"], "a") as log:
        log.write(json.dumps(["curl", *sys.argv[1:]]) + "\\n")
    mode = os.environ.get("FAKE_CURL_MODE", "ok")
    if mode == "sleep":
        time.sleep(3)
    sys.exit(7 if mode == "fail" else 0)
    """
)

FAKE_RUNNER = textwrap.dedent(
    """\
    #!/usr/bin/env python3
    import json, os, sys
    with open(os.environ["FAKE_ARGV_LOG"], "a") as log:
        log.write(json.dumps(["nas-operation-run", *sys.argv[1:]]) + "\\n")
    args = sys.argv[1:]
    if "--validate-current" in args:
        sys.exit(0)
    child = args[args.index("--") + 1:]
    os.environ["NAS_OPERATION_COORDINATION_TOKEN"] = "test-token"
    os.execv(child[0], child)
    """
)


class Appliance:
    def __init__(self, work: pathlib.Path) -> None:
        self.work = work
        self.fsroot = work / "fs"
        self.bin = work / "bin"
        self.bin.mkdir()
        self.argv_log = work / "argv.log"
        for name, body in (
            ("keepassxc-cli", FAKE_KEEPASS),
            ("sudo", FAKE_SUDO),
            ("systemctl", FAKE_SYSTEMCTL),
            ("curl", FAKE_CURL),
            ("nas-operation-run", FAKE_RUNNER),
        ):
            path = self.bin / name
            path.write_text(body, encoding="utf-8")
            path.chmod(0o755)
        for directory in (
            "run/lock",
            "run/nas-authentik",
            "run/nas-control",
            "var/lib/nas-setup",
            BOOT_DIR.lstrip("/"),
        ):
            (self.fsroot / directory).mkdir(parents=True, exist_ok=True)
        self.db = self.path(DATABASE)
        self.db.parent.mkdir(parents=True)
        self.db.write_text(json.dumps({"password": PASSWORD, "groups": [], "entries": {}}), encoding="utf-8")
        self.db.chmod(0o600)
        self.target_marker = work / "target-active"
        self.target_marker.touch()
        self.env = {
            "PATH": f"{self.bin}:{os.environ.get('PATH', '')}",
            "HOME": str(work),
            "NAS_SECRETS_TEST_ROOT": str(self.fsroot),
            "NAS_OPERATION_RUNNER": str(self.bin / "nas-operation-run"),
            "FAKE_ARGV_LOG": str(self.argv_log),
            "FAKE_TARGET_ACTIVE": str(self.target_marker),
        }

    def path(self, absolute: str) -> pathlib.Path:
        return self.fsroot / absolute.lstrip("/")

    def entries(self) -> dict[str, str]:
        return json.loads(self.db.read_text(encoding="utf-8"))["entries"]

    def argv(self) -> list[list[str]]:
        if not self.argv_log.exists():
            return []
        return [json.loads(line) for line in self.argv_log.read_text(encoding="utf-8").splitlines()]

    def calls(self, program: str) -> list[list[str]]:
        return [entry[1:] for entry in self.argv() if entry[0] == program]

    def run(
        self,
        *args: str,
        stdin: str = PASSWORD + "\n",
        env: dict[str, str] | None = None,
        binary: pathlib.Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(binary or harness_bin_dir() / "nas-secrets"), *args],
            input=stdin,
            env={**self.env, **(env or {})},
            text=True,
            capture_output=True,
            timeout=120,
            check=False,
        )

    def initialise(self) -> None:
        result = self.run("init")
        assert result.returncode == 0, result.stderr


class NasSecretsTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.nas = Appliance(pathlib.Path(temporary.name))

    def assert_no_secret_in_argv(self) -> None:
        secrets = {PASSWORD, *self.nas.entries().values()}
        for entry in self.nas.argv():
            for argument in entry:
                for value in secrets:
                    self.assertNotIn(value, argument, f"secret material in argv: {entry[0]}")

    # ------------------------------------------------------------ init/coordinator

    def test_init_creates_every_enabled_entry_and_runs_under_the_coordinator(self) -> None:
        result = self.nas.run("init")
        self.assertEqual(result.returncode, 0, result.stderr)
        entries = self.nas.entries()
        for key in (
            "authentik-secret-key",
            "authentik-bootstrap-token",
            "authentik-api-token",
            "authentik-bootstrap-password",
            "state-bundle-signing-key",
            "grafana-secret-key",
            "ntfy-admin-password",
            "ntfy-alert-topic",
            "nut-webgui-server-key",
            "zfs-dataset-key",
            "vaultwarden-oidc-client-secret",
            "vaultwarden-admin",
        ):
            self.assertIn(f"NAS/{key}", entries)
        self.assertEqual(len(entries["NAS/authentik-secret-key"]), 128)
        self.assertEqual(entries["NAS/authentik-api-token"], entries["NAS/authentik-bootstrap-token"])
        runner = self.nas.calls("nas-operation-run")
        self.assertEqual(runner[0][:3], ["--action", "nas-secrets:init", "--class"])
        self.assertEqual(runner[1], ["--validate-current", "--class", "secrets", "--class", "runtime"])
        second = self.nas.run("init")
        self.assertIn("KeePassXC item already exists: Authentik secret key", second.stdout)
        self.assert_no_secret_in_argv()

    def test_missing_coordinator_refuses_mutations(self) -> None:
        result = self.nas.run("activate-stdin", env={"NAS_OPERATION_RUNNER": str(self.nas.work / "missing")})
        self.assertEqual(result.returncode, 1)
        self.assertIn("NAS operation coordinator is unavailable", result.stderr)

    def test_usage(self) -> None:
        result = self.nas.run("bogus")
        self.assertEqual(result.returncode, 2)
        self.assertIn("Usage: nas-secrets {init|", result.stderr)

    # ------------------------------------------------------------- password line

    def test_password_line_is_bounded_and_nonempty(self) -> None:
        self.nas.initialise()
        cases = (
            ("\n", "cannot be empty"),
            ("x" * 4097 + "\n", "exceeds 4096 characters"),
            (PASSWORD, "Unable to read the KeePass database password from standard input."),
            ("wrong password\n", "Unable to unlock the KeePassXC database."),
        )
        for stdin, message in cases:
            with self.subTest(message=message):
                result = self.nas.run("activate-stdin", stdin=stdin)
                self.assertEqual(result.returncode, 1)
                self.assertIn(message, result.stderr)
        self.assertFalse(self.nas.path(SECRET_ROOT).exists())
        self.assertEqual(self.nas.calls("systemctl"), [])

    def test_missing_database_is_reported(self) -> None:
        self.nas.db.unlink()
        result = self.nas.run("activate-stdin")
        self.assertEqual(result.returncode, 1)
        self.assertIn("KeePassXC database not found", result.stderr)

    def test_concurrent_operations_are_refused(self) -> None:
        self.nas.initialise()
        import fcntl

        lock_path = self.nas.path("/run/lock/nas-secrets.lock")
        with open(lock_path, "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            result = self.nas.run("activate-stdin")
        self.assertEqual(result.returncode, 1)
        self.assertIn("Another NAS secret operation is already running.", result.stderr)

    # ------------------------------------------------------------------ activate

    def test_runtime_activation_stages_private_files_and_starts_services(self) -> None:
        self.nas.initialise()
        result = self.nas.run("activate-stdin")
        self.assertEqual(result.returncode, 0, result.stderr)
        root = self.nas.path(SECRET_ROOT)
        entries = self.nas.entries()
        environment = (root / "authentik/environment").read_text()
        self.assertIn(f"AUTHENTIK_SECRET_KEY={entries['NAS/authentik-secret-key']}\n", environment)
        self.assertIn("AUTHENTIK_BOOTSTRAP_EMAIL='admin@example.invalid'", environment)
        self.assertEqual((root / "authentik/api-token").read_text(), entries["NAS/authentik-api-token"])
        self.assertTrue((root / "authentik-token-warning").is_file())
        self.assertIn("WARNING: Authentik runtime API token is still the bootstrap token.", result.stderr)
        vaultwarden = (root / "vaultwarden/environment").read_text()
        self.assertRegex(vaultwarden, r"^ADMIN_TOKEN='\$argon2id\$v=19\$m=65536,t=3,p=4\$[^']+'\n")
        self.assertNotIn(entries["NAS/vaultwarden-admin"], vaultwarden)
        self.assertIn(f"SSO_CLIENT_SECRET='{entries['NAS/vaultwarden-oidc-client-secret']}'", vaultwarden)
        ntfy = (root / "observability/ntfy-environment").read_text()
        self.assertRegex(ntfy, r"^NTFY_AUTH_USERS=admin:\$2b\$12\$[./A-Za-z0-9]{53}:admin\n")
        self.assertEqual((root / "zfs/dataset-key").read_text(), entries["NAS/zfs-dataset-key"])
        for path in root.rglob("*"):
            if path.is_file():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400, path)
        self.assertTrue((root / "ready").is_file())
        units = [call for call in self.nas.calls("systemctl") if call[0] in ("start", "try-restart")]
        self.assertIn(["try-restart", "authentik-worker.service", "authentik.service"], units)
        self.assertIn(["start", "nas-protected-services.target"], units)
        self.assertEqual(units[-1], ["start", "nas-authentik-proxy-outpost.service"])
        self.assertFalse(list(self.nas.path("/run/nas-secret-runtime/transactions").iterdir()))
        self.assertFalse(list(self.nas.path(f"/run/nas-secret-runtime/staging/{os.getuid()}").iterdir()))
        for call in self.nas.calls("sudo"):
            self.assertNotIn("keepassxc-cli", call[0])
        self.assert_no_secret_in_argv()

    def test_failed_readiness_rolls_back_to_the_previous_tree(self) -> None:
        self.nas.initialise()
        previous = self.nas.path(SECRET_ROOT)
        previous.mkdir(parents=True)
        (previous / "ready").touch()
        (previous / "old").write_text("previous generation")
        result = self.nas.run("activate-stdin", env={"FAKE_CURL_MODE": "fail"})
        self.assertEqual(result.returncode, 73, result.stderr)
        self.assertIn("readiness probe failed", result.stderr)
        self.assertEqual((previous / "old").read_text(), "previous generation")
        self.assertFalse((previous / "authentik").exists())
        self.assertTrue(self.nas.target_marker.exists(), "the previously active target is restarted")
        self.assertFalse(list(self.nas.path("/run/nas-secret-runtime/transactions").iterdir()))

    def test_termination_after_swap_restores_the_prior_tree(self) -> None:
        self.nas.initialise()
        previous = self.nas.path(SECRET_ROOT)
        previous.mkdir(parents=True)
        (previous / "ready").touch()
        (previous / "old").write_text("previous generation")
        process = subprocess.Popen(
            [str(harness_bin_dir() / "nas-secrets"), "activate-stdin"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**self.nas.env, "FAKE_CURL_MODE": "sleep"},
            text=True,
        )
        assert process.stdin is not None
        process.stdin.write(PASSWORD + "\n")
        process.stdin.close()
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and not self.nas.calls("curl"):
            time.sleep(0.05)
        process.send_signal(signal.SIGTERM)
        _, stderr = process.communicate(timeout=60)
        self.assertEqual(process.returncode, 143, stderr)
        self.assertEqual((previous / "old").read_text(), "previous generation")
        self.assertFalse((previous / "authentik").exists())

    def test_malformed_v2_state_is_refused_before_the_swap(self) -> None:
        self.nas.initialise()
        self.nas.path("/run/nas-control/systemd-reconciled.json").write_text(
            '{"schemaVersion": 1, "startUnits": ["--bad"]}'
        )
        result = self.nas.run("activate-stdin")
        self.assertEqual(result.returncode, 70)
        self.assertIn("invalid V2 unit name", result.stderr)
        self.assertFalse(self.nas.path(SECRET_ROOT).exists())
        self.assertNotIn(["stop", "nas-protected-services.target"], self.nas.calls("systemctl"))

    def test_v2_units_are_restarted_after_the_target(self) -> None:
        self.nas.initialise()
        self.nas.path("/run/nas-control/systemd-reconciled.json").write_text(
            '{"schemaVersion": 1, "startUnits": ["nas-v2-app-demo.service"]}'
        )
        result = self.nas.run("activate-stdin")
        self.assertEqual(result.returncode, 0, result.stderr)
        starts = [call for call in self.nas.calls("systemctl") if call[0] == "start"]
        self.assertLess(
            starts.index(["start", "nas-protected-services.target"]), starts.index(["start", "nas-v2-app-demo.service"])
        )

    def test_post_setup_activation_rotates_the_first_boot_key_and_retires_plaintext(self) -> None:
        self.nas.initialise()
        self.nas.path("/var/lib/nas-setup/state.json").write_text("{}")
        boot = self.nas.path(BOOT_DIR)
        (boot / "environment").write_text("AUTHENTIK_SECRET_KEY=first-boot\n")
        (boot / "api-token").write_text("superuser token")
        outpost = "outpost-token-" + "o" * 24
        set_tokens = self.nas.run(
            "set-authentik-runtime-stdin", stdin=f"{PASSWORD}\nscoped-api-token-{'a' * 20}\n{outpost}\n"
        )
        self.assertEqual(set_tokens.returncode, 0, set_tokens.stderr)
        before = self.nas.entries()["NAS/authentik-secret-key"]
        self.nas.db.chmod(0o600)
        result = self.nas.run("activate-stdin")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Rotated the Authentik secret key held in KeePassXC", result.stdout)
        self.assertNotEqual(self.nas.entries()["NAS/authentik-secret-key"], before)
        self.assertEqual(stat.S_IMODE(self.nas.db.stat().st_mode), 0o600, "KDBX mode survives the replacing save")
        unlocked = self.nas.path("/run/nas-authentik/unlocked-environment")
        self.assertEqual(os.readlink(unlocked), str(self.nas.path(SECRET_ROOT)) + "/authentik/environment")
        self.assertEqual((boot / "outpost-token").read_text(), outpost)
        self.assertFalse((boot / "api-token").exists())
        self.assertFalse((boot / "environment").exists())
        self.assertEqual(os.readlink(self.nas.path("/run/nas-authentik/outpost-token")), str(boot / "outpost-token"))
        self.assertFalse((self.nas.path(SECRET_ROOT) / "authentik-token-warning").exists())
        self.assert_no_secret_in_argv()

    def test_post_setup_without_outpost_token_keeps_the_boot_api_token(self) -> None:
        self.nas.initialise()
        self.nas.path("/var/lib/nas-setup/state.json").write_text("{}")
        boot = self.nas.path(BOOT_DIR)
        (boot / "api-token").write_text("superuser token")
        result = self.nas.run("activate-stdin")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("boot-side Authentik outpost token was not refreshed", result.stderr)
        self.assertTrue((boot / "api-token").exists())

    def test_setup_activation_never_links_or_rotates(self) -> None:
        self.nas.initialise()
        self.nas.path("/var/lib/nas-setup/state.json").write_text("{}")
        boot = self.nas.path(BOOT_DIR)
        (boot / "environment").write_text("AUTHENTIK_SECRET_KEY=first-boot\n")
        before = self.nas.entries()["NAS/authentik-secret-key"]
        result = self.nas.run("activate-setup-stdin")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.nas.entries()["NAS/authentik-secret-key"], before)
        self.assertFalse(self.nas.path("/run/nas-authentik/unlocked-environment").exists())
        self.assertTrue((boot / "environment").exists())
        starts = [call for call in self.nas.calls("systemctl") if call[0] == "start"]
        self.assertIn(["start", "--job-mode=ignore-dependencies", "authentik.service"], starts)
        self.assertNotIn(["start", "nas-authentik-proxy-outpost.service"], starts)
        self.assertNotIn(["start", "nas-protected-services.target"], starts)

    # --------------------------------------------------------------- other commands

    def test_show_zfs_key_stdin_prints_only_the_key(self) -> None:
        self.nas.initialise()
        result = self.nas.run("show-zfs-key-stdin")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, self.nas.entries()["NAS/zfs-dataset-key"])
        extra = self.nas.run("show-zfs-key-stdin", stdin=PASSWORD + "\nmore\n")
        self.assertEqual(extra.returncode, 1)
        self.assertIn("Unexpected extra input while showing the ZFS dataset key.", extra.stderr)
        self.assertEqual(extra.stdout, "")

    def test_runtime_token_input_is_validated(self) -> None:
        self.nas.initialise()
        for stdin, message in (
            (f"{PASSWORD}\nshort\n{'b' * 20}\n", "Authentik API token format is invalid."),
            (f"{PASSWORD}\n{'a' * 20}\nbad token value!!!!!!\n", "Authentik outpost token format is invalid."),
            (f"{PASSWORD}\n{'a' * 20}\n{'b' * 20}\nextra\n", "Unexpected extra input"),
            (f"{PASSWORD}\n{'a' * 20}\n", "Unable to read the Authentik outpost token"),
        ):
            with self.subTest(message=message):
                result = self.nas.run("set-authentik-runtime-stdin", stdin=stdin)
                self.assertEqual(result.returncode, 1)
                self.assertIn(message, result.stderr)

    def test_adopt_and_retire_bootstrap_authority(self) -> None:
        self.nas.initialise()
        key, token, password = "a" * 128, "b" * 64, "c" * 48
        result = self.nas.run("adopt-authentik-bootstrap-stdin", stdin=f"{PASSWORD}\n{key}\n{token}\n{password}\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        entries = self.nas.entries()
        self.assertEqual(entries["NAS/authentik-secret-key"], key)
        self.assertEqual(entries["NAS/authentik-api-token"], token)
        bad = self.nas.run("adopt-authentik-bootstrap-stdin", stdin=f"{PASSWORD}\nnothex\n{token}\n{password}\n")
        self.assertEqual(bad.returncode, 1)
        self.assertIn("Authentik bootstrap secret key has an unsafe or unexpected format", bad.stderr)
        retired = self.nas.run("retire-authentik-bootstrap-stdin")
        self.assertEqual(retired.returncode, 0, retired.stderr)
        self.assertNotIn("NAS/authentik-bootstrap-token", self.nas.entries())
        self.assert_no_secret_in_argv()

    def test_status_and_stop(self) -> None:
        status = self.nas.run("status", stdin="")
        self.assertIn("Runtime secrets: inactive", status.stdout)
        self.assertIn("KeePassXC database: configured", status.stdout)
        root = self.nas.path(SECRET_ROOT)
        root.mkdir(parents=True)
        (root / "ready").touch()
        stopped = self.nas.run("stop", stdin="")
        self.assertEqual(stopped.returncode, 0, stopped.stderr)
        self.assertFalse(root.exists())

    def test_production_build_ignores_the_test_root(self) -> None:
        result = self.nas.run("status", stdin="", binary=release_bin_dir() / "nas-secrets")
        self.assertEqual(result.returncode, 0, result.stderr)
        if not pathlib.Path(DATABASE).exists():
            self.assertIn("KeePassXC database: missing", result.stdout)


if __name__ == "__main__":
    unittest.main()
