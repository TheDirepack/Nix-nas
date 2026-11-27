"""Black-box behaviour of the Go nas-secrets binary.

These replace the source-text assertions over the retired shell script:
order, ownership and rollback are observed through the operation log of the
fake privileged tools instead.
"""

from __future__ import annotations

import json
import os
import pty
import select
import subprocess
import time
import unittest

from tests.go_binaries import binary
from tests.nas_secrets_harness import KEEPASS, Appliance, entries

MARKER = "Unable to unlock the KeePassXC database."


class Base(unittest.TestCase):
    features: dict[str, bool] | None = None

    def setUp(self) -> None:
        self.app = Appliance(features=self.features)
        self.addCleanup(self.app.close)

    def assert_ok(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr + "\n".join(self.app.log()))

    def assert_no_secret_leak(self, result: subprocess.CompletedProcess[str]) -> None:
        values = [KEEPASS, *self.app.entries().values()]
        for value in values:
            self.assertNotIn(value, result.stdout)
            self.assertNotIn(value, result.stderr)
            for line in self.app.log():
                self.assertNotIn(value, line, "secrets must never reach argv")

    def assert_sudo_never_reads_payload(self) -> None:
        sudo = [line for line in self.app.log() if line.startswith("sudo ")]
        self.assertTrue(sudo)
        for line in sudo:
            self.assertIn("stdin=/dev/null", line)


class RuntimeActivationTests(Base):
    def post_setup(self) -> None:
        self.app.setup_state.write_text("{}", encoding="utf-8")
        (self.app.boot / "environment").write_text("AUTHENTIK_SECRET_KEY=" + "f" * 128 + "\n", encoding="utf-8")
        (self.app.boot / "api-token").write_text("superuser", encoding="utf-8")
        self.app.seed_live_tree()
        self.app.activate_target()
        self.app.database.chmod(0o640)

    def test_post_setup_activation_rotates_swaps_restarts_and_retires_in_order(self) -> None:
        self.post_setup()
        before = self.app.entries()["authentik-secret-key"]
        result = self.app.run("activate-stdin")
        self.assert_ok(result)
        self.assert_no_secret_leak(result)
        self.assert_sudo_never_reads_payload()
        log = self.app.index
        rotate = log("keepassxc-cli edit")
        self.assertLess(rotate, log("keepassxc-cli show"), "the boot key is rotated before staging")
        self.assertLess(rotate, log(f"chown -- {os.getuid()}:{os.getgid()} {self.app.database}"))
        self.assertLess(rotate, log(f"chmod -- 0640 {self.app.database}"))
        swap = log(f"mv -T -- {self.app.runtime}/transactions")
        link = log(
            f"ln -sfn -- {self.app.secret_root}/authentik/environment {self.app.authentik_run}/unlocked-environment"
        )
        restart = log("systemctl try-restart authentik-worker.service authentik.service")
        target = log("systemctl start nas-protected-services.target")
        outpost = log("systemctl start nas-authentik-proxy-outpost.service")
        commit = log("rm -rf --", start=outpost)
        install_outpost = log(f"{self.app.boot}/outpost-token", start=commit)
        remove_api = log(f"rm -f -- {self.app.boot}/api-token")
        retire = log(f"rm -f -- {self.app.boot}/environment")
        self.assertLess(swap, link)
        self.assertLess(link, restart)
        self.assertLess(restart, target)
        self.assertLess(target, outpost)
        self.assertLess(commit, install_outpost)
        self.assertLess(install_outpost, remove_api, "the superuser token goes only after the outpost token")
        self.assertLess(commit, retire)
        after = self.app.entries()["authentik-secret-key"]
        self.assertNotEqual(before, after)
        environment = (self.app.secret_root / "authentik/environment").read_text(encoding="utf-8")
        self.assertEqual(environment, f"AUTHENTIK_SECRET_KEY={after}\n")
        self.assertFalse((self.app.boot / "environment").exists())
        self.assertFalse((self.app.boot / "api-token").exists())
        self.assertEqual((self.app.boot / "outpost-token").read_text(encoding="utf-8"), "outpost-token-0123456789")
        self.assertEqual(
            os.readlink(self.app.authentik_run / "unlocked-environment"),
            str(self.app.secret_root / "authentik/environment"),
        )
        self.assertFalse((self.app.secret_root / "old-marker").exists())
        for path in ("ready", "authentik/api-token", "zfs/dataset-key", "state/bundle-signing-key"):
            self.assertEqual((self.app.secret_root / path).stat().st_mode & 0o777, 0o400, path)
        self.assertEqual(list((self.app.runtime / "transactions").iterdir()), [])
        self.assertEqual(list((self.app.runtime / f"staging/{os.getuid()}").iterdir()), [])

    def test_symlinked_runtime_environment_means_the_boot_key_is_still_in_use(self) -> None:
        self.post_setup()
        (self.app.authentik_run / "environment").symlink_to(self.app.boot / "environment")
        before = self.app.entries()["authentik-secret-key"]
        self.assert_ok(self.app.run("activate-stdin"))
        self.assertEqual(self.app.entries()["authentik-secret-key"], before)
        self.assertTrue((self.app.boot / "environment").exists())

    def test_missing_outpost_token_keeps_the_boot_api_token(self) -> None:
        self.post_setup()
        self.app.write_store(entries(**{"authentik-outpost-token": None}))
        result = self.app.run("activate-stdin")
        self.assert_ok(result)
        self.assertIn("boot-side Authentik outpost token was not refreshed", result.stderr)
        self.assertTrue((self.app.boot / "api-token").exists())

    def test_pre_setup_runtime_activation_does_not_link_the_unlocked_environment(self) -> None:
        self.assert_ok(self.app.run("activate-stdin"))
        self.assertFalse((self.app.authentik_run / "unlocked-environment").exists())
        self.assertFalse([line for line in self.app.log() if line.startswith("keepassxc-cli edit")])

    def test_v2_units_start_after_the_target_and_malformed_state_is_refused(self) -> None:
        self.app.v2_state.write_text(json.dumps({"schemaVersion": 1, "startUnits": ["app-one.service"]}))
        self.assert_ok(self.app.run("activate-stdin"))
        self.assertLess(
            self.app.index("systemctl start nas-protected-services.target"),
            self.app.index("systemctl start app-one.service"),
        )
        for document in (
            {"schemaVersion": 2, "startUnits": []},
            {"schemaVersion": 1, "startUnits": "x.service"},
            {"schemaVersion": 1, "startUnits": ["--root=/tmp.service"]},
            {"schemaVersion": 1, "startUnits": [7]},
        ):
            with self.subTest(document=document):
                self.app.v2_state.write_text(json.dumps(document))
                result = self.app.run("activate-stdin")
                self.assertEqual(result.returncode, 70, result.stderr)
                self.assertIn("Refusing to activate secrets", result.stderr)

    def test_failed_target_start_rolls_back_to_the_previous_tree(self) -> None:
        self.app.seed_live_tree()
        self.app.activate_target()
        result = self.app.run("activate-stdin", FAKE_FAIL_START_ONCE="nas-protected-services.target")
        self.assertEqual(result.returncode, 71, result.stderr)
        self.assertIn("Protected service target failed to start", result.stderr)
        self.assertTrue((self.app.secret_root / "old-marker").exists())
        failed_start = self.app.index("systemctl start nas-protected-services.target")
        restore = self.app.index("mv -T --", start=failed_start)
        self.assertLess(restore, self.app.index("systemctl start nas-protected-services.target", start=restore))
        self.assertEqual(list((self.app.runtime / "transactions").iterdir()), [])

    def test_termination_after_swap_restores_the_prior_tree(self) -> None:
        self.app.seed_live_tree()
        self.app.activate_target()
        self.app.ready_server.httpd.ready = False  # type: ignore[attr-defined]
        process = subprocess.Popen(
            [str(binary("nas-secrets")), "activate-stdin"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.app.env(),
            text=True,
        )
        assert process.stdin is not None
        process.stdin.write(KEEPASS + "\n")
        process.stdin.close()
        deadline = time.monotonic() + 30
        while not any("is-failed --quiet caddy.service" in line for line in self.app.log()):
            self.assertLess(time.monotonic(), deadline, "activation never reached the readiness wait")
            time.sleep(0.05)
        self.assertFalse((self.app.secret_root / "old-marker").exists(), "the new tree is live while waiting")
        process.terminate()
        _, stderr = process.communicate(timeout=60)
        self.assertEqual(process.returncode, 143, stderr)
        self.assertTrue((self.app.secret_root / "old-marker").exists())
        self.assertTrue((self.app.state / "target-active").exists(), "the prior consumers are restarted")
        self.assertEqual(list((self.app.runtime / "transactions").iterdir()), [])

    def test_readiness_and_unit_state_failures_have_distinct_statuses(self) -> None:
        for env, status in (
            ({"FAKE_FAILED_UNIT": "caddy.service"}, 72),
            ({"FAKE_INACTIVE_UNIT": "authentik.service"}, 74),
        ):
            with self.subTest(env=env):
                self.app.seed_live_tree() if not self.app.secret_root.exists() else None
                result = self.app.run("activate-stdin", **env)
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertTrue((self.app.secret_root / "ready").exists())

    def test_wrong_password_reports_the_marker_before_any_privileged_step(self) -> None:
        result = self.app.run("activate-stdin", stdin="not the password\n")
        self.assertEqual(result.returncode, 1)
        self.assertIn(MARKER, result.stderr)
        self.assertFalse([line for line in self.app.log() if line.startswith("sudo")])

    def test_unsafe_keepass_values_are_refused_without_echoing_them(self) -> None:
        for key, value in (
            ("authentik-api-token", "bad value with spaces"),
            ("authentik-secret-key", "z" * 128),
            ("state-bundle-signing-key", "b" * 63),
        ):
            with self.subTest(key=key):
                self.app.write_store(entries(**{key: value}))
                result = self.app.run("activate-stdin")
                self.assertEqual(result.returncode, 1)
                self.assertIn("unsafe or unexpected format", result.stderr)
                self.assertNotIn(value, result.stderr + result.stdout)
                self.assertFalse((self.app.secret_root / "ready").exists())

    def test_bootstrap_token_reuse_is_staged_with_a_warning(self) -> None:
        token = "d" * 64
        self.app.write_store(
            entries(
                **{
                    "authentik-api-token": token,
                    "authentik-bootstrap-token": token,
                    "authentik-bootstrap-password": "e" * 48,
                }
            )
        )
        result = self.app.run("activate-stdin")
        self.assert_ok(result)
        self.assertIn("still the bootstrap token", result.stderr)
        self.assertTrue((self.app.secret_root / "authentik-token-warning").exists())
        environment = (self.app.secret_root / "authentik/environment").read_text(encoding="utf-8")
        self.assertIn(f"AUTHENTIK_BOOTSTRAP_TOKEN={token}\n", environment)
        self.assertIn("AUTHENTIK_BOOTSTRAP_EMAIL='admin@example.invalid'\n", environment)


class SetupActivationTests(Base):
    def test_setup_activation_keeps_the_boot_environment_and_starts_identity_explicitly(self) -> None:
        self.app.setup_state.write_text("{}", encoding="utf-8")
        (self.app.boot / "environment").write_text("x", encoding="utf-8")
        before = self.app.entries()["authentik-secret-key"]
        self.assert_ok(self.app.run("activate-setup-stdin"))
        self.assertEqual(self.app.entries()["authentik-secret-key"], before)
        self.assertTrue((self.app.boot / "environment").exists())
        self.assertFalse((self.app.authentik_run / "unlocked-environment").exists())
        joined = "\n".join(self.app.log())
        self.assertNotIn("try-restart", joined)
        self.assertNotIn("nas-authentik-proxy-outpost.service", joined)
        order = [
            "systemctl start postgresql.service",
            "systemctl start authentik-migrate.service",
            "systemctl start --job-mode=ignore-dependencies authentik.service",
            "systemctl start --job-mode=ignore-dependencies authentik-worker.service",
            "systemctl start --job-mode=ignore-dependencies caddy.service",
        ]
        positions = [self.app.index(item) for item in order]
        self.assertEqual(positions, sorted(positions))


class OptionalConsumerTests(Base):
    features = {"observability": True, "grafana": True, "ntfy": True, "vaultwarden": True, "nutWeb": True}

    def test_every_optional_secret_is_validated_and_rendered(self) -> None:
        self.app.write_store(
            entries(
                **{
                    "grafana-secret-key": "g" * 32,
                    "ntfy-admin-password": "n" * 24,
                    "ntfy-alert-topic": "topic_0123",
                    "nut-webgui-server-key": "nut-key",
                    "vaultwarden-oidc-client-secret": "client-secret-01",
                    "vaultwarden-admin": "admin-token-0123",
                }
            )
        )
        result = self.app.run("activate-stdin")
        self.assert_ok(result)
        self.assert_no_secret_leak(result)
        ntfy = (self.app.secret_root / "observability/ntfy-environment").read_text(encoding="utf-8")
        self.assertRegex(ntfy, r"^NTFY_AUTH_USERS=admin:\$2a\$12\$[./A-Za-z0-9]{53}:admin\n")
        vault = (self.app.secret_root / "vaultwarden/environment").read_text(encoding="utf-8")
        self.assertRegex(
            vault, r"^ADMIN_TOKEN='\$argon2id\$v=19\$m=65536,t=3,p=4\$[^']+'\nSSO_CLIENT_SECRET='client-secret-01'\n$"
        )
        self.assertEqual((self.app.secret_root / "power/nut-webgui-server-key").read_text(), "nut-key")
        for key, value in (("ntfy-alert-topic", "topic/../../admin"), ("vaultwarden-admin", "bad'quote-value")):
            with self.subTest(key=key):
                self.app.write_store({**self.app.entries(), key: value})
                result = self.app.run("activate-stdin")
                self.assertEqual(result.returncode, 1)
                self.assertNotIn(value, result.stderr)


class PasswordInputTests(Base):
    def test_stdin_password_is_one_bounded_line(self) -> None:
        self.app.write_store(entries(), password="p" * 4096)
        accepted = self.app.run("show-zfs-key-stdin", stdin="p" * 4096 + "\n")
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertEqual(accepted.stdout, "c" * 64)
        rejected = self.app.run("show-zfs-key-stdin", stdin="p" * 5000 + "\n")
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("exceeds 4096", rejected.stderr)
        for stdin, message in (("\n", "cannot be empty"), ("", "Unable to read")):
            result = self.app.run("show-zfs-key-stdin", stdin=stdin)
            self.assertEqual(result.returncode, 1)
            self.assertIn(message, result.stderr)
        self.app.write_store(entries())
        extra = self.app.run("show-zfs-key-stdin", stdin=KEEPASS + "\nmore\n")
        self.assertEqual(extra.returncode, 1)
        self.assertIn("Unexpected extra input", extra.stderr)
        self.assertEqual(extra.stdout, "")

    def test_terminal_prompt_stays_on_stderr(self) -> None:
        primary, secondary = pty.openpty()
        process = subprocess.Popen(
            [str(binary("nas-secrets")), "show-zfs-key"],
            stdin=secondary,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.app.env(),
        )
        os.close(secondary)
        deadline = time.monotonic() + 10
        seen = b""
        while b"KeePass database password: " not in seen and time.monotonic() < deadline:
            assert process.stderr is not None
            ready, _, _ = select.select([process.stderr], [], [], 0.2)
            if ready:
                seen += os.read(process.stderr.fileno(), 1024)
        os.write(primary, KEEPASS.encode() + b"\n")
        stdout, stderr = process.communicate(timeout=30)
        echoed = b""
        while select.select([primary], [], [], 0.1)[0]:
            try:
                echoed += os.read(primary, 1024)
            except OSError:
                break
        os.close(primary)
        self.assertEqual(process.returncode, 0, stderr)
        self.assertEqual(stdout, b"c" * 64)
        self.assertNotIn(KEEPASS.encode(), echoed, "the password must not echo")


class SecretStoreTests(Base):
    def test_listing_failure_aborts_before_add_or_edit(self) -> None:
        result = self.app.run("set-authentik-token-stdin", stdin=KEEPASS + "\n" + "t" * 30 + "\n", FAKE_KP_FAIL_LS="7")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unable to inspect the KeePassXC secret group.", result.stderr)
        subcommands = [line.split()[1] for line in self.app.log() if line.startswith("keepassxc-cli")]
        self.assertNotIn("add", subcommands)
        self.assertNotIn("edit", subcommands)

    def test_group_creation_failure_is_not_ignored(self) -> None:
        result = self.app.run(
            "set-authentik-token-stdin",
            stdin=KEEPASS + "\n" + "t" * 30 + "\n",
            FAKE_KP_FAIL_LS="1",
            FAKE_KP_FAIL_MKDIR="2",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unable to ensure KeePassXC group", result.stderr)

    def test_tokens_are_validated_and_stored(self) -> None:
        bad = self.app.run("set-authentik-token-stdin", stdin=KEEPASS + "\nshort\n")
        self.assertEqual(bad.returncode, 1)
        self.assertIn("format is invalid", bad.stderr)
        good = self.app.run("set-authentik-runtime-stdin", stdin=KEEPASS + "\n" + "a" * 30 + "\n" + "b" * 30 + "\n")
        self.assert_ok(good)
        self.assertEqual(self.app.entries()["authentik-api-token"], "a" * 30)
        self.assertEqual(self.app.entries()["authentik-outpost-token"], "b" * 30)

    def test_adopt_retire_and_check_bootstrap_authority(self) -> None:
        payload = "\n".join([KEEPASS, "1" * 128, "2" * 64, "3" * 48]) + "\n"
        self.assert_ok(self.app.run("adopt-authentik-bootstrap-stdin", stdin=payload))
        self.assertEqual(self.app.entries()["authentik-api-token"], "2" * 64)
        check = self.app.run("check-authentik-token")
        self.assertEqual(check.returncode, 1)
        self.assertIn("still the bootstrap token", check.stderr)
        self.assert_ok(self.app.run("retire-authentik-bootstrap-stdin"))
        self.assertNotIn("authentik-bootstrap-token", self.app.entries())
        retired = self.app.run("check-authentik-token")
        self.assert_ok(retired)
        self.assertIn("bootstrap token is retired", retired.stdout)

    def test_failed_bootstrap_entry_deletion_preserves_the_entry(self) -> None:
        original = "bootstrap-token-0123456789"
        self.app.write_store(entries(**{"authentik-bootstrap-token": original}))
        result = self.app.run("retire-authentik-bootstrap-stdin", FAKE_KP_FAIL_RM="2")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unable to remove KeePassXC entry", result.stderr)
        self.assertEqual(self.app.entries()["authentik-bootstrap-token"], original)
        self.assert_no_secret_leak(result)

    def test_init_creates_only_missing_items(self) -> None:
        self.app.write_store({"zfs-dataset-key": "keep-me"})
        result = self.app.run("init")
        self.assert_ok(result)
        values = self.app.entries()
        self.assertEqual(values["zfs-dataset-key"], "keep-me")
        self.assertEqual(values["authentik-api-token"], values["authentik-bootstrap-token"])
        self.assertRegex(values["authentik-secret-key"], r"^[0-9a-f]{128}$")
        self.assertIn("KeePassXC item already exists: ZFS native encryption key", result.stdout)


class LifecycleTests(Base):
    def test_stop_revokes_readiness_before_systemd_can_reactivate_dependencies(self) -> None:
        self.app.seed_live_tree()
        self.assert_ok(self.app.run("stop", stdin=""))
        self.assertLess(
            self.app.index(f"rm -f -- {self.app.secret_root}/ready"),
            self.app.index("systemctl stop nas-protected-services.target"),
        )
        self.assertFalse(self.app.secret_root.exists())

    def test_status_reports_without_unlocking(self) -> None:
        result = self.app.run("status", stdin="")
        self.assert_ok(result)
        self.assertIn("Runtime secrets: inactive", result.stdout)
        self.assertIn("KeePassXC database: configured", result.stdout)

    def test_mutations_enter_the_operation_coordinator(self) -> None:
        result = self.app.run("stop", stdin="", NAS_OPERATION_COORDINATION_TOKEN="")
        self.assert_ok(result)
        self.assertIn(
            "runner --action nas-secrets:stop --class secrets --class runtime --",
            "\n".join(self.app.log()),
        )
        self.assert_ok(self.app.run("status", stdin="", NAS_OPERATION_COORDINATION_TOKEN=""))
        self.assertEqual(sum(line.startswith("runner --action") for line in self.app.log()), 1)

    def test_concurrent_operations_are_refused(self) -> None:
        import fcntl

        with open(self.app.root / "nas-secrets.lock", "w") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            result = self.app.run("activate-stdin")
        self.assertEqual(result.returncode, 1)
        self.assertIn("Another NAS secret operation is already running.", result.stderr)

    def test_usage(self) -> None:
        result = self.app.run("bogus", stdin="")
        self.assertEqual(result.returncode, 2)
        self.assertIn("Usage: nas-secrets {init|", result.stderr)


if __name__ == "__main__":
    unittest.main()
