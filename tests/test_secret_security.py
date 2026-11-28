from __future__ import annotations

import pathlib
import re
import shlex
import subprocess
import tempfile
import textwrap
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SECRET_TOOLS = ROOT / "modules/nas/internal/secret-tools.nix"
MAINTENANCE_TOOLS = ROOT / "modules/nas/internal/maintenance-tools.nix"


def rendered_shell_helpers(*names: str) -> str:
    """Extract selected generated-shell helpers from secret-tools.nix for direct tests."""

    source = SECRET_TOOLS.read_text(encoding="utf-8")
    starts = []
    for name in names:
        marker = f"      {name}() {{"
        position = source.find(marker)
        if position < 0:
            raise AssertionError(f"missing helper {name}")
        starts.append((position, name))
    starts.sort()
    output: list[str] = []
    for position, name in starts:
        next_function = re.search(r"\n      [a-zA-Z0-9_]+\(\) \{", source[position + 1 :])
        end = len(source) if next_function is None else position + 1 + next_function.start()
        block = source[position:end]
        block = textwrap.dedent(block).replace("''${", "${")
        output.append(block.rstrip())
    return "\n\n".join(output) + "\n"


class SecretVaultRenderingTests(unittest.TestCase):
    def test_optional_ntfy_locals_are_declared_only_when_rendered(self) -> None:
        source = SECRET_TOOLS.read_text(encoding="utf-8")
        self.assertNotIn("local ntfy_password ntfy_hash ntfy_topic state_bundle_signing_key", source)
        self.assertIn(
            "${lib.optionalString cfg.observability.ntfy.enable ''local ntfy_password ntfy_hash ntfy_topic''}",
            source,
        )

    def run_helper(self, function: str, *arguments: str) -> subprocess.CompletedProcess[str]:
        helpers = "source " + shlex.quote(str(ROOT / "scripts/lib/nas-secret-runtime.sh")) + "\n"
        command = f"{function} " + " ".join(shlex.quote(value) for value in arguments)
        return subprocess.run(
            ["bash", "-c", "set -Eeuo pipefail\n" + helpers + command],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )

    def test_environment_atom_accepts_generated_secrets(self) -> None:
        for value in (
            "a" * 20,
            "0123456789abcdef" * 4,
            "sk-live_ABC.def-123+/=:@~",
        ):
            with self.subTest(value=value):
                result = self.run_helper("require_secret_atom", value, "test secret", "8", "4096")
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_environment_atom_rejects_config_injection_and_control_characters(self) -> None:
        bad = (
            "short",
            "safe\nEVIL=1",
            "safe\rEVIL=1",
            "safe\tvalue",
            "safe value with spaces",
            "'quoted-secret'",
            '"quoted-secret"',
            "$(touch /tmp/nas-secret-injection)",
            "`id`xxxxxxxx",
            "semi;colon",
            "pipe|value",
            "back\\slash",
            "control\x1fvalue",
            "x" * 4097,
        )
        marker = pathlib.Path("/tmp/nas-secret-injection")
        marker.unlink(missing_ok=True)
        for value in bad:
            with self.subTest(value=repr(value)):
                result = self.run_helper("require_secret_atom", value, "test secret", "8", "4096")
                self.assertNotEqual(result.returncode, 0)
        self.assertFalse(marker.exists(), "validator test executed hostile command substitution")

    def test_hex_validator_requires_exact_length_and_hex_alphabet(self) -> None:
        self.assertEqual(self.run_helper("require_secret_hex", "a" * 64, "64", "key").returncode, 0)
        for value in ("a" * 63, "a" * 65, "g" * 64, "a" * 32 + "\n" + "b" * 31):
            with self.subTest(value=repr(value)):
                self.assertNotEqual(self.run_helper("require_secret_hex", value, "64", "key").returncode, 0)

    def test_ntfy_topic_cannot_inject_curl_config(self) -> None:
        for value in ("deadbeefcafebabe", "private_topic-123"):
            self.assertEqual(self.run_helper("require_ntfy_topic", value).returncode, 0)
        for value in (
            'topic"\nuser = "attacker:password"',
            "topic/../../admin",
            "topic?x=1",
            "topic with space",
            "x" * 129,
        ):
            with self.subTest(value=repr(value)):
                self.assertNotEqual(self.run_helper("require_ntfy_topic", value).returncode, 0)

    def test_every_runtime_environment_secret_is_guarded_before_rendering(self) -> None:
        source = SECRET_TOOLS.read_text(encoding="utf-8")
        required_pairs = (
            (
                'require_secret_atom "$authentik_bootstrap_password"',
                "AUTHENTIK_BOOTSTRAP_PASSWORD=$authentik_bootstrap_password",
            ),
            ('require_secret_atom "$vaultwarden_client_secret"', "SSO_CLIENT_SECRET='%s'"),
            ('require_secret_atom "$ntfy_password"', "NTFY_AUTH_USERS=admin:$ntfy_hash:admin"),
            ('require_ntfy_topic "$ntfy_topic"', "printf '%s' \"$ntfy_topic\""),
        )
        for guard, render in required_pairs:
            with self.subTest(render=render):
                guard_pos = source.find(guard)
                render_pos = source.find(render)
                self.assertGreaterEqual(guard_pos, 0, guard)
                self.assertGreater(render_pos, guard_pos, f"{render} rendered before {guard}")

    def test_keepass_passwords_and_secret_values_are_not_passed_in_argv(self) -> None:
        source = SECRET_TOOLS.read_text(encoding="utf-8")
        self.assertNotIn("--pw-stdin", source)
        self.assertNotRegex(source, r"keepassxc-cli[^\n]*(?:--password|-p)\s+\"?\$keepass_password")
        self.assertNotRegex(source, r"curl[^\n]*(?:--user|-u)\s+\"?admin:\$password")
        self.assertNotIn("set -x", source)
        self.assertNotIn("set -o xtrace", source)

    def test_secret_install_permissions_remain_owner_read_only(self) -> None:
        source = SECRET_TOOLS.read_text(encoding="utf-8")
        library = (ROOT / "scripts/lib/nas-secret-runtime.sh").read_text(encoding="utf-8")
        self.assertIn('sudo install -m 0400 -o "$owner" -g "$group" -- "$source" "$target"', library)
        self.assertIn('find "$local_stage" -type f -exec chmod 0600 {} +', source)
        self.assertIn('sudo install -m 0400 -o root -g root /dev/null "$root_stage/ready"', source)

    def test_keepass_delete_failures_are_not_silently_ignored(self) -> None:
        source = SECRET_TOOLS.read_text(encoding="utf-8")
        start = source.index("      remove_value() {")
        end = source.index("      get_secret() {", start)
        block = source[start:end]
        self.assertNotIn("|| true", block)
        self.assertIn("Unable to remove KeePassXC entry", block)

    def test_ntfy_curl_credentials_stay_in_private_config_not_argv(self) -> None:
        source = MAINTENANCE_TOOLS.read_text(encoding="utf-8")
        self.assertIn('curl_config="$(mktemp /run/nas-alert-curl.XXXXXX)"', source)
        self.assertIn('chmod 0600 "$curl_config"', source)
        self.assertIn('user = "admin:$password"', source)
        self.assertNotIn('--user "admin:$password"', source)
        self.assertNotIn('-u "admin:$password"', source)


class KeePassPasswordInputTests(unittest.TestCase):
    def prompt(self, password: str) -> subprocess.CompletedProcess[str]:
        helpers = rendered_shell_helpers("require_database", "prompt_unlock")
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            database = root / "NAS.kdbx"
            database.write_text("fixture", encoding="utf-8")
            fake = root / "keepassxc-cli"
            fake.write_text("#!/bin/sh\ncat >/dev/null\nexit 0\n", encoding="utf-8")
            fake.chmod(0o755)
            script = (
                "set -Eeuo pipefail\n"
                f"database={shlex.quote(str(database))}\nkey_file=''\npassword_from_stdin=true\n"
                + helpers
                + 'prompt_unlock\necho "length=${#keepass_password}"\n'
            )
            return subprocess.run(
                ["bash", "-c", script],
                input=password + "\n",
                env={"PATH": f"{root}:/usr/bin:/bin"},
                text=True,
                capture_output=True,
                check=False,
                timeout=10,
            )

    def test_stdin_password_is_one_bounded_line(self) -> None:
        accepted = self.prompt("p" * 4096)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertIn("length=4096", accepted.stdout)
        rejected = self.prompt("p" * 5000)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("exceeds 4096", rejected.stderr)


class AuthentikActivationModeTests(unittest.TestCase):
    def activation(self) -> str:
        source = SECRET_TOOLS.read_text(encoding="utf-8")
        start = source.index("      command_activate() (")
        return source[start : source.index("      command_status() {", start)]

    def test_keepass_environment_is_applied_by_restarting_authentik_before_the_target(self) -> None:
        body = self.activation()
        swap = body.index("nas_secret_tx_swap")
        restart = body.index("sudo systemctl try-restart authentik-worker.service authentik.service")
        target = body.index("sudo systemctl start nas-protected-services.target")
        link = body.index(
            'sudo ln -sfn -- "$secret_root/authentik/environment" ${lib.escapeShellArg authentikUnlockedEnvironmentFile}'
        )
        self.assertLess(swap, link)
        self.assertLess(link, restart)
        self.assertLess(restart, target)
        self.assertIn("if $post_setup; then", body[swap:link], "first start keeps the regenerated boot environment")
        setup_branch = body.index('if [[ "$setup_activation" == true ]]; then', swap)
        self.assertLess(setup_branch, restart, "setup activation keeps its explicit start sequence")

    def test_first_boot_secret_key_is_rotated_before_staging_and_retired_after_commit(self) -> None:
        body = self.activation()
        rotation = body.index('store_value authentik-secret-key "$(openssl rand -hex 64)"')
        guard = body[:rotation]
        self.assertIn('sudo test -e "$boot_authentik_dir/environment"', guard)
        self.assertIn("! sudo test -L ${lib.escapeShellArg authentikRuntimeEnvironmentFile}", guard)
        self.assertIn('if [[ "$setup_activation" != true ]] && sudo test -e /var/lib/nas-setup/state.json', guard)
        self.assertLess(rotation, body.index('authentik_secret="$(get_secret authentik-secret-key)"'))
        after_rotation = body[rotation : body.index('authentik_secret="$(get_secret authentik-secret-key)"')]
        self.assertIn('sudo chown -- "$database_owner" "$database"', after_rotation)
        self.assertIn('sudo chmod -- "$database_mode" "$database"', after_rotation)
        commit = body.index("        nas_secret_tx_commit\n")
        retire = body.index('sudo rm -f -- "$boot_authentik_dir/environment"')
        self.assertLess(commit, retire)
        self.assertIn("if $retire_boot_environment; then", body[commit:retire])

    def test_only_the_outpost_token_remains_on_the_system_partition(self) -> None:
        body = self.activation()
        commit = body.index("        nas_secret_tx_commit\n")
        tail = body[commit:]
        copy = tail.index(
            'sudo install -m 0400 -o root -g root "$secret_root/authentik/outpost-token" "$boot_authentik_dir/outpost-token"'
        )
        removal = tail.index('sudo rm -f -- "$boot_authentik_dir/api-token"')
        self.assertLess(copy, removal, "the superuser token is removed only after the outpost token is in place")
        self.assertNotIn('"$authentik_outpost_token" | sudo', tail, "sudo must never consume secret stdin")


if __name__ == "__main__":
    unittest.main()
