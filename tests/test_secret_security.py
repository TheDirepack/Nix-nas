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
        # Nix indented strings escape a shell interpolation as ''${...}; remove
        # only that Nix escape so the function can execute as ordinary Bash.
        block = textwrap.dedent(block).replace("''${", "${")
        output.append(block.rstrip())
    return "\n\n".join(output) + "\n"


class SecretVaultRenderingTests(unittest.TestCase):
    def run_helper(self, function: str, *arguments: str) -> subprocess.CompletedProcess[str]:
        helpers = rendered_shell_helpers(
            "require_secret_atom",
            "require_secret_hex",
            "require_ntfy_topic",
            "require_huggingface_token",
        )
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
            "hf_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
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
            "safe value with spaces",
            "'quoted-secret'",
            '"quoted-secret"',
            "$(touch /tmp/nas-secret-injection)",
            "`id`xxxxxxxx",
            "semi;colon",
            "pipe|value",
            "back\\slash",
            "nul\x00byte-value",
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

    def test_huggingface_token_is_empty_or_exact_read_token_shape(self) -> None:
        self.assertEqual(self.run_helper("require_huggingface_token", "").returncode, 0)
        self.assertEqual(self.run_helper("require_huggingface_token", "hf_" + "A" * 24).returncode, 0)
        for value in ("hf_short", "token", "hf_ABC\nEVIL=1", "hf_" + "A" * 20 + "-"):
            with self.subTest(value=repr(value)):
                self.assertNotEqual(self.run_helper("require_huggingface_token", value).returncode, 0)

    def test_every_runtime_environment_secret_is_guarded_before_rendering(self) -> None:
        source = SECRET_TOOLS.read_text(encoding="utf-8")
        required_pairs = (
            ('require_secret_atom "$authentik_password"', "AUTHENTIK_BOOTSTRAP_PASSWORD=$authentik_password"),
            ('require_secret_atom "$llama_swap_api_key"', "LLAMA_SWAP_API_KEY=%s"),
            ('require_secret_atom "$open_webui_secret"', "WEBUI_SECRET_KEY=%s"),
            ('require_secret_atom "$open_webui_admin_password"', "WEBUI_ADMIN_PASSWORD=%s"),
            ('require_huggingface_token "$huggingface_token"', "HF_TOKEN=%s"),
            ('require_secret_atom "$vaultwarden_client_secret"', "SSO_CLIENT_SECRET='%s'"),
            ('require_secret_atom "$ntfy_password"', "NTFY_AUTH_USERS=admin:$ntfy_hash:admin"),
            ('require_ntfy_topic "$ntfy_topic"', 'printf \'%s\' "$ntfy_topic"'),
        )
        for guard, render in required_pairs:
            with self.subTest(render=render):
                guard_pos = source.find(guard)
                render_pos = source.find(render)
                self.assertGreaterEqual(guard_pos, 0, guard)
                self.assertGreater(render_pos, guard_pos, f"{render} rendered before {guard}")

    def test_keepass_passwords_and_secret_values_are_not_passed_in_argv(self) -> None:
        source = SECRET_TOOLS.read_text(encoding="utf-8")
        self.assertIn("--pw-stdin", source)
        self.assertNotRegex(source, r"keepassxc-cli[^\n]*(?:--password|-p)\s+\"?\$keepass_password")
        self.assertNotRegex(source, r"curl[^\n]*(?:--user|-u)\s+\"?admin:\$password")
        self.assertNotIn("set -x", source)
        self.assertNotIn("set -o xtrace", source)

    def test_secret_install_permissions_remain_owner_read_only(self) -> None:
        source = SECRET_TOOLS.read_text(encoding="utf-8")
        self.assertIn('sudo install -m 0400 -o "$owner" -g "$group" "$source" "$target"', source)
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


if __name__ == "__main__":
    unittest.main()
