from __future__ import annotations

import os
import pathlib
import re
import subprocess
import tempfile
import textwrap
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SECRET_TOOLS = ROOT / "modules/nas/internal/secret-tools.nix"


def rendered_shell_helpers(*names: str) -> str:
    source = SECRET_TOOLS.read_text(encoding="utf-8")
    blocks: list[str] = []
    for name in names:
        marker = f"      {name}() {{"
        position = source.find(marker)
        if position < 0:
            raise AssertionError(f"missing helper {name}")
        next_function = re.search(r"\n      [a-zA-Z0-9_]+\(\) \{", source[position + 1 :])
        end = len(source) if next_function is None else position + 1 + next_function.start()
        block = textwrap.dedent(source[position:end]).replace("''${", "${")
        blocks.append(block.rstrip())
    return "\n\n".join(blocks) + "\n"


def rendered_signal_setup() -> str:
    source = SECRET_TOOLS.read_text(encoding="utf-8")
    start = source.index("      cleanup_password() {")
    end = source.index("\n\n      acquire_lock() {", start)
    return textwrap.dedent(source[start:end]).replace("''${", "${") + "\n"


class KeePassFailClosedTests(unittest.TestCase):
    def run_scenario(
        self,
        body: str,
        *,
        ls_output: str = "",
        ls_status: int = 0,
        mkdir_status: int = 0,
    ) -> tuple[subprocess.CompletedProcess[str], str]:
        with tempfile.TemporaryDirectory() as directory:
            work = pathlib.Path(directory)
            bin_dir = work / "bin"
            bin_dir.mkdir()
            log = work / "keepass.log"
            cli = bin_dir / "keepassxc-cli"
            cli.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env python3
                    import os
                    import sys

                    command = sys.argv[1] if len(sys.argv) > 1 else ""
                    with open(os.environ["KEEPASS_TEST_LOG"], "a", encoding="utf-8") as handle:
                        handle.write(" ".join(sys.argv[1:]) + "\\n")

                    if command == "ls":
                        sys.stdout.write(os.environ.get("KEEPASS_TEST_LS_OUTPUT", ""))
                        raise SystemExit(int(os.environ.get("KEEPASS_TEST_LS_STATUS", "0")))
                    if command == "mkdir":
                        raise SystemExit(int(os.environ.get("KEEPASS_TEST_MKDIR_STATUS", "0")))
                    if command in {"add", "edit", "rm"}:
                        sys.stdin.read()
                        raise SystemExit(0)
                    if command == "show":
                        sys.stdin.read()
                        sys.stdout.write("retrieved-secret")
                        raise SystemExit(0)
                    raise SystemExit(99)
                    """
                ),
                encoding="utf-8",
            )
            cli.chmod(0o755)
            helpers = rendered_shell_helpers(
                "kp_args",
                "entry_path",
                "ensure_group",
                "has_secret",
                "store_value",
                "remove_value",
                "get_secret",
                "get_secret_optional",
            )
            script = textwrap.dedent(
                f"""\
                set -Eeuo pipefail
                export PATH={bin_dir}:$PATH
                database=/tmp/test.kdbx
                key_file=""
                secret_group=NAS
                keepass_password=database-password
                {helpers}
                {body}
                """
            )
            env = os.environ.copy()
            env.update(
                {
                    "KEEPASS_TEST_LOG": str(log),
                    "KEEPASS_TEST_LS_OUTPUT": ls_output,
                    "KEEPASS_TEST_LS_STATUS": str(ls_status),
                    "KEEPASS_TEST_MKDIR_STATUS": str(mkdir_status),
                }
            )
            result = subprocess.run(
                ["bash", "-c", script],
                cwd=work,
                env=env,
                text=True,
                capture_output=True,
                check=False,
                timeout=10,
            )
            return result, log.read_text(encoding="utf-8") if log.exists() else ""

    def test_exact_flattened_listing_membership_is_used(self) -> None:
        result, log = self.run_scenario(
            "has_secret alpha; ! has_secret alp; ! has_secret gamma",
            ls_output="alpha\nbeta\n",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr + log)
        self.assertIn("ls --quiet --pw-stdin --flatten /tmp/test.kdbx NAS", log)
        self.assertNotIn("show ", log)

    def test_listing_failure_aborts_store_before_add_or_edit(self) -> None:
        result, log = self.run_scenario(
            'store_value alpha "new-secret"',
            ls_status=74,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unable to list KeePassXC secret group", result.stderr)
        self.assertIn("ls ", log)
        self.assertNotIn(" add ", f" {log} ")
        self.assertNotIn(" edit ", f" {log} ")

    def test_missing_entry_adds_but_existing_entry_edits(self) -> None:
        missing, missing_log = self.run_scenario(
            'store_value alpha "new-secret"',
            ls_output="beta\n",
        )
        self.assertEqual(missing.returncode, 0, missing.stdout + missing.stderr + missing_log)
        self.assertIn("\nadd ", "\n" + missing_log)

        existing, existing_log = self.run_scenario(
            'store_value alpha "new-secret"',
            ls_output="alpha\n",
        )
        self.assertEqual(existing.returncode, 0, existing.stdout + existing.stderr + existing_log)
        self.assertIn("\nedit ", "\n" + existing_log)

    def test_group_creation_failure_is_not_silently_ignored(self) -> None:
        result, log = self.run_scenario(
            "ensure_group",
            ls_status=1,
            mkdir_status=75,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unable to create or verify KeePassXC secret group", result.stderr)
        self.assertIn("\nmkdir ", "\n" + log)

    def test_absent_optional_secret_returns_empty_without_show(self) -> None:
        result, log = self.run_scenario(
            'value="$(get_secret_optional alpha)"; [[ -z "$value" ]]',
            ls_output="beta\n",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr + log)
        self.assertNotIn("\nshow ", "\n" + log)

    def test_machine_keys_are_validated_before_runtime_staging(self) -> None:
        source = SECRET_TOOLS.read_text(encoding="utf-8")
        required = (
            'require_secret_hex "$grafana_secret_key" 64',
            'require_secret_hex "$nut_webgui_server_key" 64',
            'require_secret_hex "$zfs_dataset_key" 64',
        )
        for marker in required:
            with self.subTest(marker=marker):
                self.assertIn(marker, source)

    def test_token_setters_and_hf_validator_have_explicit_upper_bounds(self) -> None:
        source = SECRET_TOOLS.read_text(encoding="utf-8")
        self.assertGreaterEqual(source.count("''${#token} > 4096"), 3)
        helpers = rendered_shell_helpers("require_huggingface_token")
        too_large = "hf_" + "A" * 4094
        result = subprocess.run(
            [
                "bash",
                "-c",
                "set -Eeuo pipefail\n" + helpers + 'require_huggingface_token "$1"',
                "bash",
                too_large,
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)

    def test_secret_signal_handlers_terminate_instead_of_resuming(self) -> None:
        setup = rendered_signal_setup()
        source = SECRET_TOOLS.read_text(encoding="utf-8")
        for signal_name, expected_status in (("HUP", 129), ("INT", 130), ("TERM", 143)):
            with self.subTest(signal=signal_name):
                self.assertIn(
                    f"trap 'cleanup_password; exit {expected_status}' {signal_name}",
                    source,
                )
                result = subprocess.run(
                    [
                        "bash",
                        "-c",
                        "set -Eeuo pipefail\n"
                        "keepass_password=top-secret\n"
                        + setup
                        + f"kill -s {signal_name} $$\nprintf 'survived\\n'\n",
                    ],
                    cwd=ROOT,
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=10,
                )
                self.assertEqual(result.returncode, expected_status, result.stdout + result.stderr)
                self.assertNotIn("survived", result.stdout)


if __name__ == "__main__":
    unittest.main()
