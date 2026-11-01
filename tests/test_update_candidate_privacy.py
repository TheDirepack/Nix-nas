from __future__ import annotations

import os
import pathlib
import re
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "scripts/update-nas.sh"


class UpdateCandidatePrivacyTests(unittest.TestCase):
    def run_candidate(self, *, fail_checkout: bool = False) -> subprocess.CompletedProcess[str]:
        source = SOURCE.read_text(encoding="utf-8")
        start = re.search(r'^  candidate_(?:worktree|root)="\$\(mktemp', source, re.MULTILINE)
        assert start is not None
        checkout = source[start.start() : source.index('\nfi\n\ncd "$deployment_dir"')]
        cleanup = source[source.index("cleanup_candidate() {") : source.index("\ntrap cleanup_candidate EXIT")]
        with tempfile.TemporaryDirectory() as raw:
            private = pathlib.Path(raw)
            self.assertEqual(private.stat().st_mode & 0o777, 0o700)
            root = private / "shared"
            root.mkdir()
            root.chmod(0o777)
            script = "\n".join(
                [
                    "set -Eeuo pipefail",
                    'candidate_worktree=""; candidate_root=""; active_config_dir="$FIXTURE_ROOT"; candidate_commit=fixture',
                    'mktemp() { command mktemp -d "$FIXTURE_ROOT/private.XXXXXX"; }',
                    "git_safe() {",
                    '  if [[ "$1 $2" == "worktree add" ]]; then',
                    '    local target=$4 parent; parent=$(dirname -- "$target")',
                    '    [[ -d "$parent" && $(stat -c %a "$parent") == 700 ]] || return 81',
                    '    [[ ! -e "$target" ]] || return 82',
                    "    [[ ${FAIL_CHECKOUT:-0} == 0 ]] || return 83",
                    '    mkdir -- "$target"; touch "$target/candidate"',
                    "  else",
                    '    command rm -rf -- "${@: -1}"',
                    "  fi",
                    "}",
                    cleanup,
                    "trap cleanup_candidate EXIT",
                    checkout,
                    '[[ -f "$deployment_dir/candidate" ]]',
                ]
            )
            result = subprocess.run(
                ["bash", "-c", script],
                env={**os.environ, "FIXTURE_ROOT": str(root), "FAIL_CHECKOUT": "1" if fail_checkout else "0"},
                capture_output=True,
                text=True,
                check=False,
                timeout=15,
            )
            self.assertEqual(list(root.iterdir()), [], result.stdout + result.stderr)
            return result

    def test_private_parent_exists_before_git_creates_candidate(self) -> None:
        result = self.run_candidate()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_checkout_failure_preserves_native_exit_and_cleans_private_parent(self) -> None:
        result = self.run_candidate(fail_checkout=True)
        self.assertEqual(result.returncode, 83, result.stdout + result.stderr)
