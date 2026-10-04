"""Execute the production transaction shell at its dependency boundaries.

Native adapter rollback is tested in each adapter suite. Here external adapter
commands are failing stand-ins; Git history and the transaction/rollback shell
are real. These assertions prove ordering and revision recovery, not live OS
convergence.
"""

from __future__ import annotations

import pathlib
import shlex
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))
import nas_v2_history as history  # noqa: E402


class V2TransactionFaultTests(unittest.TestCase):
    def render(self, source, replacements):
        for key in sorted(replacements, key=len, reverse=True):
            value = replacements[key]
            source = source.replace("${" + key + "}", value)
        source = source.replace("${lib.optionalString networkingEnabled ''", "")
        source = source.replace("${lib.optionalString firewalldEnabled ''", "")
        source = source.replace("''}", "").replace("''${", "${")
        self.assertNotIn("${lib.", source)
        self.assertNotIn("${pkgs.", source)
        return source

    def test_transaction_failures_do_not_commit_and_rollback_restores_real_authority(self):
        source = (ROOT / "modules/nas/config/managed-services-transactions.nix").read_text()
        post = source.split("postStart = lib.mkForce ''", 1)[1].split("    '';", 1)[0]
        rollback = source.split("rollbackToApplied = pkgs.writeShellScript \"nas-v2-rollback-to-applied\" ''", 1)[
            1
        ].split("  '';", 1)[0]
        stages = ("nmstate", "firewalld", "systemd", "caddy", "mark-applied", "ack-pending", "cancel")
        for established in (False, True):
            for stage in stages:
                with self.subTest(established=established, stage=stage), tempfile.TemporaryDirectory() as raw:
                    root = pathlib.Path(raw)
                    authority = root / "services.yaml"
                    repo = root / "history.git"
                    authority.write_text("schemaVersion: 3\nservices: {}\n")
                    history.ensure_bootstrap_applied(authority=authority, repository=repo)
                    if established:
                        authority.write_text("schemaVersion: 3\nservices:\n  old: {}\n")
                        old = history.record_desired(authority=authority, repository=repo)["head"]
                        history.mark_applied(authority=authority, repository=repo, commit=old)
                        history.clear_previous_applied(authority=authority, repository=repo)
                    baseline = authority.read_bytes()
                    authority.write_text("schemaVersion: 3\nservices:\n  new: {}\n")
                    failed = history.record_desired(authority=authority, repository=repo)["head"]
                    plan = root / "plan.json"
                    plan.write_text('{"desiredRevision": "' + failed + '"}')
                    real_history = shlex.join(
                        [
                            sys.executable,
                            str(ROOT / "services/nas_v2_history.py"),
                            "--authority",
                            str(authority),
                            "--repository",
                            str(repo),
                        ]
                    )
                    replacements = {
                        "v2Python": str(root / "python"),
                        "v2Source": str(ROOT / "services"),
                        "lib.escapeShellArgs historyArgs": "history_command",
                        "lib.escapeShellArgs nmstateArgs": "dependency nmstate",
                        "lib.escapeShellArgs statelessFirewalldArgs": "dependency firewalld",
                        "lib.escapeShellArgs systemdReconcileArgs": "dependency systemd",
                        "pkgs.systemd": str(root / "tools"),
                        "pkgs.coreutils": "/usr",
                        "pkgs.git": "/usr",
                        "pkgs.jq": str(root / "tools"),
                        "caddyPackage": str(root / "tools"),
                        "guardUnitShell": "guard_unit=test-guard",
                        "lib.escapeShellArg planPath": shlex.quote(str(plan)),
                        "lib.escapeShellArg caddyActivePath": shlex.quote(str(root / "caddy.conf")),
                        "lib.escapeShellArg reconcilePendingPath": shlex.quote(str(root / "pending")),
                        "lib.escapeShellArg guardCurrentFile": shlex.quote(str(root / "guard")),
                        "lib.escapeShellArg guardStateDir": shlex.quote(str(root / "guard-state")),
                        'lib.escapeShellArg "${pkgs.systemd}/bin/systemctl"': shlex.quote(
                            str(root / "tools/bin/systemctl")
                        ),
                        "lib.escapeShellArg (toString v2Source)": shlex.quote(str(ROOT / "services")),
                        "lib.escapeShellArg historyRepoPath": shlex.quote(str(repo)),
                        "lib.escapeShellArg (builtins.dirOf desiredPath)": shlex.quote(str(root)),
                    }
                    # The Python command prefix is replaced, not a second
                    # implementation of transaction ordering or history recovery.
                    post_script = self.render(post, replacements).replace(str(root / "python/bin/python") + " ", "")
                    rollback_script = self.render(rollback, replacements).replace(
                        str(root / "python/bin/python") + " ", ""
                    )
                    rollback_script = rollback_script.replace(
                        '"${restore_args[@]}"', 'history_command "${restore_args[@]:1}"'
                    )
                    tools = root / "tools/bin"
                    tools.mkdir(parents=True)

                    def executable(name, body):
                        path = tools / name
                        path.write_text("#!/bin/bash\nset -euo pipefail\n" + body)
                        path.chmod(0o700)

                    executable(
                        "jq",
                        "exec "
                        + shlex.join(
                            [
                                sys.executable,
                                "-c",
                                "import json,sys;print(json.load(open(sys.argv[-1]))['desiredRevision'])",
                            ]
                        )
                        + ' "$@"\n',
                    )
                    recompile = root / "recompile.py"
                    recompile.write_text(
                        f"import sys,json,pathlib; sys.path.insert(0,{str(ROOT / 'services')!r}); import nas_v2_history as h; result=h.record_desired(authority=pathlib.Path({str(authority)!r}),repository=pathlib.Path({str(repo)!r})); pathlib.Path({str(plan)!r}).write_text(json.dumps({{'desiredRevision':result['head']}}))\n"
                    )
                    executable(
                        "systemctl",
                        'printf "%s\\n" "$*" >> "$LOG"\nif [[ "$1" == restart ]]; then '
                        + shlex.join([sys.executable, str(recompile)])
                        + '; exec bash "$POST"; fi\n',
                    )
                    executable("caddy", 'printf "caddy\\n" >> "$LOG"\n[[ "${FAIL_STAGE:-}" != caddy ]]\n')
                    prelude = f"""
dependency() {{ printf '%s\\n' "$1" >> "$LOG"; [[ "${{FAIL_STAGE:-}}" != "$1" ]]; }}
history_command() {{
  printf '%s\\n' "$1" >> "$LOG"
  [[ "${{FAIL_STAGE:-}}" != "$1" ]] || return 97
  {real_history} "$@"
}}
guard_command() {{ dependency cancel; }}
"""
                    post_script = post_script.replace(str(ROOT / "services/nas_guarded_apply.py"), "guard_command")
                    post_path = root / "post.sh"
                    post_path.write_text("set -euo pipefail\n" + prelude + post_script)
                    rollback_path = root / "rollback.sh"
                    rollback_path.write_text("set -euo pipefail\n" + prelude + rollback_script)
                    import os

                    env = {**os.environ, "LOG": str(root / "calls"), "POST": str(post_path), "FAIL_STAGE": stage}
                    result = subprocess.run(
                        ["bash", str(post_path)], env=env, capture_output=True, text=True, timeout=15
                    )
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    calls = (root / "calls").read_text().splitlines()
                    self.assertIn(stage, calls)
                    if stage in stages[:4]:
                        self.assertNotIn("mark-applied", calls)
                    env["FAIL_STAGE"] = "systemd"
                    compensation = subprocess.run(
                        ["bash", str(rollback_path)], env=env, capture_output=True, text=True, timeout=15
                    )
                    self.assertNotEqual(compensation.returncode, 0)
                    self.assertEqual(authority.read_bytes(), baseline)
                    self.assertFalse(history.history_status(authority=authority, repository=repo)["inSync"])
                    env.pop("FAIL_STAGE")
                    result = subprocess.run(
                        ["bash", str(rollback_path)], env=env, capture_output=True, text=True, timeout=15
                    )
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(authority.read_bytes(), baseline)
                    self.assertTrue(history.history_status(authority=authority, repository=repo)["inSync"])


if __name__ == "__main__":
    unittest.main()
