from __future__ import annotations

import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class V2SecretLifecycleTests(unittest.TestCase):
    def run_stop(self, *, member_stuck: bool) -> tuple[subprocess.CompletedProcess[str], pathlib.Path, str]:
        source = (ROOT / "modules/nas/internal/secret-tools.nix").read_text(encoding="utf-8")
        stop = source.split("command_stop() {", 1)[1].split("command_check_authentik_token() {", 1)[0]
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory)
        root = pathlib.Path(directory) / "secrets"
        root.mkdir()
        (root / "ready").touch()
        (root / "credential").touch()
        log = pathlib.Path(directory) / "systemctl.log"
        # The target stop returns while its PartOf member is still stopping;
        # only the member's own stop job observes that it is down.
        script = (
            'set -euo pipefail\nsecret_root="$1"\nlog="$2"\nstuck="$3"\n'
            "acquire_lock() { :; }\n"
            "sudo() {\n"
            '  if [[ "$1" == systemctl ]]; then\n'
            "    shift\n"
            '    printf "%s\\n" "$*" >> "$log"\n'
            '    [[ ! -e "$secret_root/ready" ]] || return 91\n'
            '    [[ -e "$secret_root/credential" ]] || return 92\n'
            '    case "$1" in\n'
            "      show) echo nas-v2-app.service copyparty.service ;;\n"
            '      stop) [[ "$*" != *nas-v2-app.service* || "$stuck" != 1 ]] ;;\n'
            '      is-active) [[ "$stuck" == 1 && "$*" == *nas-v2-app.service* ]] ;;\n'
            "    esac\n"
            '  else "$@"; fi\n'
            "}\n"
            f"source {ROOT / 'scripts/lib/nas-secret-transaction.sh'}\n"
            "command_stop() {" + stop + "\ncommand_stop\n"
        )
        result = subprocess.run(
            ["bash", "-c", script, "stop-test", str(root), str(log), "1" if member_stuck else "0"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result, root, log.read_text(encoding="utf-8")

    def test_stop_revokes_readiness_and_waits_for_members_before_removing_secrets(self) -> None:
        result, root, log = self.run_stop(member_stuck=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(root.exists())
        self.assertEqual(
            log.splitlines(),
            [
                "stop nas-protected-services.target",
                "show --property=ConsistsOf --value -- nas-protected-services.target",
                "stop -- nas-v2-app.service copyparty.service",
            ],
        )

    def test_stop_keeps_secrets_while_a_protected_member_is_still_running(self) -> None:
        result, root, _log = self.run_stop(member_stuck=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("still active: nas-v2-app.service", result.stderr)
        self.assertTrue((root / "credential").exists())
        self.assertFalse((root / "ready").exists())

    def test_secret_activation_remains_keepass_backed_and_transactional(self) -> None:
        source = (ROOT / "modules/nas/internal/secret-tools.nix").read_text(encoding="utf-8")
        activate = source.split("command_activate() (", 1)[1].split("command_status() {", 1)[0]

        self.assertIn("prompt_unlock", activate)
        self.assertIn("get_secret authentik-secret-key", activate)
        self.assertIn("nas_secret_tx_swap", activate)
        self.assertIn("nas_secret_tx_commit", activate)
        self.assertIn("kp_args() {", source)
        self.assertIn("get_secret() {", source)

    def test_secret_activation_validates_platform_substrate_not_copyparty(self) -> None:
        source = (ROOT / "modules/nas/internal/secret-tools.nix").read_text(encoding="utf-8")
        activate = source.split("command_activate() (", 1)[1].split("command_status() {", 1)[0]

        self.assertIn("authentik.service authentik-worker.service caddy.service", activate)
        self.assertNotIn("/run/copyparty/http.sock", activate)
        # Workload recovery is exercised end to end by
        # test_v2_secret_activation_recovery; activation keeps no unit list.
        self.assertNotIn("copyparty.service", activate)
        self.assertNotIn("gated_unit", activate)

    def test_discarded_generation_helpers_do_not_return(self) -> None:
        source = (ROOT / "modules/nas/internal/secret-tools.nix").read_text(encoding="utf-8")

        self.assertNotIn("nas-secret-stage-copyparty", source)
        self.assertNotIn("nas-secret-stage-authentik", source)
        self.assertNotIn("nas-keepass-validate", source)
        self.assertNotIn("nas-secret-fault-test", source)

    def test_authentik_token_check_accepts_retired_bootstrap_authority(self) -> None:
        source = (ROOT / "modules/nas/internal/secret-tools.nix").read_text(encoding="utf-8")
        check = source.split("command_check_authentik_token() {", 1)[1].split("command_set_authentik_token() {", 1)[0]

        self.assertIn("if ! has_secret authentik-bootstrap-token; then", check)
        self.assertIn("Authentik bootstrap token is retired", check)
        self.assertIn('if [[ "$bootstrap" == "$api" ]]', check)


if __name__ == "__main__":
    unittest.main()
