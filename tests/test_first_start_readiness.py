from __future__ import annotations

import os
import pathlib
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class FirstStartReadinessTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = pathlib.Path(self.directory.name)
        self.default = self.root / "first-run.json"
        self.state = self.root / "state.json"
        self.journal = self.root / "journal.json"

    def validate(self, path, *, owner: int | None = None):
        source = (ROOT / "modules/nas/config/install-readiness.nix").read_text()
        function = source.split("    check_file() {", 1)[1].split("    check_file ${", 1)[0]
        block = source.split("${lib.optionalString cfg.firstStart.enable ''", 1)[1].split("''}", 1)[0]
        script = "set -euo pipefail\ncheck_file() {" + function + block
        stat_command = shlex.quote(shutil.which("stat") or "stat")
        if owner is not None:
            script = (
                f"readiness_stat() {{ if [[ \"$2\" == %u ]]; then printf '%s\\n' {owner}; "
                f'else {stat_command} "$@"; fi; }}\n' + script
            )
            stat_command = "readiness_stat"
        for before, after in (
            ("${pkgs.coreutils}/bin/stat", stat_command),
            ("${lib.escapeShellArg cfg.firstStart.configFile}", shlex.quote(str(path))),
            ("/var/lib/nas-first-start/first-run.json", str(self.default)),
            ("/var/lib/nas-setup/state.json", str(self.state)),
            ("/var/lib/nas-setup/first-run-journal.json", str(self.journal)),
        ):
            script = script.replace(before, after)
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True)

    def test_missing_default_plan_is_allowed_before_setup(self):
        self.assertEqual(self.validate(self.default).returncode, 0)

    def test_missing_custom_plan_is_rejected(self):
        self.assertNotEqual(self.validate(self.root / "custom.json").returncode, 0)

    def test_missing_plan_after_setup_started_is_rejected(self):
        for marker in (self.state, self.journal):
            with self.subTest(marker=marker):
                marker.write_text("{}")
                self.assertNotEqual(self.validate(self.default).returncode, 0)
                marker.unlink()

    def test_existing_plan_keeps_file_policy(self):
        self.default.write_text("{}")
        self.default.chmod(0o666)
        result = self.validate(self.default)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be root-owned and not group/other writable", result.stderr)
        self.default.unlink()
        self.default.symlink_to(self.root / "missing")
        self.assertNotEqual(self.validate(self.default).returncode, 0)
        self.default.unlink()
        self.default.mkdir()
        self.assertNotEqual(self.validate(self.default).returncode, 0)

    @unittest.skipUnless(os.geteuid() == 0, "root-owned valid configuration requires root")
    def test_private_root_owned_plan_is_accepted(self):
        self.default.write_text("{}")
        self.default.chmod(0o600)
        self.assertEqual(self.validate(self.default).returncode, 0)

    def test_plan_mode_policy_independent_of_owner(self):
        self.default.write_text("{}")
        for mode, accepted in ((0o666, False), (0o600, True)):
            with self.subTest(mode=oct(mode)):
                self.default.chmod(mode)
                result = self.validate(self.default, owner=0)
                self.assertEqual(result.returncode == 0, accepted, result.stderr)
                if not accepted:
                    self.assertIn("must be root-owned and not group/other writable", result.stderr)

    def test_private_plan_with_nonroot_owner_is_rejected(self):
        self.default.write_text("{}")
        self.default.chmod(0o600)
        result = self.validate(self.default, owner=1000)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be root-owned and not group/other writable", result.stderr)
