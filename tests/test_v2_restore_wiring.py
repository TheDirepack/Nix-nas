from __future__ import annotations

import pathlib
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
ZFS_ROOT = "/tank"
LOCAL_REPOSITORY = "/tank/backups/restic-system"
REMOTE_REPOSITORY = "rclone:gdrive:nas-backup"


class V2RestoreWiringTests(unittest.TestCase):
    def test_restore_verification_is_resource_oriented(self):
        storage = (ROOT / "modules/nas/config/storage-monitoring.nix").read_text(encoding="utf-8")

        self.assertIn("nas_v2_backup.py", storage)
        self.assertNotIn("nas_v2_backup_verify.py", storage)
        self.assertIn("--inventory ${lib.escapeShellArg v2BackupInventory}", storage)
        self.assertIn('--restore-root "$restore_root"', storage)
        self.assertIn("--pg-restore ${config.services.postgresql.package}/bin/pg_restore", storage)

        for application_specific_fragment in (
            "django_migrations",
            "authentik_core_user",
            '"$staged"/copyparty/*.db',
            "syncthingConfigDir",
            "ET.parse",
            "pg_ctl",
            "authentik_verify",
        ):
            with self.subTest(fragment=application_specific_fragment):
                self.assertNotIn(application_specific_fragment, storage)

    def test_verifier_has_no_application_name_branches(self):
        verifier = (ROOT / "services/nas_v2_backup.py").read_text(encoding="utf-8")
        for application_name in ("authentik", "copyparty", "syncthing", "vaultwarden"):
            with self.subTest(application=application_name):
                self.assertNotIn(application_name, verifier.lower())

    def test_restore_verification_fails_without_restored_zfs_control_directory(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            with_control = root / "with-control"
            (with_control / "tank" / "nas-control").mkdir(parents=True)
            without_control = root / "without-control"
            without_control.mkdir()

            # Positive control: an otherwise complete restore passes only because
            # the restored dataset path exists.
            passed = self.run_restore_verify(root, LOCAL_REPOSITORY, with_control, zfs_root=ZFS_ROOT)
            self.assertEqual(passed.returncode, 0, passed.stdout + passed.stderr)
            self.assertIn('"resources"', passed.stdout)
            self.assertEqual(passed.stderr, "")

            # A restore that recreated only the live compatibility symlink target
            # (/var/lib/nas-control) is not a valid recovery: the dataset path
            # under the restore root must exist.
            failed = self.run_restore_verify(root, LOCAL_REPOSITORY, without_control, zfs_root=ZFS_ROOT)
            self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
            # The restic restore and resource verification both completed; the
            # non-zero exit comes from the restored control-directory check.
            self.assertIn('"resources"', failed.stdout)
            self.assertEqual(failed.stderr, "")

    def test_remote_rclone_restore_environment_fails_closed(self):
        # restic requires the rclone executable and RCLONE_CONFIG for an
        # `rclone:` repository. The restore-verify unit declares neither, so a
        # remote restore verification can only fail; it must never report
        # success for a restore it could not perform.
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            complete = root / "complete"
            (complete / "tank" / "nas-control").mkdir(parents=True)
            result = self.run_restore_verify(root, REMOTE_REPOSITORY, complete, zfs_root=ZFS_ROOT)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("rclone", result.stderr)
            self.assertNotIn('"resources"', result.stdout)

    def run_restore_verify(
        self,
        root: pathlib.Path,
        repository: str,
        restored_tree: pathlib.Path,
        *,
        zfs_root: str,
    ) -> subprocess.CompletedProcess[str]:
        tools = root / "tools"
        tools.mkdir(exist_ok=True)
        coreutils = self.link_tools(tools / "coreutils", ("cp", "df", "install", "mkdir", "rm", "tail", "tr"))
        python_bin = tools / "python"
        (python_bin / "bin").mkdir(parents=True, exist_ok=True)
        (python_bin / "bin" / "python3").unlink(missing_ok=True)
        (python_bin / "bin" / "python3").symlink_to(sys.executable)
        postgresql = tools / "postgresql"
        (postgresql / "bin").mkdir(parents=True, exist_ok=True)
        pg_restore = postgresql / "bin" / "pg_restore"
        pg_restore.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        pg_restore.chmod(0o700)
        restic = tools / "restic"
        bash = shutil.which("bash")
        assert bash is not None, "host tool unavailable: bash"
        restic.write_text(
            f"#!{bash}\n"
            "set -euo pipefail\n"
            'printf \'%s\\n\' "$*" >> "$RESTIC_LOG"\n'
            "repo=''\n"
            "target=''\n"
            "while [ $# -gt 0 ]; do\n"
            "  case $1 in\n"
            "    --repo) repo=$2; shift 2 ;;\n"
            "    --target) target=$2; shift 2 ;;\n"
            "    *) shift ;;\n"
            "  esac\n"
            "done\n"
            "case $repo in\n"
            "  rclone:*)\n"
            "    command -v rclone >/dev/null 2>&1 || "
            "{ printf 'restic: exec: rclone: executable file not found in $PATH\\n' >&2; exit 1; }\n"
            '    [ -n "${RCLONE_CONFIG:-}" ] || '
            "{ printf 'restic: rclone: RCLONE_CONFIG is unset\\n' >&2; exit 1; }\n"
            "    ;;\n"
            "esac\n"
            '[ -n "$target" ]\n'
            'mkdir -p "$target"\n'
            'cp -a "$RESTIC_FIXTURE_TREE/." "$target/"\n',
            encoding="utf-8",
        )
        restic.chmod(0o700)
        password_file = root / "restic-password"
        password_file.write_text("fixture\n", encoding="utf-8")
        inventory = root / "backup-resources.json"
        inventory.write_text('{"schemaVersion": 1, "resources": []}\n', encoding="utf-8")
        verify_root = root / "verify"
        script = self.render_restore_verify_script(
            verify_root=verify_root,
            password_file=password_file,
            restic=shlex.join([str(restic), "--repo", repository]),
            inventory=inventory,
            coreutils=coreutils,
            python_bin=python_bin,
            postgresql=postgresql,
            zfs_root=zfs_root,
        )
        script_path = root / "restore-verify.sh"
        script_path.write_text(script, encoding="utf-8")
        bash = shutil.which("bash")
        assert bash is not None, "host tool unavailable: bash"
        # Only fixture tools are visible so an ambient rclone on the host cannot
        # make a remote restore appear to work.
        environment = {
            "PATH": str(coreutils / "bin"),
            "RESTIC_LOG": str(root / "restic.log"),
            "RESTIC_FIXTURE_TREE": str(restored_tree),
            "LC_ALL": "C",
        }
        return subprocess.run(
            [bash, str(script_path)],
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    @staticmethod
    def dedent(body: str) -> str:
        """Strip the common indentation Nix removes from an indented string."""
        lines = body.splitlines()
        indents = [len(line) - len(line.lstrip()) for line in lines if line.strip()]
        common = min(indents) if indents else 0
        return "\n".join(line[common:] if line.strip() else "" for line in lines)

    @staticmethod
    def link_tools(directory: pathlib.Path, commands: tuple[str, ...]) -> pathlib.Path:
        bin_dir = directory / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        for command in commands:
            host_tool = shutil.which(command)
            assert host_tool is not None, f"host tool unavailable: {command}"
            (bin_dir / command).unlink(missing_ok=True)
            (bin_dir / command).symlink_to(host_tool)
        return directory

    def render_restore_verify_script(
        self,
        *,
        verify_root: pathlib.Path,
        password_file: pathlib.Path,
        restic: str,
        inventory: pathlib.Path,
        coreutils: pathlib.Path,
        python_bin: pathlib.Path,
        postgresql: pathlib.Path,
        zfs_root: str,
    ) -> str:
        storage = (ROOT / "modules/nas/config/storage-monitoring.nix").read_text(encoding="utf-8")
        section = storage.split("systemd.services.nas-backup-restore-verify", 1)[1]
        body = section.split("script = ''", 1)[1].split("\n      '';", 1)[0]
        body = self.dedent(body)
        replacements = {
            "lib.escapeShellArg restoreVerifyPath": shlex.quote(str(verify_root)),
            "toString cfg.backup.stagingMinFreeBytes": "0",
            "lib.escapeShellArg cfg.backup.passwordFile": shlex.quote(str(password_file)),
            "resticCommand": restic,
            "lib.escapeShellArg v2BackupInventory": shlex.quote(str(inventory)),
            "v2Source": str(SERVICES),
            "config.services.postgresql.package": shlex.quote(str(postgresql)),
            "pkgs.coreutils": str(coreutils),
            "pkgs.python3": str(python_bin),
            "cfg.zfsRoot": zfs_root,
        }
        for key in sorted(replacements, key=len, reverse=True):
            body = body.replace("${" + key + "}", replacements[key])
        self.assertNotIn("${", body)
        self.assertIn(f"{postgresql}/bin/pg_restore", body)
        return "set -euo pipefail\n" + body


if __name__ == "__main__":
    unittest.main()
