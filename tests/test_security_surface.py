from __future__ import annotations

import importlib.util
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))
sys.path.insert(0, str(ROOT / "tests"))
from adversarial_payloads import CONTROL_PAYLOADS, PATH_PAYLOADS, SHELL_PAYLOADS, SQL_PAYLOADS, XSS_PAYLOADS

import nas_common as common
import nas_cockpit_api as api
import nas_setup_config as setup_config
import nas_state as state


class SecuritySurfaceTests(unittest.TestCase):
    def test_static_security_scanner_passes_repository(self):
        result = subprocess.run(
            [sys.executable, "scripts/security-static-scan.py"], cwd=ROOT, text=True, capture_output=True
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_static_scanner_detects_representative_python_sinks(self):
        spec = importlib.util.spec_from_file_location(
            "security_static_scan", ROOT / "scripts" / "security-static-scan.py"
        )
        assert spec and spec.loader
        scanner = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = scanner
        spec.loader.exec_module(scanner)
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "bad.py"
            path.write_text(
                "import marshal, pickle, subprocess, tempfile\n"
                "eval(user)\n"
                "subprocess.run(cmd, shell=True)\n"
                "c.execute(f'SELECT {user}')\n"
                "query = f'SELECT * FROM users WHERE name={user}'\n"
                "query_alias = query\n"
                "c.execute(query_alias)\n"
                "pickle.loads(blob)\n"
                "marshal.loads(blob)\n"
                "tempfile.mktemp()\n"
                "archive.extractall(dst)\n"
            )
            rules = {finding.rule for finding in scanner.scan_python(path)}
        self.assertEqual(
            {
                "code-command-injection",
                "shell-injection",
                "sql-injection",
                "unsafe-deserialization",
                "insecure-temporary-file",
                "archive-extraction",
            },
            rules,
        )

    def test_static_scanner_detects_generated_nix_shell_injection_sinks(self):
        spec = importlib.util.spec_from_file_location(
            "security_static_scan_nix", ROOT / "scripts" / "security-static-scan.py"
        )
        assert spec and spec.loader
        scanner = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = scanner
        spec.loader.exec_module(scanner)
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "bad.nix"
            path.write_text(
                "text = ''\n  eval \"$user_command\"\n  sqlite3 \"$source\" \".backup '$destination'\"\n'';\n",
                encoding="utf-8",
            )
            rules = {finding.rule for finding in scanner.scan_nix(path)}
        self.assertIn("generated-shell-eval", rules)
        self.assertIn("sqlite-meta-command-injection", rules)

    def test_static_scanner_detects_shell_tracing_that_can_leak_secrets(self):
        spec = importlib.util.spec_from_file_location(
            "security_static_scan_xtrace", ROOT / "scripts" / "security-static-scan.py"
        )
        assert spec and spec.loader
        scanner = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = scanner
        spec.loader.exec_module(scanner)
        with tempfile.TemporaryDirectory() as tmp:
            shell = pathlib.Path(tmp) / "bad.sh"
            shell.write_text("set -x\nprintf '%s\\n' \"$secret\"\n", encoding="utf-8")
            shell_rules = {finding.rule for finding in scanner.scan_shell(shell)}
            self.assertIn("shell-xtrace-secret-leak", shell_rules)

            combined = pathlib.Path(tmp) / "combined.sh"
            combined.write_text("set -euxo pipefail\n", encoding="utf-8")
            self.assertIn(
                "shell-xtrace-secret-leak",
                {finding.rule for finding in scanner.scan_shell(combined)},
            )

            safe = pathlib.Path(tmp) / "safe.sh"
            safe.write_text("set -euo pipefail\nset +x\n", encoding="utf-8")
            self.assertNotIn(
                "shell-xtrace-secret-leak",
                {finding.rule for finding in scanner.scan_shell(safe)},
            )

            nix = pathlib.Path(tmp) / "bad.nix"
            nix.write_text("text = ''\n  bash -x ./secret-helper.sh\n'';\n", encoding="utf-8")
            self.assertIn(
                "generated-shell-xtrace-secret-leak",
                {finding.rule for finding in scanner.scan_nix(nix)},
            )

    def test_static_scanner_detects_additional_browser_execution_sinks(self):
        spec = importlib.util.spec_from_file_location(
            "security_static_scan_web", ROOT / "scripts" / "security-static-scan.py"
        )
        assert spec and spec.loader
        scanner = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = scanner
        spec.loader.exec_module(scanner)
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "bad.js"
            path.write_text(
                "frame.srcdoc = attacker;\n"
                "node.setAttribute('onclick', attacker);\n"
                "setTimeout('globalThis.pwned=1', 1);\n",
                encoding="utf-8",
            )
            rules = {finding.rule for finding in scanner.scan_web(path)}
        self.assertEqual(
            {"dom-xss-srcdoc", "dom-xss-event-attribute", "javascript-string-timer"},
            rules,
        )

    def test_static_scanner_does_not_confuse_nix_eval_with_shell_eval(self):
        spec = importlib.util.spec_from_file_location(
            "security_static_scan_eval_position", ROOT / "scripts" / "security-static-scan.py"
        )
        assert spec and spec.loader
        scanner = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = scanner
        spec.loader.exec_module(scanner)
        with tempfile.TemporaryDirectory() as tmp:
            safe = pathlib.Path(tmp) / "safe.sh"
            safe.write_text("nix eval --raw .#value\nif nix eval --raw .#other; then :; fi\n", encoding="utf-8")
            self.assertNotIn("shell-eval", {finding.rule for finding in scanner.scan_shell(safe)})
            bad = pathlib.Path(tmp) / "bad.sh"
            bad.write_text('eval "$user_command"\nfalse || eval "$fallback"\n', encoding="utf-8")
            self.assertEqual(
                [finding.rule for finding in scanner.scan_shell(bad)].count("shell-eval"),
                2,
            )

    def test_static_scanner_detects_shell_format_and_tempfile_hazards(self):
        spec = importlib.util.spec_from_file_location(
            "security_static_scan_shell", ROOT / "scripts" / "security-static-scan.py"
        )
        assert spec and spec.loader
        scanner = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = scanner
        spec.loader.exec_module(scanner)
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "bad.sh"
            path.write_text('printf "$user"\nmktemp -u /tmp/nas.XXXXXX\n', encoding="utf-8")
            rules = {finding.rule for finding in scanner.scan_shell(path)}
        self.assertEqual({"shell-format-string", "insecure-temporary-file"}, rules)

    def test_copyparty_backup_uses_sqlite_backup_api_not_meta_commands(self):
        source = (ROOT / "modules" / "nas" / "config" / "managed-services-backup-resources.nix").read_text(
            encoding="utf-8"
        )
        self.assertIn("source_db.backup(destination_db)", source)
        self.assertIn('sqlite3.connect(f"file:{source}?mode=ro", uri=True)', source)
        self.assertNotIn(".backup '$destination'", source)
        self.assertNotIn(".restore '$source'", source)

    def test_portal_explicitly_escapes_identity_values(self):
        portal = (ROOT / "web" / "portal" / "index.html").read_text(encoding="utf-8")
        self.assertIn('placeholder "http.request.header.Remote-Name" | html', portal)
        self.assertIn('placeholder "http.request.header.Remote-User" | urlquery', portal)
        self.assertNotIn('placeholder "http.request.header.Remote-Name"}}</strong>', portal)

    def test_nas_alert_rejects_crlf_in_header_value(self):
        source = (ROOT / "modules" / "nas" / "internal" / "maintenance-tools.nix").read_text(encoding="utf-8")
        self.assertIn("Alert titles must be one line and at most 200 characters.", source)
        self.assertIn("$'\\r'", source)
        self.assertIn("$'\\n'", source)

    def test_control_characters_never_grant_admin(self):
        for raw in CONTROL_PAYLOADS:
            with self.subTest(raw=raw):
                self.assertEqual(common.split_groups(raw), set())
                self.assertFalse(common.account_is_admin(common.split_groups(raw)))

    def test_injection_payloads_are_rejected_as_v2_service_ids(self):
        for raw in SHELL_PAYLOADS + SQL_PAYLOADS + XSS_PAYLOADS + PATH_PAYLOADS:
            with (
                self.subTest(raw=raw),
                mock.patch.object(api, "acquire_operation") as lock,
                mock.patch.object(api, "run") as run,
            ):
                with self.assertRaises(api.ApiError):
                    api.set_managed_service(raw, "always")
                lock.assert_not_called()
                run.assert_not_called()

    def test_archive_traversal_payloads_cannot_escape_posix_staging_root(self):
        for raw in PATH_PAYLOADS:
            with self.subTest(raw=raw):
                try:
                    accepted = state.safe_member_name(raw)
                except state.StateError:
                    continue
                self.assertFalse(accepted.is_absolute())
                self.assertNotIn("..", accepted.parts)

    def test_setup_storage_does_not_accept_shellish_devices(self):
        for raw in SHELL_PAYLOADS:
            config = {
                "schemaVersion": 2,
                "storage": {"createPool": True, "devices": [raw]},
                "accounts": [],
                "services": {},
            }
            with self.subTest(raw=raw), self.assertRaises(setup_config.SetupError):
                setup_config.normalize_config(config)


if __name__ == "__main__":
    unittest.main()
