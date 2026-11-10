"""Locked-boot browser surface: Caddy selection and the static unlock notice."""

from __future__ import annotations

import html.parser
import pathlib
import re
import subprocess
import tempfile
import textwrap
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
BOOTSTRAP_NIX = ROOT / "modules/nas/config/caddy-bootstrap.nix"
NOTICE = ROOT / "web/locked/index.html"


def nix_string(source: str, start_marker: str) -> str:
    """Return the dedented body of the Nix indented string opened after start_marker."""
    start = source.index("''\n", source.index(start_marker)) + 3
    match = re.compile(r"\n *'';").search(source, start)
    assert match is not None
    return textwrap.dedent(source[start : match.start()])


class SelectorHarness:
    """Run the shipped selector with fake systemctl/caddy and temporary state paths."""

    def __init__(self, root: pathlib.Path, *, reload_status: int = 0) -> None:
        self.root = root
        self.log = root / "calls.log"
        self.active = root / "caddy-active.conf"
        self.state = root / "state.json"
        self.secrets = root / "secrets"
        self.secrets.mkdir()
        bin_dir = root / "bin"
        bin_dir.mkdir()
        (bin_dir / "systemctl").write_text(
            "#!/bin/sh\n"
            f'echo "systemctl $*" >> "{self.log}"\n'
            'case "$1" in\n'
            "  is-active) exit 0 ;;\n"
            "  start) exit 1 ;;\n"
            "  *) exit 0 ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        (bin_dir / "caddy").write_text(
            f'#!/bin/sh\necho "caddy $* active=$(cat "{self.active}")" >> "{self.log}"\nexit {reload_status}\n',
            encoding="utf-8",
        )
        for tool in ("systemctl", "caddy"):
            (bin_dir / tool).chmod(0o755)
        substitutions = {
            "${activeCaddyPath}": str(self.active),
            "${managedPath}": str(root / "caddy-managed.conf"),
            "${planPath}": str(root / "plan.json"),
            "${desiredPath}": str(root / "services.yaml"),
            "${authorityLockPath}": str(root / "services.lock"),
            "${historyRepoPath}": str(root / "history.git"),
            "${bootstrapCaddyfile}": "BOOTSTRAP",
            "${lockedCaddyfile}": "LOCKED",
            "${lib.escapeShellArg fullCaddyImport}": "'import FULL'",
            "${lib.escapeShellArg selectorLockPath}": str(root / "selector.lock"),
            "${secretRoot}": str(self.secrets),
            "${caddyPackage}/bin/": "",
            "${runOptions}": "--config active",
            "${config.services.caddy.user}": "caddy",
            "${config.services.caddy.group}": "caddy",
            "/var/lib/nas-setup/state.json": str(self.state),
        }
        script = nix_string(BOOTSTRAP_NIX.read_text(encoding="utf-8"), 'writeShellScript "nas-caddy-bootstrap-select"')
        script = re.sub(r"\$\{pkgs\.[a-z-]+\}/bin/", "", script)
        for nix, value in substitutions.items():
            script = script.replace(nix, value)
        if "${" in script:
            raise AssertionError(f"unsubstituted Nix interpolation: {script[script.index('${') :][:80]}")
        self.script = root / "select.sh"
        self.script.write_text(script, encoding="utf-8")
        self.path = f"{bin_dir}:/usr/bin:/bin"

    def run(self, *, setup_complete: bool, unlocked: bool) -> subprocess.CompletedProcess[str]:
        self.state.unlink(missing_ok=True)
        (self.secrets / "ready").unlink(missing_ok=True)
        self.log.write_text("", encoding="utf-8")
        if setup_complete:
            self.state.write_text("{}", encoding="utf-8")
        if unlocked:
            (self.secrets / "ready").write_text("", encoding="utf-8")
        return subprocess.run(
            ["bash", str(self.script)],
            env={"PATH": self.path},
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    def calls(self) -> list[str]:
        return self.log.read_text(encoding="utf-8").splitlines()


class LockedSelectionTests(unittest.TestCase):
    def harness(self, **kwargs: int) -> SelectorHarness:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return SelectorHarness(pathlib.Path(temporary.name), **kwargs)

    def test_completed_setup_without_secrets_loads_only_the_locked_notice(self) -> None:
        harness = self.harness()
        completed = harness.run(setup_complete=True, unlocked=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(harness.active.read_text(encoding="utf-8"), "import LOCKED\n")
        calls = harness.calls()
        self.assertIn("caddy reload --config active --force active=import LOCKED", calls)
        self.assertFalse(any("BOOTSTRAP" in call for call in calls), "bootstrap routes must never load while locked")
        self.assertFalse(any("start" in call.split()[:2] for call in calls), "locked boot must not reconcile")

    def test_first_start_keeps_the_bootstrap_routes(self) -> None:
        harness = self.harness()
        for unlocked in (False, True):
            with self.subTest(unlocked=unlocked):
                completed = harness.run(setup_complete=False, unlocked=unlocked)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(harness.active.read_text(encoding="utf-8"), "import BOOTSTRAP\n")
                self.assertFalse(any("LOCKED" in call for call in harness.calls()))

    def test_unlocked_appliance_never_selects_the_locked_notice(self) -> None:
        harness = self.harness()
        harness.run(setup_complete=True, unlocked=True)
        calls = harness.calls()
        self.assertIn("systemctl start nas-managed-services-reconcile.service", calls)
        self.assertFalse(any("LOCKED" in call for call in calls))

    def test_failed_locked_reload_stops_caddy(self) -> None:
        harness = self.harness(reload_status=1)
        completed = harness.run(setup_complete=True, unlocked=False)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("systemctl stop --no-block caddy.service", harness.calls())


class NoticeParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[str] = []
        self.attributes: list[tuple[str, str | None]] = []
        self.text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        self.attributes.extend(attrs)

    def handle_data(self, data: str) -> None:
        self.text.append(data)


class LockedNoticeContentTests(unittest.TestCase):
    def test_notice_is_static_guidance_without_management_actions(self) -> None:
        parser = NoticeParser()
        parser.feed(NOTICE.read_text(encoding="utf-8"))
        for tag in ("script", "form", "input", "button", "iframe", "a", "link", "img"):
            self.assertNotIn(tag, parser.tags, f"locked notice must not contain <{tag}>")
        self.assertFalse([name for name, _value in parser.attributes if name.startswith("on")])
        self.assertIn(("id", "nas-locked"), parser.attributes)
        text = " ".join(" ".join(parser.text).split())
        self.assertIn("sudo nas-secrets activate", text)
        self.assertIn("local recovery administrator", text)
        self.assertIn("SSH with a provisioned recovery key", text)

    def test_locked_configuration_proxies_nothing(self) -> None:
        locked = nix_string(BOOTSTRAP_NIX.read_text(encoding="utf-8"), 'writeText "locked-caddyfile"')
        self.assertNotIn("reverse_proxy", locked)
        self.assertNotIn("caddyForwardAuth", locked)
        self.assertNotIn("redir", locked)
        self.assertEqual(locked.count("handle"), 1, "one catch-all handle serves every path")
        self.assertIn("root * ${lockedNotice}/share/nas-locked", locked)
        self.assertIn("rewrite * /index.html", locked)
        self.assertIn("status 503", locked)
        self.assertIn("form-action 'none'", locked)
        self.assertIn('Cache-Control "no-store"', locked)
        self.assertIn("${caddySiteHeaders}", locked)


if __name__ == "__main__":
    unittest.main()
