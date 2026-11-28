"""Locked-boot browser surface: Caddy selection, the gated unlock page, and the fallback notice."""

from __future__ import annotations

import html.parser
import json
import pathlib
import re
import subprocess
import tempfile
import textwrap
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
BOOTSTRAP_NIX = ROOT / "modules/nas/config/caddy-bootstrap.nix"
NOTICE = ROOT / "web/locked/index.html"
UNLOCK_PAGE = ROOT / "web/unlock/index.html"
UNLOCK_SCRIPT = ROOT / "web/unlock/unlock.js"


def nix_string(source: str, start_marker: str) -> str:
    """Return the dedented body of the Nix indented string opened after start_marker."""
    start = source.index("''\n", source.index(start_marker)) + 3
    match = re.compile(r"\n *'';").search(source, start)
    assert match is not None
    return textwrap.dedent(source[start : match.start()])


class SelectorHarness:
    """Run the shipped selector with fake systemctl/caddy and temporary state paths."""

    def __init__(self, root: pathlib.Path, *, reload_status: int = 0, reconcile_status: int = 1) -> None:
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
            f"  start) exit {reconcile_status} ;;\n"
            "  *) exit 0 ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        (bin_dir / "caddy").write_text(
            "#!/bin/sh\n"
            f'echo "caddy $* active=$(cat "{self.active}")" >> "{self.log}"\n'
            f'if [ "$1" = reload ]; then exit {reload_status}; fi\n'
            "exit 0\n",
            encoding="utf-8",
        )
        # Validation runs as the Caddy user with owned scratch directories; the
        # fakes keep the directory layout without needing root.
        (bin_dir / "install").write_text(
            '#!/bin/sh\nset -e\nwhile [ $# -gt 0 ]; do case "$1" in -d) shift ;; -m|-o|-g) shift 2 ;; '
            '*) mkdir -p "$1"; shift ;; esac; done\n',
            encoding="utf-8",
        )
        (bin_dir / "runuser").write_text(
            '#!/bin/sh\nwhile [ "$1" != "--" ]; do shift; done\nshift\nexec "$@"\n', encoding="utf-8"
        )
        for tool in ("systemctl", "caddy", "install", "runuser"):
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

    def publish_generated_revision(self) -> None:
        """Create the applied desired-state revision the selector requires for full routes."""
        desired = self.root / "services.yaml"
        desired.write_text("services: {}\n", encoding="utf-8")
        (self.root / "services.lock").write_text("", encoding="utf-8")
        (self.root / "caddy-managed.conf").write_text("(nas_v2_managed_paths) {\n}\n", encoding="utf-8")
        git = ["git", "--git-dir", str(self.root / "history.git"), "--work-tree", str(self.root)]
        environment = {
            "PATH": "/usr/bin:/bin",
            "GIT_AUTHOR_NAME": "test",
            "GIT_AUTHOR_EMAIL": "test@example.test",
            "GIT_COMMITTER_NAME": "test",
            "GIT_COMMITTER_EMAIL": "test@example.test",
        }
        subprocess.run(
            ["git", "init", "--quiet", "--bare", str(self.root / "history.git")], check=True, env=environment
        )
        subprocess.run([*git, "add", "services.yaml"], check=True, env=environment)
        subprocess.run([*git, "commit", "--quiet", "-m", "desired"], check=True, env=environment)
        revision = subprocess.run(
            [*git, "rev-parse", "HEAD"], check=True, capture_output=True, text=True, env=environment
        ).stdout.strip()
        subprocess.run([*git, "update-ref", "refs/nas/applied", revision], check=True, env=environment)
        (self.root / "plan.json").write_text(json.dumps({"desiredRevision": revision}), encoding="utf-8")

    def calls(self) -> list[str]:
        return self.log.read_text(encoding="utf-8").splitlines()


class LockedSelectionTests(unittest.TestCase):
    def harness(self, **kwargs: int) -> SelectorHarness:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return SelectorHarness(pathlib.Path(temporary.name), **kwargs)

    def test_completed_setup_without_secrets_loads_the_locked_configuration(self) -> None:
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

    def test_unlocked_appliance_selects_the_full_configuration(self) -> None:
        harness = self.harness(reconcile_status=0)
        harness.publish_generated_revision()
        completed = harness.run(setup_complete=True, unlocked=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(harness.active.read_text(encoding="utf-8"), "import FULL\n")
        calls = harness.calls()
        self.assertIn("systemctl start nas-managed-services-reconcile.service", calls)
        self.assertIn("caddy reload --config active --force active=import FULL", calls)
        self.assertFalse(any("LOCKED" in call for call in calls))

    def test_unlocked_appliance_without_a_current_revision_falls_back_to_bootstrap(self) -> None:
        harness = self.harness(reconcile_status=1)
        completed = harness.run(setup_complete=True, unlocked=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(harness.active.read_text(encoding="utf-8"), "import BOOTSTRAP\n")
        self.assertFalse(any("LOCKED" in call for call in harness.calls()))

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
    def test_fallback_notice_is_static_guidance_without_management_actions(self) -> None:
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

    def test_unlock_page_posts_only_the_password_to_its_own_api(self) -> None:
        parser = NoticeParser()
        parser.feed(UNLOCK_PAGE.read_text(encoding="utf-8"))
        self.assertFalse([name for name, _value in parser.attributes if name.startswith("on")])
        self.assertIn(("src", "unlock.js"), parser.attributes)
        self.assertIn(("type", "password"), parser.attributes)
        self.assertNotIn("style", parser.tags, "the unlock page CSP forbids inline styles")
        script = UNLOCK_SCRIPT.read_text(encoding="utf-8")
        self.assertEqual(re.findall(r'fetch\("([^"]+)"', script), ["/unlock/api/status", "/unlock/api/activate"])
        self.assertIn("JSON.stringify({password})", script)
        self.assertIn('input.value = "";', script)
        for forbidden in ("localStorage", "sessionStorage", "innerHTML", "eval(", "document.cookie"):
            self.assertNotIn(forbidden, script)

    def locked(self) -> str:
        return nix_string(BOOTSTRAP_NIX.read_text(encoding="utf-8"), 'writeText "locked-caddyfile"')

    def test_locked_configuration_proxies_only_sign_in_and_the_gated_unlock_api(self) -> None:
        locked = self.locked()
        self.assertEqual(
            sorted(set(re.findall(r"reverse_proxy (\$\{[^}]+\}|\S+)", locked.replace("127.0.0.1:", "")))),
            ["${toString authentikOutpostPort}", "${toString authentikPort}", "unix//run/nas-unlock/unlock.sock"],
        )
        for absent in ("/console", "/setup", "nas-setup-api", "nas-cockpit-sso", "caddy_config", "/shares"):
            self.assertNotIn(absent, locked)
        self.assertIn("redir * /unlock/ 303", locked)
        self.assertIn('Cache-Control "no-store"', locked)
        self.assertIn("${caddySiteHeaders}", locked)

    def test_unlock_routes_require_forward_auth_and_nas_admin(self) -> None:
        locked = self.locked()
        for route in ("handle /unlock/api/* {", "handle /unlock/* {"):
            block = locked[locked.index(route) :]
            block = block[: block.index("\n  }\n")]
            with self.subTest(route=route):
                auth = block.index("${caddyForwardAuth}")
                gate = block.index("not header_regexp Remote-Groups ${adminGroupPattern}")
                self.assertLess(auth, gate)
                self.assertIn("respond @missingUnlock", block)
                served = block.index("reverse_proxy") if "reverse_proxy" in block else block.index("file_server")
                self.assertLess(gate, served)
        source = BOOTSTRAP_NIX.read_text(encoding="utf-8")
        self.assertIn('adminGroupPattern = "(^|[|,][[:space:]]*)nas_admin([[:space:]]*[|,]|$)";', source)

    def test_authentik_interfaces_are_withheld_until_unlock(self) -> None:
        locked = self.locked()
        interfaces = locked.index("handle @authentikInterfaces {")
        self.assertLess(interfaces, locked.index("handle @authentikUi {"), "the interface redirect must win")
        self.assertIn("if/admin*", locked)
        self.assertIn("if/user*", locked)

    def test_upstream_failures_fall_back_to_the_static_notice(self) -> None:
        locked = self.locked()
        errors = locked[locked.index("handle_errors 502 503 504 {") :]
        self.assertIn("root * ${lockedNotice}/share/nas-locked", errors)
        self.assertIn("rewrite * /index.html", errors)
        self.assertIn("status 503", errors)
        self.assertIn("disable_canonical_uris", errors)
        self.assertIn("form-action 'none'", errors)

    def test_unlock_page_csp_forbids_inline_and_foreign_code(self) -> None:
        locked = self.locked()
        csp = re.search(r'handle /unlock/\* \{.*?Content-Security-Policy "([^"]+)"', locked, re.S)
        assert csp is not None
        policy = csp.group(1)
        self.assertIn("default-src 'none'", policy)
        self.assertIn("script-src 'self'", policy)
        self.assertIn("frame-ancestors 'none'", policy)
        self.assertNotIn("unsafe", policy)


if __name__ == "__main__":
    unittest.main()
