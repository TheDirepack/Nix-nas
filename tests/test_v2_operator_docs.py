"""Guard operator documentation against retired V1 capability instructions.

V2's service seed declares capability IDs, Authentik owns assignments, and
Caddy checks application.<service>.<capability> groups. Keep user instructions
aligned with that contract as it evolves.
"""

from pathlib import Path
import re
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "src"

CAPABILITY_DOCS = {
    "permissions.md",
    "admin/authentik.md",
    "admin/accounts.md",
    "users/applications.md",
}
EXPECTED_DEFAULT_GROUPS = {
    "application.copyparty.files",
    "application.copyparty.webdav",
    "application.syncthing.access",
    "application.vaultwarden.access",
}
EXPECTED_ADMIN_GROUPS = {
    "application.copyparty.admin",
    "application.syncthing.admin",
    "application.vaultwarden.admin",
    "application.cockpit.admin",
}
SEED_SERVICES = {
    "copyparty": ("files", "webdav", "admin"),
    "syncthing": ("access", "admin"),
    "vaultwarden": ("access", "admin"),
}

RETIRED_GROUP_RE = re.compile(r"nas_(?:allow|deny)_[a-z0-9_]*")
_TABLE_LINE_RE = re.compile(r"^\s*\|.*\|\s*$")
_SEPARATOR_LINE_RE = re.compile(r"^\s*\|[\s:|-]+\|\s*$")

# Explanatory mentions of retired groups are fine; actionable grants, ACLs, and
# CLI examples are not.
UNSAFE_GRANT_RE = re.compile(
    r"(?:--group\s+nas_(?:allow|deny)_"
    r"|(?:^|\n)\s*[-|]\s*`nas_(?:allow|deny)_"
    r"|@nas_(?:allow|deny)_"
    r"|\$\{u%\+nas_(?:allow|deny)_)"
)


def _iter_table_cells(markdown: str):
    """Yield ``(line number, column number, cell)`` for every table cell."""
    lines = markdown.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        if _TABLE_LINE_RE.match(line) and not _SEPARATOR_LINE_RE.match(line):
            table_lines = [line]
            next_index = index + 1
            while next_index < len(lines) and (
                _TABLE_LINE_RE.match(lines[next_index]) or _SEPARATOR_LINE_RE.match(lines[next_index])
            ):
                table_lines.append(lines[next_index])
                next_index += 1
            for offset, row in enumerate(table_lines):
                if _SEPARATOR_LINE_RE.match(row):
                    continue
                cells = [cell.strip() for cell in row.strip().strip("|").split("|")]
                for column, cell in enumerate(cells, 1):
                    yield index + offset + 1, column, cell
            index = next_index
        else:
            index += 1


def _retired_table_violations(root: Path) -> list[str]:
    violations = []
    for md_file in sorted(root.rglob("*.md")):
        relative = md_file.relative_to(root).as_posix()
        for line, column, cell in _iter_table_cells(md_file.read_text(encoding="utf-8")):
            if RETIRED_GROUP_RE.search(cell):
                violations.append(f"{relative}:{line} column {column}: {cell}")
    return violations


def _unsafe_grant_paths(root: Path) -> list[str]:
    return [
        md_file.relative_to(root).as_posix()
        for md_file in sorted(root.rglob("*.md"))
        if UNSAFE_GRANT_RE.search(md_file.read_text(encoding="utf-8"))
    ]


def _service_block(seed: str, service: str) -> str:
    """Return one service declaration up to the next service declaration."""
    match = re.search(rf"^    {re.escape(service)} = ", seed, re.MULTILINE)
    if match is None:
        return ""
    rest = seed[match.end() :]
    following = re.search(r"^    [A-Za-z][\w-]* = ", rest, re.MULTILINE)
    return rest[: following.start()] if following else rest


class V2OperatorDocumentationTests(unittest.TestCase):
    def test_default_group_examples_match_seed(self) -> None:
        seed = (ROOT / "modules/nas/config/managed-services-seed-v2.nix").read_text()
        # The seed declares per-service IDs and capability IDs, and the
        # compiler constructs canonical application.<service>.<capability>.
        for service, capabilities in SEED_SERVICES.items():
            with self.subTest(service=service):
                block = _service_block(seed, service)
                self.assertNotEqual(block, "", f"service {service} is not declared in the seed")
                for capability in capabilities:
                    self.assertIn(f'(capability "{capability}"', block)
        with self.subTest(service="cockpit"):
            block = _service_block(seed, "cockpit")
            self.assertNotEqual(block, "", "service cockpit is not declared in the seed")
            self.assertIn('id = "admin"', block)

        for path in sorted(CAPABILITY_DOCS):
            text = (DOC / path).read_text()
            with self.subTest(path=path):
                for group in sorted(EXPECTED_DEFAULT_GROUPS):
                    self.assertIn(group, text)

    def test_seed_capability_scope_rejects_cross_service_leakage(self) -> None:
        # A capability declared under the wrong service must not satisfy the
        # expectation for the service the documentation names.
        seed = (
            "    copyparty = {\n"
            '      (capability "files")\n'
            "    };\n"
            "    syncthing = {\n"
            '      (capability "webdav")\n'
            "    };\n"
        )
        self.assertIn('(capability "files"', _service_block(seed, "copyparty"))
        self.assertNotIn("webdav", _service_block(seed, "copyparty"))

    def test_administrator_capabilities_are_documented(self) -> None:
        for path in ("permissions.md", "admin/accounts.md"):
            text = (DOC / path).read_text()
            with self.subTest(path=path):
                for group in sorted(EXPECTED_ADMIN_GROUPS):
                    self.assertIn(group, text)
                self.assertNotRegex(text, r"four groups are the ones the default V2")
        permissions = (DOC / "permissions.md").read_text()
        self.assertIn("not the whole capability set", permissions)
        interfaces = (DOC / "reference/interfaces.md").read_text()
        syncthing_rows = [line for line in interfaces.splitlines() if line.startswith("| `/syncthing/`")]
        self.assertEqual(len(syncthing_rows), 1, interfaces)
        self.assertIn("`application.syncthing.admin`", syncthing_rows[0])

    def test_cockpit_route_capability_matches_documentation(self) -> None:
        interfaces = (DOC / "reference/interfaces.md").read_text()
        cockpit_rows = [
            line
            for line in interfaces.splitlines()
            if line.startswith("| `/console/`") or "Cockpit navigation item" in line
        ]
        self.assertEqual(len(cockpit_rows), 2, interfaces)
        for row in cockpit_rows:
            with self.subTest(row=row):
                self.assertIn("`application.cockpit.admin`", row)
                self.assertIn("`nas_admin`", row)

        permissions = (DOC / "permissions.md").read_text()
        self.assertNotIn("cannot open Cockpit", permissions)
        self.assertIn("the `/console` route grants access to `application.cockpit.admin` or `nas_admin`", permissions)

    def test_webdav_row_requires_the_files_group(self) -> None:
        applications = (DOC / "users/applications.md").read_text()
        rows = [line for line in applications.splitlines() if line.startswith("| WebDAV |")]
        self.assertEqual(len(rows), 1, applications)
        self.assertIn("`application.copyparty.webdav`", rows[0])
        self.assertIn("`application.copyparty.files`", rows[0])

    def test_copyparty_migration_covers_the_mutable_seed(self) -> None:
        copyparty = (DOC / "admin/copyparty.md").read_text()
        _, separator, migration = copyparty.partition("## Migrating existing volume ACLs")
        self.assertTrue(separator, "missing CopyParty migration section")
        # The seed file is never rewritten, so both the volume ACL and the
        # dynamic per-user volume name must be migrated explicitly.
        self.assertIn("created only when absent", migration)
        self.assertIn("@application.copyparty.files", migration)
        self.assertIn("${u%+application.copyparty.files}", migration)
        self.assertIn("systemctl reload copyparty", migration)

    def test_disabled_service_group_lifecycle_is_not_contradictory(self) -> None:
        authentik = (DOC / "admin/authentik.md").read_text()
        self.assertNotIn("exist only for enabled or deployed services", authentik)
        self.assertIn("including a service that is currently disabled", authentik)
        self.assertIn("the capability group and its memberships remain", authentik)
        self.assertIn("declares no group at all", authentik)

    def test_no_retired_group_is_recommended(self) -> None:
        self.assertEqual(_unsafe_grant_paths(DOC), [], "actionable retired grant instruction in operator docs")

    def test_retired_groups_are_not_recommended_in_any_table_column(self) -> None:
        self.assertEqual(_retired_table_violations(DOC), [])

    def test_retired_grant_scans_cover_nested_files_and_every_column(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "admin").mkdir()
            (root / "admin" / "service-map.md").write_text(
                "| Path | Group |\n|---|---|\n| `/dav/` | `nas_allow_webdav` |\n",
                encoding="utf-8",
            )
            (root / "users").mkdir()
            (root / "users" / "applications.md").write_text(
                "Assign `nas_allow_files` with `--group nas_allow_files`. @nas_deny_all\n",
                encoding="utf-8",
            )
            self.assertEqual(
                _retired_table_violations(root),
                ["admin/service-map.md:3 column 2: `nas_allow_webdav`"],
            )
            self.assertEqual(_unsafe_grant_paths(root), ["users/applications.md"])

    def test_account_cli_uses_only_reserved_identity_roles(self) -> None:
        accounts = (DOC / "admin/accounts.md").read_text()
        self.assertIn("--group nas_users", accounts)
        self.assertNotRegex(accounts, r"--group\s+application\.")
        self.assertIn("Authentik", accounts)

    def test_first_start_has_no_retired_controller_dependency(self) -> None:
        first_run = (DOC / "admin/first-run.md").read_text()
        self.assertNotIn("or the feature controller", first_run)


if __name__ == "__main__":
    unittest.main()
