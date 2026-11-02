from __future__ import annotations

import pathlib
import re
import sys
import unittest

TESTS = pathlib.Path(__file__).resolve().parents[1]
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from repo_test_utils import ROOT, text  # noqa: E402

# Authentik group names that are retired/legacy and must not be recommended as
# access grants in operator documentation. The current grant convention is
# nas_allow_*, nas_deny_*, nas_admin, nas_users, nas_disabled, and
# application.* capability groups.
RETIRED_GROUPS = {
    "nas-files",
    "nas-webdav",
    "nas-syncthing",
    "nas-vault",
    "nas_allow_all",
    "nas_group_files",
}

_TABLE_LINE_RE = re.compile(r"^\s*\|.*\|\s*$")
_SEPARATOR_LINE_RE = re.compile(r"^\s*\|[\s:|-]+\|\s*$")


def _iter_table_cells(markdown: str):
    """Yield the text of every cell in every column of every markdown table."""
    lines = markdown.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        if _TABLE_LINE_RE.match(line) and not _SEPARATOR_LINE_RE.match(line):
            table_lines = [line]
            next_index = index + 1
            while next_index < len(lines) and (
                _TABLE_LINE_RE.match(lines[next_index])
                or _SEPARATOR_LINE_RE.match(lines[next_index])
            ):
                table_lines.append(lines[next_index])
                next_index += 1
            for row in table_lines:
                if _SEPARATOR_LINE_RE.match(row):
                    continue
                cells = [cell.strip() for cell in row.strip().strip("|").split("|")]
                for cell in cells:
                    yield cell
            index = next_index
        else:
            index += 1


class OperatorDocsTests(unittest.TestCase):
    def test_retired_groups_not_recommended_in_any_table_column(self):
        """No docs table cell in any column may recommend a retired group.

        The previous check only inspected the first table cell of each row, so
        retired grant references in later columns passed undetected. Every cell
        of every row is checked here.
        """
        docs_dir = ROOT / "docs" / "src"
        for md_file in sorted(docs_dir.rglob("*.md")):
            content = text(str(md_file.relative_to(ROOT)))
            for cell in _iter_table_cells(content):
                for retired in RETIRED_GROUPS:
                    if retired in cell:
                        self.fail(
                            f"{md_file}: retired group {retired!r} recommended in "
                            f"table cell: {cell!r}"
                        )


if __name__ == "__main__":
    unittest.main()
