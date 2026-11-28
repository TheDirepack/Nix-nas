"""A recording keepassxc-cli for black-box tests of `nas-keepass-setup database`."""

from __future__ import annotations

import contextlib
import json
import os
import pathlib
import sys
import tempfile
import textwrap
from collections.abc import Iterator
from typing import TypedDict
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from zig_binaries import release_bin_dir  # noqa: E402

FAKE = textwrap.dedent(
    """\
    #!/usr/bin/env python3
    import json, os, sys
    stdin = sys.stdin.read()
    with open(os.environ["FAKE_KP_LOG"], "a") as log:
        log.write(json.dumps({"argv": sys.argv[1:], "stdin": stdin}) + "\\n")
    database = sys.argv[-1]
    if sys.argv[1] == "db-create":
        if os.environ.get("FAKE_KP_CREATE_NOOP") != "1":
            with open(database, "w") as handle:
                handle.write("fresh")
        sys.exit(0)
    if sys.argv[1] == "db-info":
        sys.exit(0 if os.environ.get("FAKE_KP_OPENS", "1") == "1" else 1)
    sys.exit(2)
    """
)


def export_keepass_setup() -> None:
    os.environ.setdefault("NAS_KEEPASS_SETUP_BIN", str(release_bin_dir() / "nas-keepass-setup"))


class KeePassCall(TypedDict):
    argv: list[str]
    stdin: str


class KeePassLog:
    def __init__(self, path: pathlib.Path) -> None:
        self.path = path

    def calls(self) -> list[KeePassCall]:
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines()]

    def argv(self) -> list[list[str]]:
        return [call["argv"] for call in self.calls()]


@contextlib.contextmanager
def fake_keepass(setup_module: object, *, opens: bool = True, create_noop: bool = False) -> Iterator[KeePassLog]:
    """Run `nas-keepass-setup` for real against a recording keepassxc-cli.

    `admin_command` runs the helper directly instead of switching users.
    """
    export_keepass_setup()
    with tempfile.TemporaryDirectory() as raw:
        bin_dir = pathlib.Path(raw)
        cli = bin_dir / "keepassxc-cli"
        cli.write_text(FAKE, encoding="utf-8")
        cli.chmod(0o755)
        log = bin_dir / "calls.jsonl"
        env = {
            "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}",
            "FAKE_KP_LOG": str(log),
            "FAKE_KP_OPENS": "1" if opens else "0",
            "FAKE_KP_CREATE_NOOP": "1" if create_noop else "0",
        }
        with mock.patch.dict(os.environ, env), mock.patch.object(setup_module, "admin_command", side_effect=list):
            yield KeePassLog(log)
