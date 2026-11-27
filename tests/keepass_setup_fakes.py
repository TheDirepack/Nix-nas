"""Fake tools for driving nas-keepass-setup database against a temp KDBX."""

from __future__ import annotations

import os
import pathlib
import shutil
import textwrap

FAKE_KEEPASSXC = r"""#!/usr/bin/env bash
printf 'keepassxc-cli %s\n' "$*" >> "$FAKE_LOG"
db="${@: -1}"
IFS= read -r password
case "$1" in
  db-create)
    IFS= read -r again
    [[ "$password" == "$again" ]] || exit 9
    printf '%s' "$password" > "$db.password"
    printf 'fresh' > "$db"
    ;;
  db-info)
    [[ -f "$db" ]] || exit 1
    [[ ! -f "$db.password" || "$(cat "$db.password")" == "$password" ]] || exit 1
    [[ -z "${FAKE_DB_INFO_FAIL:-}" ]] || exit 1
    ;;
esac
"""

FAKE_SUDO = r"""#!/usr/bin/env bash
printf 'sudo %s stdin=%s\n' "$*" "$(readlink /proc/self/fd/0)" >> "$FAKE_LOG"
[[ "$1" == -n ]] && shift
[[ "$1" == -v ]] && exit 0
[[ "$1" == -- ]] && shift
exec "$@"
"""

FAKE_INSTALL = """#!/usr/bin/env bash
printf 'install %s\\n' "$*" >> "$FAKE_LOG"
exec @MKDIR@ -p "${@: -1}"
"""


def install_fakes(root: pathlib.Path) -> dict[str, str]:
    bin_dir = root / "bin"
    bin_dir.mkdir(exist_ok=True)
    log = root / "ops.log"
    log.touch()
    mkdir = shutil.which("mkdir") or "/bin/mkdir"
    for name, text in (("keepassxc-cli", FAKE_KEEPASSXC), ("sudo", FAKE_SUDO), ("install", FAKE_INSTALL)):
        path = bin_dir / name
        path.write_text(textwrap.dedent(text).replace("@MKDIR@", mkdir), encoding="utf-8")
        path.chmod(0o755)
    return {"PATH": f"{bin_dir}:{os.environ.get('PATH', '')}", "FAKE_LOG": str(log)}


def operations(root: pathlib.Path) -> list[str]:
    return (root / "ops.log").read_text(encoding="utf-8").splitlines()
