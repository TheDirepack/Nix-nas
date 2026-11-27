"""Black-box harness for the Go nas-secrets binary.

Fakes on PATH stand in for keepassxc-cli (a JSON store), sudo (records that
its stdin is /dev/null, then executes), systemctl (a recorded state machine)
and coreutils that need root (install -o/-g, chown). Every fake appends to
one ordered log so tests can assert operation order without reading source.
"""

from __future__ import annotations

import http.server
import json
import os
import pathlib
import shutil
import socketserver
import subprocess
import tempfile
import textwrap
import threading
from typing import Any

from tests.go_binaries import binary

KEEPASS = "fixture keepass passphrase"
REAL_INSTALL = shutil.which("install") or "/usr/bin/install"

FAKE_KEEPASS = r'''#!/usr/bin/env python3
import json, os, sys
store_path = os.environ["FAKE_KP_STORE"]
log = open(os.environ["FAKE_LOG"], "a")
args = sys.argv[1:]
sub = args[0]
log.write("keepassxc-cli " + sub + "\n"); log.flush()
with open(store_path) as handle:
    store = json.load(handle)
password = sys.stdin.readline().rstrip("\n")
if password != store["password"]:
    print("Error while reading the database: Invalid credentials", file=sys.stderr)
    sys.exit(1)
fail = os.environ.get("FAKE_KP_FAIL_" + sub.upper().replace("-", "_"))
if fail:
    sys.exit(int(fail))
entries = store["entries"]
operands = [a for a in args[1:] if not a.startswith("-")]
if "--key-file" in args:
    operands.remove(args[args.index("--key-file") + 1])
def save():
    with open(store_path, "w") as handle:
        json.dump(store, handle)
    os.chmod(store_path, 0o600)
if sub == "db-info":
    sys.exit(0)
if sub == "ls":
    if not store.get("group"):
        sys.exit(1)
    if "--flatten" in args:
        for key in sorted(entries):
            print(key)
    sys.exit(0)
if sub == "mkdir":
    store["group"] = True; save(); sys.exit(0)
key = operands[-1].split("/", 1)[1] if len(operands) > 1 else None
if sub in ("add", "edit"):
    if (sub == "add") == (key in entries):
        sys.exit(3)
    entries[key] = sys.stdin.readline().rstrip("\n"); save(); sys.exit(0)
if sub == "show":
    if key not in entries:
        print("Could not find entry", file=sys.stderr); sys.exit(1)
    print(entries[key]); sys.exit(0)
if sub == "rm":
    entries.pop(key, None); save(); sys.exit(0)
sys.exit(2)
'''

FAKE_SUDO = """#!/usr/bin/env bash
stdin="$(readlink /proc/self/fd/0)"
if [[ "$1" == -v || "$1" == -n ]]; then
  printf 'sudo %s stdin=%s\\n' "$*" "$stdin" >> "$FAKE_LOG"
  [[ "$1" == -v || "$2" == -v ]] && exit 0
  shift
fi
[[ "$1" == -- ]] && shift
printf 'sudo stdin=%s %s\\n' "$stdin" "$*" >> "$FAKE_LOG"
exec "$@"
"""

FAKE_SYSTEMCTL = """#!/usr/bin/env bash
printf 'systemctl %s\\n' "$*" >> "$FAKE_LOG"
state="$FAKE_STATE_DIR"
case "$1" in
  show)
    printf 'LoadState=loaded\\nJob=\\n'
    if [[ -e "$state/target-active" ]]; then echo ActiveState=active; else echo ActiveState=inactive; fi
    ;;
  stop) rm -f "$state/target-active" ;;
  start)
    for unit in "${@:2}"; do
      [[ "$unit" == --* ]] && continue
      if [[ "${FAKE_FAIL_START:-}" == "$unit" ]]; then exit 1; fi
      if [[ "${FAKE_FAIL_START_ONCE:-}" == "$unit" && ! -e "$state/failed-once" ]]; then
        touch "$state/failed-once"; exit 1
      fi
      if [[ "$unit" == *.target ]]; then touch "$state/target-active"; fi
    done
    exit 0
    ;;
  is-failed) [[ -n "${FAKE_FAILED_UNIT:-}" && " ${*:2} " == *" $FAKE_FAILED_UNIT "* ]] ;;
  is-active) [[ -z "${FAKE_INACTIVE_UNIT:-}" || " ${*:2} " != *" $FAKE_INACTIVE_UNIT "* ]] ;;
  *) exit 0 ;;
esac
"""

FAKE_INSTALL = """#!/usr/bin/env bash
# Unprivileged stand-in: drops -o/-g so tests need no root.
args=()
while (($#)); do
  case "$1" in
    -o|-g) shift 2 ;;
    *) args+=("$1"); shift ;;
  esac
done
exec @REAL_INSTALL@ "${args[@]}"
"""

FAKE_CHOWN = """#!/usr/bin/env bash
printf 'chown %s\\n' "$*" >> "$FAKE_LOG"
"""

FAKE_RUNNER = """#!/usr/bin/env bash
printf 'runner %s\\n' "$*" >> "$FAKE_LOG"
[[ "$1" == --validate-current ]] && exit 0
while [[ "$1" != -- ]]; do shift; done
shift
export NAS_OPERATION_COORDINATION_TOKEN=from-runner
exec "$@"
"""


class ReadyServer:
    def __init__(self) -> None:
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - http.server naming
                self.send_response(200 if self.server.ready else 503)  # type: ignore[attr-defined]
                self.end_headers()

            def log_message(self, *_: Any) -> None:
                return

        self.httpd = socketserver.TCPServer(("127.0.0.1", 0), Handler)
        self.httpd.ready = True  # type: ignore[attr-defined]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.httpd.server_address[1]}/auth/-/health/ready/"

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def entries(**overrides: str | None) -> dict[str, str]:
    values: dict[str, str | None] = {
        "authentik-secret-key": "a" * 128,
        "authentik-api-token": "scoped-api-token-0123456789",
        "authentik-outpost-token": "outpost-token-0123456789",
        "state-bundle-signing-key": "b" * 64,
        "zfs-dataset-key": "c" * 64,
    }
    values.update(overrides)
    return {key: value for key, value in values.items() if value is not None}


class Appliance:
    """A temporary appliance tree plus the fakes and config to drive it."""

    def __init__(self, *, features: dict[str, bool] | None = None, store: dict[str, str] | None = None) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(os.path.realpath(self._temporary.name))
        self.bin = self.root / "bin"
        self.state = self.root / "state"
        for directory in (self.bin, self.state):
            directory.mkdir()
        self.log_path = self.root / "ops.log"
        self.log_path.touch()
        self.store = self.root / "store.json"
        self.database = self.root / "control-plane/nas-secrets/NAS.kdbx"
        self.database.parent.mkdir(parents=True)
        self.database.write_text("kdbx", encoding="utf-8")
        self.write_store(store if store is not None else entries())
        self.runtime = self.root / "run/nas-secret-runtime"
        self.runtime.mkdir(parents=True)
        self.secret_root = self.runtime / "live"
        self.authentik_run = self.root / "run/nas-authentik"
        self.authentik_run.mkdir(parents=True)
        self.boot = self.root / "control-plane/authentik"
        self.boot.mkdir(parents=True)
        self.setup_state = self.root / "var/lib/nas-setup/state.json"
        self.setup_state.parent.mkdir(parents=True)
        self.v2_state = self.root / "run/nas-control/systemd-reconciled.json"
        self.v2_state.parent.mkdir(parents=True)
        for name, text in (
            ("keepassxc-cli", FAKE_KEEPASS),
            ("sudo", FAKE_SUDO),
            ("systemctl", FAKE_SYSTEMCTL),
            ("install", FAKE_INSTALL),
            ("chown", FAKE_CHOWN),
            ("nas-operation-run", FAKE_RUNNER),
        ):
            path = self.bin / name
            path.write_text(textwrap.dedent(text).replace("@REAL_INSTALL@", REAL_INSTALL), encoding="utf-8")
            path.chmod(0o755)
        self.ready_server = ReadyServer()
        self.config = self.root / "nas-secrets.json"
        self.config.write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "database": str(self.database),
                    "keyFile": "",
                    "group": "NAS",
                    "secretRoot": str(self.secret_root),
                    "runtimeRoot": str(self.runtime),
                    "lockFile": str(self.root / "nas-secrets.lock"),
                    "setupState": str(self.setup_state),
                    "protectedTarget": "nas-protected-services.target",
                    "v2SystemdState": str(self.v2_state),
                    "bootstrapAuthentikDir": str(self.boot),
                    "authentikRuntimeEnvironmentFile": str(self.authentik_run / "environment"),
                    "authentikUnlockedEnvironmentFile": str(self.authentik_run / "unlocked-environment"),
                    "authentikRuntimeOutpostTokenFile": str(self.authentik_run / "outpost-token"),
                    "authentikApiTokenFile": str(self.secret_root / "authentik/api-token"),
                    "authentikRuntimeApiTokenFile": str(self.authentik_run / "api-token"),
                    "authentikReadyUrl": self.ready_server.url,
                    "bootstrapEmail": "admin@example.invalid",
                    "operationRunner": str(self.bin / "nas-operation-run"),
                    "features": {
                        "observability": False,
                        "grafana": False,
                        "ntfy": False,
                        "nutWeb": False,
                        "zfsEncryption": True,
                        "vaultwarden": False,
                        **(features or {}),
                    },
                }
            ),
            encoding="utf-8",
        )

    def write_store(self, values: dict[str, str], *, password: str = KEEPASS) -> None:
        self.store.write_text(json.dumps({"password": password, "group": True, "entries": values}), encoding="utf-8")

    def entries(self) -> dict[str, str]:
        return json.loads(self.store.read_text(encoding="utf-8"))["entries"]

    def close(self) -> None:
        self.ready_server.close()
        self._temporary.cleanup()

    def env(self, **extra: str) -> dict[str, str]:
        return {
            "PATH": f"{self.bin}:{os.environ.get('PATH', '/usr/bin:/bin')}",
            "HOME": str(self.root),
            "LANG": "C.UTF-8",
            "NAS_SECRETS_CONFIG": str(self.config),
            "NAS_OPERATION_COORDINATION_TOKEN": "fixture-token",
            "FAKE_LOG": str(self.log_path),
            "FAKE_KP_STORE": str(self.store),
            "FAKE_STATE_DIR": str(self.state),
            **extra,
        }

    def run(self, *args: str, stdin: str = KEEPASS + "\n", **env: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(binary("nas-secrets")), *args],
            input=stdin,
            env=self.env(**env),
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )

    def log(self) -> list[str]:
        return self.log_path.read_text(encoding="utf-8").splitlines()

    def index(self, needle: str, *, start: int = 0) -> int:
        for position, line in enumerate(self.log()[start:], start):
            if needle in line:
                return position
        raise AssertionError(f"{needle!r} not in operation log:\n" + "\n".join(self.log()))

    def activate_target(self) -> None:
        (self.state / "target-active").touch()

    def seed_live_tree(self) -> None:
        (self.secret_root / "authentik").mkdir(parents=True)
        (self.secret_root / "ready").write_text("", encoding="utf-8")
        (self.secret_root / "old-marker").write_text("old", encoding="utf-8")
