from __future__ import annotations

import gc
import json
import os
import pathlib
import re
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import warnings
from contextlib import closing

ROOT = pathlib.Path(__file__).resolve().parents[1]
GUEST = ROOT / "tests/vm/guest-test.sh"
sys.path.insert(0, str(ROOT / "services"))

import nas_v2_quadlet as quadlet  # noqa: E402
import nas_v2_spec as spec  # noqa: E402


class OciDurabilityProbeTests(unittest.TestCase):
    def test_operator_pattern_compiles_without_backing_up_cache_or_scratch(self):
        text = (ROOT / "docs/src/admin/backups.md").read_text()
        section = text.split("## Durable OCI application state", 1)
        if len(section) != 2:
            self.fail("durable OCI operator section is missing")
        example = re.search(r"```yaml\n(.*?)\n```", section[1].split("\n## ", 1)[0], re.DOTALL)
        if example is None:
            self.fail("durable OCI operator pattern is missing")
        effective = spec.compile_document(
            spec.parse_yaml_text(example[1]), spec.load_schema(ROOT / "schemas/managed-services-v3.schema.json")
        )
        self.assertEqual(effective["derived"]["backupResources"], ["app-state"])
        rendered = quadlet.render_quadlet(
            effective, "example", effective["services"]["example"], unit_lines=[], service_lines=[]
        ).decode()
        self.assertIn("Volume=/tank/apps/example/state:/state:rw", rendered)
        self.assertIn("Tmpfs=/tmp:size=67108864", rendered)

    def test_installed_document_fixture_projects_persistent_state_and_readonly_credential(self):
        source = GUEST.read_text()
        expression = re.search(r"jq '(\.document\n.*?)' /tmp/nas-v2-oci-original.json", source, re.DOTALL)
        if expression is None:
            self.fail("installed OCI create expression is missing")
        result = subprocess.run(
            ["jq", expression[1]],
            input=json.dumps({"document": {"schemaVersion": 3, "services": {}}}),
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        effective = spec.compile_document(
            json.loads(result.stdout), spec.load_schema(ROOT / "schemas/managed-services-v3.schema.json")
        )
        rendered = quadlet.render_quadlet(
            effective, "vm-oci-probe", effective["services"]["vm-oci-probe"], unit_lines=[], service_lines=[]
        ).decode()
        self.assertIn("Volume=/tank/vm-oci-state:/state:rw", rendered)
        self.assertIn("Volume=/run/nas-secrets/vm-oci-probe/token:/run/secrets/token:ro", rendered)
        self.assertIn("ReadOnly=true", rendered)

    def verifier(self) -> str:
        source = GUEST.read_text()
        marker = "assert_oci_durable_state() {"
        if marker not in source:
            self.fail("installed OCI lifecycle has no durable-state verifier")
        return marker + source.split(marker, 1)[1].split("\n}\n", 1)[0] + "\n}\n"

    def test_installed_verifier_rejects_lost_state_identity_credential_or_metadata(self):
        verifier = self.verifier()
        # The fixture must not defer connection cleanup to interpreter exit:
        # unclosed SQLite handles keep test databases locked and mask fixture bugs.
        with warnings.catch_warnings(record=True) as caught:
            self.run_verifier_faults(verifier)
            gc.collect()
        leaks = [str(item.message) for item in caught if issubclass(item.category, ResourceWarning)]
        self.assertEqual(leaks, [])

    def run_verifier_faults(self, verifier):
        for fault in (
            None,
            "identity",
            "tasks",
            "credential",
            "credential-source",
            "writable-credential",
            "mode",
            "corrupt",
        ):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                database = root / "app.db"
                with closing(sqlite3.connect(database)) as connection, connection:
                    connection.executescript(
                        "CREATE TABLE identity(id TEXT); INSERT INTO identity VALUES('vm-oci-probe');"
                        "CREATE TABLE tasks(task TEXT); INSERT INTO tasks VALUES('task-1');"
                    )
                    if fault == "identity":
                        connection.execute("UPDATE identity SET id = 'replacement'")
                    elif fault == "tasks":
                        connection.execute("DELETE FROM tasks")
                database.chmod(0o600)
                (root / "expected-token").write_text("test-only-credential\n")
                (root / "container-token").write_text("wrong\n" if fault == "credential" else "test-only-credential\n")
                (root / "inspect.json").write_text(
                    json.dumps(
                        [
                            {
                                "Mounts": [
                                    {
                                        "Source": str(
                                            root / ("other-token" if fault == "credential-source" else "expected-token")
                                        ),
                                        "Destination": "/run/secrets/token",
                                        "RW": fault == "writable-credential",
                                    }
                                ]
                            }
                        ]
                    )
                )
                if fault == "mode":
                    database.chmod(0o644)
                elif fault == "corrupt":
                    database.write_bytes(b"not a SQLite database\n")
                result = subprocess.run(
                    [
                        "bash",
                        "-c",
                        """set -euo pipefail
oci_state=$1
oci_container=fixture-container
oci_credential=$1/expected-token
oci_db_metadata="$(id -u):$(id -g):600"
fail() { echo "$*" >&2; exit 1; }
podman() {
  case "$*" in
    'exec fixture-container cat /run/secrets/token') cat "$oci_state/container-token" ;;
    'inspect fixture-container') cat "$oci_state/inspect.json" ;;
    *) return 99 ;;
  esac
}
oci_sql() {
  python3 - "$oci_state/app.db" "$1" <<'PYSQL'
import sqlite3, sys
from contextlib import closing
with closing(sqlite3.connect(sys.argv[1])) as connection:
    for row in connection.execute(sys.argv[2]):
        print('|'.join('' if value is None else str(value) for value in row))
PYSQL
}
"""
                        + verifier
                        + '\nassert_oci_durable_state "task-1"\n',
                        "test",
                        directory,
                    ],
                    env=os.environ.copy(),
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(result.returncode == 0, fault is None, result.stdout + result.stderr)
                if fault is not None:
                    self.assertIn("OCI", result.stderr)

    def test_guest_quiesces_snapshot_restore_and_retains_data_after_removal(self):
        source = GUEST.read_text()
        self.assertTrue(
            "contents = [ pkgs.busybox pkgs.sqlite ];" in (ROOT / "tests/nixos/vm-common.nix").read_text(),
            "VM OCI probe image must include SQLite",
        )
        for marker in (
            '"stateClass": "authoritative"',
            '"resource": "vm-oci-state", "mountPath": "/state", "access": "write"',
            '"credential": "vm-oci-token", "use": "file", "mountPath": "/run/secrets/token"',
            'oci_first_container="$(podman inspect --format',
            'assert_oci_durable_state "task-1,task-2"',
            'zfs snapshot "$oci_dataset@consistent"',
            'zfs clone -o mountpoint=/tank/vm-oci-restored "$oci_dataset@consistent" "$oci_restore_dataset"',
            "oci_retained_db=/tank/vm-oci-state/app.db",
            "assert_oci_retained_state",
            'zfs destroy -r "$oci_restore_dataset"',
        ):
            self.assertTrue(marker in source, f"guest OCI lifecycle is missing {marker}")
        for operation in ('zfs snapshot "$oci_dataset@consistent"', "zfs clone -o mountpoint=/tank/vm-oci-restored"):
            before = source[: source.index(operation)]
            self.assertGreater(
                before.rfind("systemctl stop nas-v2-vm-oci-probe.service"),
                before.rfind("systemctl start nas-v2-vm-oci-probe.service"),
            )
        removal = source.index('pass "unknown OCI service removal cleaned')
        self.assertGreater(source.index('pass "OCI definition removal retained'), removal)

    def test_cleanup_handles_extra_snapshots_and_preserves_failures(self):
        source = GUEST.read_text()
        cleanup = source.split(
            'pass "unknown OCI service removal cleaned native runtime, route, and authorization projections"\n', 1
        )[1]
        cleanup = cleanup.split('\nlog "Observability and notifications"', 1)[0]
        for failure in ("none", "retention", "restore", "state"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                (root / "credential").mkdir()
                (root / "credential/token").write_text("test-only-credential\n")
                result = subprocess.run(
                    [
                        "bash",
                        "-c",
                        """set -euo pipefail
root=$1
failure=$2
oci_dataset=tank/nas/vm-oci-state
oci_restore_dataset=tank/nas/vm-oci-restored
oci_credential=$root/credential/token
assert_oci_retained_state() { [[ $failure != retention ]] || return 75; }
pass() { :; }
zfs() {
  printf '%s\n' "$*" >>"$root/commands"
  if [[ $1 == snapshot ]]; then
    [[ $# == 3 && $2 == "$oci_restore_dataset@cleanup-probe" && $3 == "$oci_dataset@cleanup-probe" ]]
    return
  fi
  [[ $1 == destroy ]] || return 90
  local target=${!#}
  case "$target" in
    "$oci_restore_dataset")
      [[ $failure != restore ]] || return 73
      ;;
    "$oci_dataset")
      [[ $failure != state ]] || return 74
      ;;
    "$oci_dataset@before-restore"|"$oci_dataset@consistent") return 0 ;;
    *) return 91 ;;
  esac
  # Both datasets have extra snapshots, as when Sanoid fires during the drill.
  [[ $# == 3 && $2 == -r ]] || { echo 'cannot destroy: filesystem has snapshots' >&2; return 1; }
}
rmdir() {
  [[ $# == 1 && $1 == /run/nas-secrets/vm-oci-probe ]] || return 92
  command rmdir "$root/credential"
}
"""
                        + cleanup,
                        "test",
                        directory,
                        failure,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(
                    result.returncode, {"none": 0, "retention": 75, "restore": 73, "state": 74}[failure], result.stderr
                )
                commands = root / "commands"
                observed = commands.read_text().splitlines() if commands.exists() else []
                expected = (
                    []
                    if failure == "retention"
                    else [
                        "snapshot tank/nas/vm-oci-restored@cleanup-probe tank/nas/vm-oci-state@cleanup-probe",
                        "destroy -r tank/nas/vm-oci-restored",
                    ]
                )
                if failure in ("none", "state"):
                    expected.append("destroy -r tank/nas/vm-oci-state")
                self.assertEqual(observed, expected)
                self.assertEqual((root / "credential/token").exists(), failure != "none")

    def test_retained_state_check_rejects_destroyed_swapped_or_writable_data(self):
        source = GUEST.read_text()
        marker = "assert_oci_retained_state() {"
        if marker not in source:
            self.fail("installed OCI lifecycle has no retained-state verifier")
        verifier = marker + source.split(marker, 1)[1].split("\n}\n", 1)[0] + "\n}\n"
        for fault in (None, "destroyed", "swapped", "mode", "writable", "missing-credential"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                database = root / "app.db"
                if fault != "destroyed":
                    with closing(sqlite3.connect(database)) as connection, connection:
                        connection.executescript(
                            "CREATE TABLE tasks(task TEXT);"
                            "INSERT INTO tasks VALUES('task-1');"
                            + ("" if fault == "swapped" else "INSERT INTO tasks VALUES('task-2');")
                        )
                    database.chmod(0o644 if fault == "mode" else 0o600)
                credential = root / "token"
                if fault != "missing-credential":
                    credential.write_text("test-only-credential\n")
                    credential.chmod(0o666 if fault == "writable" else 0o600)
                result = subprocess.run(
                    [
                        "bash",
                        "-c",
                        """set -euo pipefail
oci_retained_db=$1/app.db
oci_credential=$1/token
oci_db_metadata="$(id -u):$(id -g):600"
fail() { echo "$*" >&2; exit 1; }
oci_host_sql() {
  python3 - "$1" "$2" <<'PYSQL'
import sqlite3, sys
from contextlib import closing
with closing(sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)) as connection:
    for row in connection.execute(sys.argv[2]):
        print("|".join("" if value is None else str(value) for value in row))
PYSQL
}
"""
                        + verifier
                        + "\nassert_oci_retained_state\n",
                        "test",
                        directory,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(result.returncode == 0, fault is None, result.stdout + result.stderr)
                if fault is not None:
                    self.assertIn("OCI", result.stderr)


if __name__ == "__main__":
    unittest.main()
