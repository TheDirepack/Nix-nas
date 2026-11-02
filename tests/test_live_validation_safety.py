"""Safety behaviour of the live appliance drills (PR #172 findings).

The Syncoid drill is exercised against fake ``zfs``/``syncoid``/``ssh`` tools so
that cleanup is verified by observation rather than by matching source text: the
fake tools keep a dataset registry and record every command they receive.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts/live-validation.sh"
SCRIPT = SCRIPT_PATH.read_text(encoding="utf-8")
# The drills are sourced exactly as tests/test_contract_tooling.py does it: take
# everything before the dispatch case and call the function directly.
PREFIX = SCRIPT.split('case "${1:-}" in', 1)[0]
STAMP = "20261101T000000Z"
MARKER = f"nas-live-{STAMP}"

FAKE_ZFS = r"""#!{python}
import os
import shutil
import sys
import urllib.parse

state = os.environ["FAKE_ZFS_STATE"]
mounts = os.environ["FAKE_ZFS_MOUNTS"]
log = os.environ["FAKE_ZFS_LOG"]
race_dir = os.path.join(os.path.dirname(state), "race")
race_names = [name for name in os.environ.get("FAKE_ZFS_RACE_NAMES", "").split(",") if name]
args = sys.argv[1:]
with open(log, "a", encoding="utf-8") as handle:
    handle.write("zfs " + " ".join(args) + "\n")


def dataset_file(name):
    return os.path.join(state, urllib.parse.quote(name, safe=""))


def mount_path(name):
    return os.path.join(mounts, urllib.parse.quote(name, safe=""))


def exists(name):
    return os.path.exists(dataset_file(name))


def register(name):
    open(dataset_file(name), "w", encoding="utf-8").close()


def registered():
    return [urllib.parse.unquote(entry) for entry in os.listdir(state)]


def race_flag(name):
    return os.path.join(race_dir, urllib.parse.quote(name, safe=""))


def probe(name):
    # Arm a listed name: a competing writer wins it between this probe and the
    # drill's next write to that name.
    if name in race_names and not exists(name) and not os.path.exists(race_flag(name)):
        os.makedirs(race_dir, exist_ok=True)
        open(race_flag(name), "w", encoding="utf-8").close()


def compete(name):
    if name in race_names and os.path.exists(race_flag(name)) and not exists(name):
        register(name)
        os.makedirs(mount_path(name), exist_ok=True)
        with open(os.path.join(mount_path(name), "marker.txt"), "w", encoding="utf-8") as handle:
            handle.write("foreign\n")


command = args[0]
if command == "get":
    name = args[-1]
    if not exists(name):
        probe(name)
        sys.exit(1)
    print(mount_path(name))
elif command == "create":
    name = args[-1]
    compete(name)
    if exists(name):
        sys.stderr.write("cannot create " + name + ": dataset exists\n")
        sys.exit(1)
    register(name)
    os.makedirs(mount_path(name), exist_ok=True)
elif command == "snapshot":
    name = args[-1]
    compete(name)
    if exists(name):
        sys.stderr.write("cannot snapshot " + name + ": already exists\n")
        sys.exit(1)
    register(name)
elif command == "clone":
    source, name = args[-2], args[-1]
    compete(name)
    if not exists(source):
        sys.stderr.write("no such snapshot: " + source + "\n")
        sys.exit(1)
    if exists(name):
        sys.stderr.write("cannot clone " + name + ": dataset exists\n")
        sys.exit(1)
    register(name)
    os.makedirs(mount_path(name), exist_ok=True)
    parent = mount_path(source.split("@", 1)[0])
    if os.path.isdir(parent):
        for entry in os.listdir(parent):
            shutil.copy2(os.path.join(parent, entry), os.path.join(mount_path(name), entry))
elif command == "destroy":
    if "--" in args[1:]:
        names = [value for value in args[1:] if value != "--"]
    elif args[1] in ("-r", "-R", "-rf"):
        sys.stderr.write("recursive destroy is not permitted by the safety contract\n")
        sys.exit(65)
    else:
        names = args[1:]
    if len(names) != 1:
        sys.stderr.write("unexpected destroy arguments: " + " ".join(args) + "\n")
        sys.exit(64)
    name = names[0]
    if not exists(name):
        sys.stderr.write("no such dataset: " + name + "\n")
        sys.exit(1)
    if any(other.startswith(name + "/") for other in registered()):
        sys.stderr.write("dataset has children: " + name + "\n")
        sys.exit(1)
    # Destroying a dataset also destroys its own snapshots, as ZFS does.
    for other in registered():
        if other.startswith(name + "@"):
            os.unlink(dataset_file(other))
    os.unlink(dataset_file(name))
    shutil.rmtree(mount_path(name), ignore_errors=True)
else:
    sys.stderr.write("unsupported fake zfs command: " + command + "\n")
    sys.exit(64)
"""

FAKE_SYNCOID = r"""#!/usr/bin/env bash
set -euo pipefail
printf 'syncoid %s\n' "$*" >> "$FAKE_ZFS_LOG"
source_dataset=$2
target=$3
# Syncoid accepts host:dataset and opens the dataset on that host.
target_dataset=${target#*:}
[[ "$target" == *:* ]] || target_dataset=$target
# Simulate another writer owning the generated name after the preflight: Syncoid
# reports success but the dataset holds someone else's data.
if [[ "${FAKE_SYNCOID_COLLISION:-0}" == 1 ]]; then
  zfs create -- "$target_dataset"
  printf 'foreign\n' > "$(zfs get -H -o value mountpoint "$target_dataset")/marker.txt"
  zfs snapshot -- "$target_dataset@validation"
  exit 0
fi
zfs create -- "$target_dataset"
cp -a "$(zfs get -H -o value mountpoint "$source_dataset")/." \
  "$(zfs get -H -o value mountpoint "$target_dataset")/"
# Simulate a replication that fails after leaving a partial destination.
if [[ "${FAKE_SYNCOID_FAIL:-0}" == 1 ]]; then
  exit 1
fi
zfs snapshot -- "$target_dataset@validation"
"""

FAKE_SSH = r"""#!/usr/bin/env bash
set -euo pipefail
while [[ $# -gt 0 ]]; do
  case $1 in
    -o) shift 2 ;;
    -*) shift ;;
    *) break ;;
  esac
done
shift
exec "$@"
"""

FAKE_DATE = r"""#!/usr/bin/env bash
if [[ "${1:-}" == "-u" && "${2:-}" == "+%Y%m%d%H%M%S" ]]; then
  printf '%s\n' "${FAKE_STAMP}"
  exit 0
fi
exec {date} "$@"
"""


@dataclass
class Drill:
    result: subprocess.CompletedProcess[str]
    commands: list[str]
    destroyed: list[str]
    registered: set[str]
    harness: "Harness"

    def marker_text(self, dataset: str) -> str:
        return (self.harness.mount_path(dataset) / "marker.txt").read_text(encoding="utf-8").strip()


class Harness:
    """Fake ZFS universe the drill can run in."""

    def __init__(self) -> None:
        self.temporary = Path(tempfile.mkdtemp(prefix="nas-live-validation-"))
        self.bin = self.temporary / "bin"
        self.state = self.temporary / "state"
        self.mounts = self.temporary / "mounts"
        self.log = self.temporary / "commands.log"
        for directory in (self.bin, self.state, self.mounts):
            directory.mkdir(parents=True)
        self.log.touch()
        self._install("zfs", FAKE_ZFS.replace("{python}", sys.executable))
        self._install("syncoid", FAKE_SYNCOID)
        self._install("ssh", FAKE_SSH)
        self._install("date", FAKE_DATE.replace("{date}", shutil.which("date") or "/bin/date"))
        self.env = dict(os.environ)
        # Isolate the drill from any clone override in the developer environment.
        for name in ("NAS_SYNCOID_LOCAL_CLONE", "NAS_SYNCOID_REMOTE_CLONE", "_LIVE_ALL_MODE"):
            self.env.pop(name, None)
        self.env.update(
            {
                "PATH": f"{self.bin}{os.pathsep}{os.environ.get('PATH', '')}",
                "FAKE_ZFS_STATE": str(self.state),
                "FAKE_ZFS_MOUNTS": str(self.mounts),
                "FAKE_ZFS_LOG": str(self.log),
                "FAKE_STAMP": STAMP,
                "NAS_LIVE_CONFIRM": "SYNCOID_DRILL",
            }
        )

    def _install(self, name: str, content: str) -> None:
        path = self.bin / name
        path.write_text(content, encoding="utf-8")
        path.chmod(0o755)

    def mount_path(self, dataset: str) -> Path:
        return self.mounts / urllib.parse.quote(dataset, safe="")

    def create_dataset(self, name: str) -> None:
        subprocess.run(
            [str(self.bin / "zfs"), "create", name],
            env=self.env,
            check=True,
            capture_output=True,
            timeout=30,
        )

    def run(
        self,
        *,
        source: str = "tank/source",
        target: str = "tank/target",
        preexisting: tuple[str, ...] = (),
        syncoid_fail: bool = False,
        extra_env: dict[str, str] | None = None,
    ) -> Drill:
        env = dict(self.env)
        env["NAS_SYNCOID_SOURCE"] = source
        env["NAS_SYNCOID_TARGET"] = target
        if syncoid_fail:
            env["FAKE_SYNCOID_FAIL"] = "1"
        env.update(extra_env or {})
        for name in preexisting:
            self.create_dataset(name)
        # Only log what the drill itself runs.
        self.log.write_text("", encoding="utf-8")
        result = subprocess.run(
            ["bash", "-c", PREFIX + "\nsyncoid_drill\n"],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        commands = self.log.read_text(encoding="utf-8").splitlines()
        return Drill(
            result=result,
            commands=commands,
            destroyed=[line for line in commands if line.startswith("zfs destroy ")],
            registered={urllib.parse.unquote(entry.name) for entry in self.state.iterdir()},
            harness=self,
        )

    def close(self) -> None:
        shutil.rmtree(self.temporary, ignore_errors=True)


class SyncoidDrillTests(unittest.TestCase):
    def harness(self) -> Harness:
        instance = Harness()
        self.addCleanup(instance.close)
        return instance

    def assert_exact_cleanup(self, drill: Drill, expected: set[str]) -> None:
        self.assertEqual(
            sorted(drill.destroyed),
            sorted(f"zfs destroy -- {name}" for name in expected),
            drill.result.stdout + drill.result.stderr,
        )
        self.assertEqual(drill.registered, set(), "cleanup left datasets behind")
        self.assertEqual(
            [line for line in drill.commands if line.startswith("zfs destroy -r")],
            [],
            "cleanup used recursive destroy",
        )

    def test_local_drill_cleanup_destroys_exactly_the_datasets_it_created(self):
        # Findings 2 and 3: exactly the datasets this run created, removed
        # non-recursively, including the atomically claimed destination.
        drill = self.harness().run()
        self.assertEqual(drill.result.returncode, 0, drill.result.stderr)
        child = f"tank/source/{MARKER}"
        claim = f"tank/target/{MARKER}"
        replica = f"{claim}/replica"
        self.assert_exact_cleanup(drill, {f"{child}@validation", child, claim, replica, f"{replica}-restore"})

    def test_remote_drill_cleanup_destroys_exactly_the_datasets_it_created(self):
        # Findings 2 and 3 (remote branch): the same exact set, addressed through
        # the remote host.
        drill = self.harness().run(target="backup-host:backup/nas/validation")
        self.assertEqual(drill.result.returncode, 0, drill.result.stderr)
        child = f"tank/source/{MARKER}"
        claim = f"backup/nas/validation/{MARKER}"
        replica = f"{claim}/replica"
        self.assertIn(
            f"syncoid --no-sync-snap {child} backup-host:{replica}",
            drill.commands,
            "the replication must address the remote host, not a local dataset",
        )
        self.assertIn(f"zfs create -- {claim}", drill.commands)
        self.assert_exact_cleanup(drill, {f"{child}@validation", child, claim, replica, f"{replica}-restore"})

    def test_destination_must_be_unused_before_the_drill_starts(self):
        # Finding 2: an occupied destination, including one with a foreign child,
        # aborts before the drill writes anything.
        cases = (
            ("tank/target", f"tank/target/{MARKER}", "local destination already exists"),
            (
                "backup-host:backup/nas/validation",
                f"backup/nas/validation/{MARKER}",
                "remote destination already exists",
            ),
        )
        for target, existing, message in cases:
            with self.subTest(target=target):
                drill = self.harness().run(target=target, preexisting=(existing, f"{existing}/foreign"))
                self.assertNotEqual(drill.result.returncode, 0)
                self.assertIn(message, drill.result.stderr)
                self.assertEqual(drill.destroyed, [], "cleanup touched a dataset this run does not own")
                self.assertEqual(
                    [line for line in drill.commands if line.startswith("zfs create ")],
                    [],
                    "the drill created data before proving the destination was unused",
                )
                self.assertEqual(drill.registered, {existing, f"{existing}/foreign"})

    def test_failed_replication_leaves_the_partial_destination_for_inspection(self):
        # Finding 2: ownership is recorded only after the replication marker is
        # read back, so the claim and its partial replica survive.
        drill = self.harness().run(syncoid_fail=True)
        self.assertNotEqual(drill.result.returncode, 0)
        self.assertIn("syncoid replication", drill.result.stderr)
        child = f"tank/source/{MARKER}"
        claim = f"tank/target/{MARKER}"
        replica = f"{claim}/replica"
        self.assertEqual(
            sorted(drill.destroyed),
            sorted([f"zfs destroy -- {child}@validation", f"zfs destroy -- {child}"]),
            "an unowned partial destination must not be destroyed",
        )
        self.assertEqual(drill.registered, {claim, replica})
        self.assertEqual(drill.marker_text(replica), MARKER)

    def test_name_collision_after_preflight_is_never_destroyed(self):
        # Finding 2: ownership follows verification. A replica that carries another
        # writer's marker is left in place instead of being destroyed.
        drill = self.harness().run(extra_env={"FAKE_SYNCOID_COLLISION": "1"})
        self.assertNotEqual(drill.result.returncode, 0)
        self.assertIn("replicated marker mismatch", drill.result.stderr)
        child = f"tank/source/{MARKER}"
        claim = f"tank/target/{MARKER}"
        replica = f"{claim}/replica"
        self.assertEqual(
            sorted(drill.destroyed),
            sorted([f"zfs destroy -- {child}@validation", f"zfs destroy -- {child}"]),
            "only the source datasets this run created may be removed",
        )
        self.assertEqual(drill.registered, {claim, replica, f"{replica}@validation"})
        self.assertEqual(drill.marker_text(replica), "foreign")

    def test_competing_writer_claiming_the_destination_is_not_destroyed(self):
        # The destination is claimed with an atomic `zfs create`, so a writer that
        # wins the name between the existence probe and that create makes the drill
        # fail without touching the winner's dataset.
        cases = (
            ("tank/target", f"tank/target/{MARKER}", "could not claim local destination"),
            (
                "backup-host:backup/nas/validation",
                f"backup/nas/validation/{MARKER}",
                "could not claim remote destination",
            ),
        )
        for target, claim, message in cases:
            with self.subTest(target=target):
                drill = self.harness().run(target=target, extra_env={"FAKE_ZFS_RACE_NAMES": claim})
                self.assertNotEqual(drill.result.returncode, 0)
                self.assertIn(message, drill.result.stderr)
                child = f"tank/source/{MARKER}"
                self.assertEqual(
                    sorted(drill.destroyed),
                    sorted([f"zfs destroy -- {child}@validation", f"zfs destroy -- {child}"]),
                    "the loser must not destroy the winner's dataset",
                )
                self.assertEqual(drill.registered, {claim})
                self.assertEqual(drill.marker_text(claim), "foreign")
                self.assertEqual(
                    [line for line in drill.commands if line.startswith("syncoid ")],
                    [],
                    "the drill replicated before it owned the destination",
                )

    def test_competing_writer_taking_the_clone_name_is_not_destroyed(self):
        # `zfs clone` is itself an atomic claim, so a clone name lost after the
        # preflight probe is never recorded as ours.
        custom_clone = "tank/clones/live-drill"
        drill = self.harness().run(
            extra_env={
                "NAS_SYNCOID_LOCAL_CLONE": custom_clone,
                "FAKE_ZFS_RACE_NAMES": custom_clone,
            }
        )
        self.assertNotEqual(drill.result.returncode, 0)
        child = f"tank/source/{MARKER}"
        claim = f"tank/target/{MARKER}"
        replica = f"{claim}/replica"
        # The replica is proven, so the destination is still cleaned up; the
        # foreign clone name is not.
        self.assertEqual(
            sorted(drill.destroyed),
            sorted(
                [
                    f"zfs destroy -- {child}@validation",
                    f"zfs destroy -- {child}",
                    f"zfs destroy -- {claim}",
                    f"zfs destroy -- {replica}",
                ]
            ),
        )
        self.assertEqual(drill.registered, {custom_clone})
        self.assertEqual(drill.marker_text(custom_clone), "foreign")

    def test_clone_override_is_taken_from_the_environment(self):
        # Finding 13: the expected clone name follows NAS_SYNCOID_LOCAL_CLONE, and
        # the harness clears any inherited value.
        custom_clone = "tank/clones/live-drill"
        drill = self.harness().run(extra_env={"NAS_SYNCOID_LOCAL_CLONE": custom_clone})
        self.assertEqual(drill.result.returncode, 0, drill.result.stderr)
        child = f"tank/source/{MARKER}"
        claim = f"tank/target/{MARKER}"
        replica = f"{claim}/replica"
        self.assert_exact_cleanup(drill, {f"{child}@validation", child, claim, replica, custom_clone})
        self.assertNotIn(f"zfs destroy -- {replica}-restore", drill.destroyed)

    def test_snapshot_qualified_clone_override_is_rejected_before_any_change(self):
        # Finding 5: a snapshot-qualified clone override fails in preflight.
        drill = self.harness().run(extra_env={"NAS_SYNCOID_LOCAL_CLONE": "tank/clones/live@snap"})
        self.assertNotEqual(drill.result.returncode, 0)
        self.assertIn("clone target must not be snapshot-qualified", drill.result.stderr)
        self.assertEqual(drill.destroyed, [])
        self.assertEqual(
            [line for line in drill.commands if line.startswith(("zfs create ", "zfs snapshot "))],
            [],
        )
        self.assertEqual(drill.registered, set())

    def test_identical_local_source_and_target_are_rejected(self):
        # Finding 10: source == target is rejected before any ZFS call.
        drill = self.harness().run(source="tank/source", target="tank/source")
        self.assertNotEqual(drill.result.returncode, 0)
        self.assertIn("source and target must not be identical", drill.result.stderr)
        self.assertEqual(drill.destroyed, [])
        self.assertEqual(
            [line for line in drill.commands if line.startswith("zfs create ")],
            [],
        )


class CleanupOnFailureTests(unittest.TestCase):
    """Cleanup must also run when a command fails under errexit."""

    def harness(self) -> Harness:
        instance = Harness()
        self.addCleanup(instance.close)
        return instance

    def tool(self, harness: Harness, name: str, body: str) -> None:
        path = harness.bin / name
        path.write_text("#!/usr/bin/env bash\nset -euo pipefail\n" + body, encoding="utf-8")
        path.chmod(0o755)

    def run_drill(self, harness: Harness, env: dict[str, str], function: str) -> subprocess.CompletedProcess[str]:
        merged = dict(harness.env)
        merged.update(env)
        return subprocess.run(
            ["bash", "-c", PREFIX + f"\n{function}\n"],
            cwd=ROOT,
            env=merged,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )

    def test_restic_cleanup_runs_when_the_restore_fails(self):
        # Finding 2/7: an errexit failure inside the drill must still remove the
        # marker and the per-run restore directory.
        harness = self.harness()
        source = harness.temporary / "restic-source"
        source.mkdir()
        target = harness.temporary / "restore-target"
        target.mkdir()
        self.tool(
            harness,
            "restic",
            'if [[ "${1:-}" == backup ]]; then\n'
            '  printf \'%s\\n\' \'{"message_type":"summary","snapshot_id":"abc123"}\'\n'
            "  exit 0\n"
            "fi\n"
            "exit 0\n",
        )
        self.tool(harness, "jq", "cat >/dev/null\nprintf 'abc123\\n'\n")
        result = self.run_drill(
            harness,
            {
                "RESTIC_REPOSITORY": str(harness.temporary / "repo"),
                "RESTIC_PASSWORD_FILE": str(harness.temporary / "restic-password"),
                "NAS_RESTIC_SOURCE": str(source),
                "NAS_RESTIC_RESTORE_TARGET": str(target),
                "NAS_LIVE_CONFIRM": "RESTIC_DRILL",
            },
            "restic_drill",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(source.iterdir()), [], "the run marker leaked")
        self.assertEqual(list(target.iterdir()), [], "the restore directory leaked")

    def test_copyparty_cleanup_runs_when_the_upload_fails(self):
        # Finding 7: a failing curl must not leak either temporary file.
        harness = self.harness()
        temporary = harness.temporary / "tmp"
        temporary.mkdir()
        password_file = harness.temporary / "copy-password"
        password_file.write_text("secret\n", encoding="utf-8")
        password_file.chmod(0o600)
        self.tool(harness, "curl", "exit 1\n")
        self.tool(harness, "nas-identity-sync", "exit 0\n")
        result = self.run_drill(
            harness,
            {
                "NAS_COPY_USER": "validation",
                "NAS_COPY_PASSWORD_FILE": str(password_file),
                "NAS_COPY_BASE_URL": "http://127.0.0.1:1/dav/validation/",
                "TMPDIR": str(temporary),
                "NAS_LIVE_CONFIRM": "COPY_DRILL",
            },
            "copyparty",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(temporary.iterdir()), [], "temporary upload files leaked")


class LiveValidationScriptTests(unittest.TestCase):
    """Static contracts for the parts that cannot run without real services."""

    def test_remote_zfs_script_is_single_printf_with_all_continuations(self):
        # Finding 1: every line of the remote script, including the mountpoint
        # arm, must end with a continuation backslash so one printf feeds ssh.
        block = SCRIPT.split("  printf '%s", 1)[1].split("| ssh", 1)[0]
        lines = [line for line in block.splitlines() if line.strip()]
        self.assertGreater(len(lines), 5)
        for line in lines:
            self.assertTrue(line.rstrip().endswith("\\"), f"missing continuation: {line!r}")
        self.assertIn('mountpoint) exec zfs get -H -o value mountpoint "$first" ;;', SCRIPT)

    def test_remote_script_never_destroys_recursively(self):
        # Finding 3: no recursive destroy on the local or remote side.
        self.assertNotIn("destroy -r", SCRIPT)
        self.assertNotIn("destroy-recursive", SCRIPT)

    def test_cleanup_is_registered_for_exit_as_well_as_return(self):
        # Finding 2: every failure path must clean up, so each drill registers
        # its cleanup for RETURN and for EXIT.
        for name in ("copyparty", "syncoid", "restic"):
            self.assertIn(f"trap cleanup_{name} RETURN", SCRIPT)
            self.assertIn(f"trap cleanup_{name} EXIT", SCRIPT)

    def test_cleanup_state_is_global_so_errexit_keeps_it(self):
        # Finding 2: bash unwinds function locals before running the EXIT trap,
        # so cleanup state must not live in locals.
        for name in (
            "_syncoid_owned_child",
            "_syncoid_owned_snapshot",
            "_syncoid_owned_target",
            "_syncoid_owned_clone",
            "_syncoid_child",
            "_syncoid_snapshot",
            "_syncoid_claim",
            "_syncoid_target_dataset",
            "_syncoid_clone",
        ):
            self.assertIn(f"{name}=", SCRIPT)
        self.assertNotIn("local owned_child", SCRIPT)
        self.assertNotIn("local restore_root", SCRIPT)
        self.assertNotIn("local temp", SCRIPT)

    def test_destination_preflight_runs_before_ownership_is_taken(self):
        # Finding 2: both destinations are proven unused before anything is created.
        create_at = SCRIPT.index('zfs create -- "$_syncoid_child"')
        for marker_text in (
            "local destination already exists",
            "remote destination already exists",
            "local clone destination already exists",
            "remote clone destination already exists",
        ):
            self.assertLess(SCRIPT.index(marker_text), create_at, marker_text)

    def test_destination_is_claimed_by_an_atomic_create_before_replication(self):
        # Claim-before-use: the destination name is taken by `zfs create`, which is
        # the only exclusive primitive available, and the drill replicates into a
        # child of that claim because syncoid refuses a pre-existing target.
        claim = SCRIPT.index('create "$_syncoid_claim"')
        replication = SCRIPT.index('syncoid --no-sync-snap "$_syncoid_child" "$syncoid_target"')
        self.assertLess(claim, replication)
        self.assertIn('_syncoid_target_dataset="$_syncoid_claim/replica"', SCRIPT)
        self.assertIn('remote_zfs "$_syncoid_host" create "$_syncoid_claim"', SCRIPT)

    def test_cleanup_requires_proven_ownership_of_the_destination(self):
        # Cleanup destroys the replica and its claim only behind the ownership flag
        # set after the replicated marker was read back, and never recursively.
        cleanup = SCRIPT.split("  cleanup_syncoid() {", 1)[1].split("\n  }", 1)[0]
        self.assertEqual(
            cleanup.count('"${_syncoid_owned_target:-false}" == false'),
            4,
            "the destination and its claim must both be gated on proven ownership, on the local and the remote branch",
        )
        self.assertIn('destroy "$_syncoid_target_dataset" >/dev/null 2>&1', cleanup)
        self.assertIn('destroy "$_syncoid_claim" >/dev/null 2>&1', cleanup)
        self.assertNotIn("destroy -r", cleanup)

    def test_restore_root_is_unique_and_trap_registered_after_it_exists(self):
        # Restore-root uniqueness: mktemp -d per run, cleanup registered after it
        # exists (already fixed in the tree, kept as a regression test).
        self.assertIn("_restic_restore_root=$(mktemp -d", SCRIPT)
        mktemp_at = SCRIPT.index("_restic_restore_root=$(mktemp -d")
        trap_at = SCRIPT.index("trap cleanup_restic RETURN")
        self.assertLess(mktemp_at, trap_at)

    def test_restic_restore_path_always_joins_with_a_separator(self):
        # Finding 8: a relative NAS_RESTIC_SOURCE must not be concatenated blindly.
        self.assertIn('restored="$_restic_restore_root/${NAS_RESTIC_SOURCE#/}/.$run_id"', SCRIPT)
        self.assertNotIn('restored="$_restic_restore_root${NAS_RESTIC_SOURCE}', SCRIPT)

    def test_copyparty_uses_unique_filename_per_run(self):
        # Finding 4: the upload goes to a run-unique name, never a fixed file that
        # a concurrent or earlier run could overwrite and delete.
        self.assertIn("nas-live-$stamp-$$.txt", SCRIPT)
        self.assertNotIn("nas-live-validation.txt", SCRIPT)
        self.assertNotIn("nas-live-$stamp.txt", SCRIPT)

    def test_temp_files_are_cleaned_when_an_allocation_fails(self):
        # Finding 7: cleanup is registered before either allocation, so a failed
        # second mktemp cannot leak the first file.
        trap = SCRIPT.index("trap cleanup_copyparty RETURN")
        first = SCRIPT.index("_copyparty_temp=$(mktemp)")
        second = SCRIPT.index("_copyparty_downloaded=$(mktemp)")
        self.assertLess(trap, first)
        self.assertLess(first, second)
        self.assertIn('rm -f -- "$_copyparty_temp"', SCRIPT)
        self.assertIn('rm -f -- "$_copyparty_downloaded"', SCRIPT)

    def test_observability_queries_after_the_final_wait(self):
        # Finding 6: query on every iteration, never sleep after the last query,
        # and keep the full 50 second window (11 queries, 10 sleeps).
        loop = SCRIPT.split("for ((i = 1; i <= 11; i++)); do", 1)[1].split("\n  done", 1)[0]
        query_at = loop.index("api/v1/query")
        fail_at = loop.index('fail "victoriaMetrics sample not visible')
        sleep_at = loop.index("sleep 5")
        self.assertLess(query_at, fail_at)
        self.assertLess(fail_at, sleep_at)
        self.assertEqual(loop.count("sleep 5"), 1)

    def test_confirm_accepts_exactly_one_drill_name(self):
        # Finding 11: the documented contract is exact matching, so no
        # confirmation list or other drill name authorizes a drill.
        env = dict(os.environ)
        env.pop("_LIVE_ALL_MODE", None)
        for value, expected_status in (
            ("SYNCOID_DRILL,RESTIC_DRILL", 1),
            ("RESTIC_DRILL", 1),
            ("SYNCOID_DRILL", 0),
        ):
            with self.subTest(value=value):
                env["NAS_LIVE_CONFIRM"] = value
                result = subprocess.run(
                    ["bash", "-c", PREFIX + "\nconfirm SYNCOID_DRILL\n"],
                    cwd=ROOT,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                self.assertEqual(result.returncode, expected_status, result.stderr)
                if expected_status:
                    self.assertIn("set NAS_LIVE_CONFIRM=SYNCOID_DRILL", result.stderr)

    def test_credential_escaping_failure_aborts_before_curl(self):
        # Finding 9: a rejected control character returns nonzero instead of
        # running curl with an empty credential.
        harness = Harness()
        self.addCleanup(harness.close)
        marker = harness.temporary / "curl-ran"
        curl = harness.bin / "curl"
        curl.write_text('#!/usr/bin/env bash\n: > "$FAKE_CURL_MARKER"\nexit 0\n', encoding="utf-8")
        curl.chmod(0o755)
        env = dict(harness.env)
        env["FAKE_CURL_MARKER"] = str(marker)
        command = PREFIX + "\ncurl_basic operator \"$(printf 'bad\\001token')\" http://127.0.0.1:1\n"
        result = subprocess.run(
            ["bash", "-c", command],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("curl_config_escape failed for password", result.stderr)
        self.assertFalse(marker.exists(), "curl ran with an empty credential")


if __name__ == "__main__":
    unittest.main()
