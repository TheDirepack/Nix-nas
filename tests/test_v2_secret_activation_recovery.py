"""Secret activation leaves V2 workload recovery to the target-wanted V2 reconcile.

The harness executes the real activation tail from ``secret-tools.nix`` and the
real secret transaction library. A small systemd model propagates protected
target stops to ``PartOf`` units and, like the installed unit graph, runs the
real V2 systemd reconcile whenever the protected target starts with secrets
ready. Native QEMU cases cover the real unit graph.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[1]
LIBRARY = ROOT / "scripts/lib/nas-secret-transaction.sh"
SECRET_TOOLS = ROOT / "modules/nas/internal/secret-tools.nix"
TARGET = "nas-protected-services.target"

COPYPARTY = "copyparty.service"
APP = "nas-v2-app.service"
GATE = "nas-v2-ready-app.service"
BROKEN = "nas-v2-broken.service"
JOB = "nas-v2-job.service"
TIMER = "nas-v2-timer-job-0.timer"
OFF = "nas-v2-off.service"
OUTPOST = "nas-authentik-proxy-outpost.service"
# Units the protected target starts itself (Requires/Wants in the Nix graph).
CORE = ("postgresql.service", "authentik.service", "authentik-worker.service", "caddy.service", OUTPOST)
# The outpost stops with Authentik through Requires=.
PART_OF_TARGET = (*CORE, COPYPARTY, APP, BROKEN)

FAKE_SYSTEMCTL = textwrap.dedent(
    """\
    import json, os, pathlib, sys

    sys.path.insert(0, os.environ["FAKE_SERVICES"])
    state_path = pathlib.Path(os.environ["FAKE_STATE"])
    config = json.loads(pathlib.Path(os.environ["FAKE_CONFIG"]).read_text())
    args = sys.argv[1:]
    with open(os.environ["FAKE_LOG"], "a") as log:
        log.write(" ".join(args) + "\\n")
    units = json.loads(state_path.read_text())

    def save():
        state_path.write_text(json.dumps(units))

    no_block = "--no-block" in args
    args = [a for a in args if not a.startswith("--") or a == "--no-block"]
    args = [a for a in args if a != "--no-block"]
    verb, names = args[0], args[1:]
    if verb == "show":
        if "--property=ConsistsOf" in sys.argv:
            # ConsistsOf: the units that are PartOf the target.
            print(" ".join(config["partOf"]) if names == [config["target"]] else "")
        else:
            print(units.get(names[0], "inactive"))
        sys.exit(0)
    if verb == "is-active":
        state = units.get(names[0], "inactive")
        print(state)
        sys.exit(0 if state == "active" else 3)
    if verb == "is-failed":
        sys.exit(0 if units.get(names[0]) == "failed" else 1)
    if verb == "reset-failed":
        for name in names:
            if units.get(name) == "failed":
                units[name] = "inactive"
        save()
        sys.exit(0)
    if verb == "stop":
        for name in names:
            units[name] = "inactive"
            if name == config["target"]:
                for member in config["partOf"]:
                    if units.get(member) != "failed":
                        units[member] = "inactive"
        save()
        sys.exit(0)
    if verb == "try-restart":
        sys.exit(0)
    if verb in {"start", "restart"}:
        status = 0
        for name in names:
            if name in config["failStart"]:
                units[name] = "failed"
                status = 0 if no_block else 1
                continue
            units[name] = "active"
            if name == config["target"]:
                for member in config["core"]:
                    units[member] = "active"
        save()
        if config["target"] in names and pathlib.Path(config["secretRoot"], "ready").is_file():
            # The target wants the reconcile; its ConditionPathExists is ready.
            import nas_v2_systemd_reconcile as reconcile
            result = reconcile.reconcile(
                manifest_path=pathlib.Path(config["manifest"]),
                projection_root=pathlib.Path(config["projection"]),
                systemd_runtime_dir=pathlib.Path(config["runtime"]),
                quadlet_runtime_dir=pathlib.Path(config["quadlet"]),
                state_path=pathlib.Path(config["reconcileState"]),
                systemctl=os.environ["FAKE_SYSTEMCTL"],
            )
            with open(config["results"], "a") as handle:
                handle.write(json.dumps(result) + "\\n")
        sys.exit(status)
    sys.exit(0)
    """
)


def activation_tail() -> str:
    source = SECRET_TOOLS.read_text(encoding="utf-8")
    activate = source.split("command_activate() (", 1)[1].split("command_status() {", 1)[0]
    start = activate.index("        nas_secret_tx_swap\n")
    end = activate.index("        nas_secret_tx_commit\n") + len("        nas_secret_tx_commit\n")
    tail = activate[start:end]
    tail = tail.replace("${toString authentikPort}${cfg.identity.authentikPath}", "9000/")
    if re.search(r"\$\{(?!unit\b)[a-z]", tail) or "''$" in tail:
        raise AssertionError("activation tail gained Nix interpolation the harness does not model")
    return tail


class SecretActivationRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.work = pathlib.Path(self._tmp.name)
        self.bin = self.work / "bin"
        self.bin.mkdir()
        projection = self.work / "projection"
        projection.mkdir()
        (self.work / "runtime").mkdir()
        (self.work / "quadlet").mkdir()
        bodies = {
            APP: "[Unit]\nPartOf=nas-protected-services.target\n[Service]\nExecStart=/bin/sleep infinity\n",
            GATE: f"[Unit]\nRequires={APP}\nAfter={APP}\n[Service]\nType=oneshot\nExecStart=/bin/true\n",
            BROKEN: "[Unit]\nPartOf=nas-protected-services.target\n[Service]\nExecStart=/bin/false\n",
            JOB: "[Service]\nType=oneshot\nExecStart=/bin/true\n",
            TIMER: f"[Timer]\nUnit={JOB}\nOnCalendar=daily\n",
            OFF: "[Service]\nExecStart=/bin/sleep infinity\n",
        }
        links = []
        for unit, body in bodies.items():
            (projection / unit).write_text(body, encoding="utf-8")
            links.append({"target": unit, "source": str(projection / unit)})
        manifest = projection / "manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "links": links,
                    "quadletLinks": [],
                    "ownedUnits": sorted([*bodies, COPYPARTY]),
                    "startUnits": sorted([COPYPARTY, APP, GATE, BROKEN, TIMER]),
                    "readinessUnits": [GATE],
                    "readinessOwners": {GATE: APP},
                    "stopUnits": [OFF],
                    "fingerprints": dict.fromkeys(bodies, "v1"),
                }
            ),
            encoding="utf-8",
        )
        self.secret_root = self.work / "secrets"
        self.config = {
            "target": TARGET,
            "partOf": list(PART_OF_TARGET),
            "core": list(CORE),
            "failStart": [],
            "secretRoot": str(self.secret_root),
            "manifest": str(manifest),
            "projection": str(projection),
            "runtime": str(self.work / "runtime"),
            "quadlet": str(self.work / "quadlet"),
            "reconcileState": str(self.work / "systemd-reconciled.json"),
            "results": str(self.work / "reconcile-results.jsonl"),
        }
        (self.work / "config.json").write_text(json.dumps(self.config), encoding="utf-8")
        (self.work / "fake_systemctl.py").write_text(FAKE_SYSTEMCTL, encoding="utf-8")
        self.systemctl = self.bin / "systemctl"
        self.systemctl.write_text(
            f'#!/usr/bin/env bash\nexec {sys.executable} -I {self.work / "fake_systemctl.py"} "$@"\n',
            encoding="utf-8",
        )
        self.systemctl.chmod(0o755)
        curl = self.bin / "curl"
        curl.write_text('#!/usr/bin/env bash\nexit "${FAKE_CURL_STATUS:-0}"\n', encoding="utf-8")
        curl.chmod(0o755)
        self.state = self.work / "units.json"
        self.log = self.work / "systemctl.log"
        self.env = {
            **os.environ,
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "FAKE_SERVICES": str(ROOT / "services"),
            "FAKE_STATE": str(self.state),
            "FAKE_CONFIG": str(self.work / "config.json"),
            "FAKE_LOG": str(self.log),
            "FAKE_SYSTEMCTL": str(self.systemctl),
        }

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def boot_unlocked(self) -> None:
        """Boot, unlock, and let the first reconcile start everything once."""
        self.secret_root.mkdir()
        (self.secret_root / "ready").write_text("old\n", encoding="utf-8")
        self.state.write_text(json.dumps({}), encoding="utf-8")
        self.systemctl_run("start", TARGET)
        units = self.units()
        self.assertEqual(units[COPYPARTY], "active")
        self.assertEqual(units[BROKEN], "active")
        # The workload completed its first scheduled run, and the broken app's
        # image has since become unavailable.
        units[JOB] = "inactive"
        self.state.write_text(json.dumps(units), encoding="utf-8")
        self.config["failStart"] = [BROKEN]
        (self.work / "config.json").write_text(json.dumps(self.config), encoding="utf-8")
        self.log.write_text("", encoding="utf-8")
        pathlib.Path(self.config["results"]).write_text("", encoding="utf-8")

    def systemctl_run(self, *args: str) -> None:
        subprocess.run([str(self.systemctl), *args], env=self.env, check=True, timeout=30)

    def units(self) -> dict[str, str]:
        return json.loads(self.state.read_text(encoding="utf-8"))

    def results(self) -> list[dict[str, Any]]:
        return [json.loads(line) for line in pathlib.Path(self.config["results"]).read_text().splitlines()]

    def activate(self, *, curl_status: int = 0) -> subprocess.CompletedProcess[str]:
        transaction = self.work / "transaction"
        transaction.mkdir()
        stage = transaction / "new"
        stage.mkdir()
        (stage / "ready").write_text("new\n", encoding="utf-8")
        script = textwrap.dedent(
            f"""\
            set -Eeuo pipefail
            export NAS_SECRET_TX_PRIVILEGE= NAS_SECRET_TX_LOGGER=
            sudo() {{ "$@"; }}
            setup_activation=false
            source {LIBRARY}
            nas_secret_tx_init {self.secret_root} {stage} {transaction / "previous"} {TARGET} {transaction}
            cleanup() {{
              local rc=$? status
              trap - EXIT
              set +e
              nas_secret_tx_cleanup "$rc"
              status=$?
              set -e
              [[ $status -ne 125 ]] || exit 125
              exit "$rc"
            }}
            trap cleanup EXIT
            """
        )
        script += activation_tail()
        return subprocess.run(
            ["bash", "-c", script],
            env={**self.env, "FAKE_CURL_STATUS": str(curl_status)},
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )

    def assert_v2_recovered(self) -> None:
        units = self.units()
        self.assertEqual(units[COPYPARTY], "active")
        self.assertEqual(units[APP], "active")
        self.assertEqual(units[GATE], "active")
        self.assertEqual(units[TIMER], "active")
        self.assertEqual(units[OUTPOST], "active")
        self.assertEqual(units.get(JOB), "inactive")
        self.assertEqual(units.get(OFF, "inactive"), "inactive")
        log = self.log.read_text(encoding="utf-8").splitlines()
        self.assertNotIn(f"start {JOB}", " | ".join(log))
        self.assertFalse(any(OFF in line for line in log if "start" in line))
        self.assertIn(f"--no-block start {APP} {GATE}", log)
        self.assertIn(f"--no-block start {COPYPARTY}", log)
        member_stop = f"stop -- {' '.join(PART_OF_TARGET)}"
        self.assertIn(member_stop, log)

    def test_same_boot_stop_then_activate_restores_expected_v2_units(self) -> None:
        self.boot_unlocked()
        # nas-secrets stop: readiness is revoked, then the target stops.
        (self.secret_root / "ready").unlink()
        self.systemctl_run("stop", TARGET)
        for unit in (COPYPARTY, APP):
            self.assertEqual(self.units()[unit], "inactive")
        self.assertEqual(self.units()[TIMER], "active")
        for child in self.secret_root.iterdir():
            child.unlink()
        self.secret_root.rmdir()
        self.log.write_text("", encoding="utf-8")

        result = self.activate()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.secret_root / "ready").read_text(), "new\n")
        self.assert_v2_recovered()
        # A broken workload never fails the commit. Recovery reports it only as
        # queued; its failed outcome is observed from systemd, not assumed.
        self.assertEqual(self.units()[BROKEN], "failed")
        [reconciled] = self.results()
        self.assertTrue(reconciled["noop"])
        self.assertIn(BROKEN, reconciled["recovery"]["queued"])

    def test_post_swap_failure_rolls_back_and_restores_expected_v2_units(self) -> None:
        self.boot_unlocked()

        result = self.activate(curl_status=7)

        self.assertEqual(result.returncode, 73, result.stdout + result.stderr)
        self.assertIn("Authentik readiness probe failed", result.stderr)
        self.assertEqual((self.secret_root / "ready").read_text(), "old\n")
        log = self.log.read_text(encoding="utf-8").splitlines()
        target_starts = [index for index, line in enumerate(log) if line == f"start {TARGET}"]
        self.assertEqual(len(target_starts), 2, log)
        # Rollback's target start recovered the workloads its swap stopped.
        self.assertIn(f"--no-block start {COPYPARTY}", log[target_starts[1] :])
        self.assertIn(f"--no-block start {APP} {GATE}", log[target_starts[1] :])
        self.assert_v2_recovered()
        self.assertEqual([entry["noop"] for entry in self.results()], [True, True])

    def test_activation_has_no_competing_v2_start_list(self) -> None:
        tail = activation_tail()
        self.assertNotIn("systemd-reconciled.json", SECRET_TOOLS.read_text(encoding="utf-8"))
        self.assertNotIn("startUnits", tail)

    def test_protected_target_wants_the_outpost_it_stops(self) -> None:
        # The harness models the outpost as target-wanted; keep that true.
        source = (ROOT / "modules/nas/config/application-services.nix").read_text(encoding="utf-8")
        outpost = source.split("systemd.services.nas-authentik-proxy-outpost = {", 1)[1].split("};", 1)[0]
        self.assertIn('wantedBy = [ "multi-user.target" "nas-protected-services.target" ];', outpost)
        self.assertIn('requires = [ "authentik.service"', outpost)


if __name__ == "__main__":
    unittest.main()
