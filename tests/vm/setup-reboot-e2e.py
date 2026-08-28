"""Installed-appliance setup persistence test.

This runner is deliberately stateful: the normal first-run guest suite creates
the pool and accounts, then this program proves that the completed appliance
survives two independently booted service stacks.  It is invoked through the
VM test wrapper so its Selenium dependencies stay out of the appliance image.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any


REPO = pathlib.Path("/var/lib/nas-test/repo")
STATE = pathlib.Path("/var/lib/nas-test/setup-reboot-e2e-state.json")
RESULT = pathlib.Path("/var/lib/nas-test/setup-reboot-e2e-result.json")
UNIT = pathlib.Path("/etc/systemd/system/nas-vm-setup-reboot-e2e.service")
SENTINEL = pathlib.Path("/tank/shares/e2e-reboot-sentinel.txt")
PUBLIC_ORIGIN = "https://nas-test.local:8443"
REQUIRED_UNITS = (
    "nas-protected-services.target",
    "caddy.service",
    "authentik.service",
    "copyparty.service",
    "syncthing.service",
    "vaultwarden.service",
    "victoriametrics.service",
    "telegraf.service",
    "nas-alert-router.service",
    "vmalert-nas.service",
    "grafana.service",
    "ntfy-sh.service",
)
REQUIRED_SERVICES = {
    "copyparty",
    "syncthing",
    "vaultwarden",
    "victoriametrics",
    "telegraf",
    "alert-router",
    "vmalert",
    "grafana",
    "notifications",
}


class CheckError(RuntimeError):
    """A concise, operator-useful E2E assertion failure."""


def run(*command: str, timeout: int = 120, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=False,
        text=True,
        input=input_text,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )


def require(command: tuple[str, ...], *, timeout: int = 120) -> str:
    result = run(*command, timeout=timeout)
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise CheckError(f"{' '.join(command)} failed ({result.returncode}): {detail[-1200:]}")
    return result.stdout


def write_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(path)


def read_state() -> dict[str, Any]:
    try:
        value = json.loads(STATE.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as error:
        raise CheckError(f"setup reboot lifecycle state is unavailable: {error}") from error
    if not isinstance(value, dict) or value.get("schemaVersion") != 1:
        raise CheckError("setup reboot lifecycle state has an unexpected format")
    return value


def wait_active(unit: str, timeout_seconds: int = 180) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if run("systemctl", "is-active", "--quiet", unit, timeout=15).returncode == 0:
            return
        time.sleep(2)
    status = run("systemctl", "status", "--no-pager", unit, timeout=30)
    raise CheckError(f"timed out waiting for {unit} to become active: {status.stdout[-1200:]}")


def wait_http(command: tuple[str, ...], label: str, timeout_seconds: int = 180) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if run(*command, timeout=30).returncode == 0:
            return
        time.sleep(2)
    raise CheckError(f"timed out waiting for {label}")


def managed_service_ids() -> set[str]:
    raw = require(("nas-managed-services-control", "status"))
    try:
        document = json.loads(raw)
        services = document["services"]
    except (json.JSONDecodeError, KeyError, TypeError) as error:
        raise CheckError("managed-services status did not return its V3 service list") from error
    if not isinstance(services, list):
        raise CheckError("managed-services status service list is not an array")
    service_ids: set[str] = set()
    for item in services:
        if not isinstance(item, dict):
            continue
        service_id = item.get("id")
        if isinstance(service_id, str):
            service_ids.add(service_id)
    return service_ids


def syncthing_api_key() -> str:
    key_path = pathlib.Path("/var/lib/syncthing/.config/syncthing/apikey")
    if key_path.is_file():
        value = key_path.read_text(encoding="utf-8").strip()
        if value:
            return value
    config = pathlib.Path("/var/lib/syncthing/.config/syncthing/config.xml")
    if config.is_file():
        import re

        match = re.search(r"<apikey>([^<]+)</apikey>", config.read_text(encoding="utf-8"))
        if match:
            return match.group(1)
    raise CheckError("Syncthing API key is unavailable")


def verify_services(stage: str) -> None:
    status = require(("nas-setup", "status"))
    try:
        setup = json.loads(status)
    except json.JSONDecodeError as error:
        raise CheckError("nas-setup status did not return JSON") from error
    if not all(setup.get(key) is True for key in ("runtimeSecretsActive", "poolPresent", "datasetPresent")):
        raise CheckError(f"setup is not complete after {stage}: {setup}")
    if not SENTINEL.is_file() or SENTINEL.read_text(encoding="utf-8") != "setup-reboot-e2e\n":
        raise CheckError(f"ZFS-backed setup sentinel did not survive {stage}")
    require(("zpool", "status", "-x", "tank"))
    require(("zfs", "list", "tank/nas"))
    mount = require(("findmnt", "-n", "-o", "FSTYPE,SOURCE,TARGET", "/tank"))
    if mount.split() != ["zfs", "tank/nas", "/tank"]:
        raise CheckError(f"/tank is not mounted from the created ZFS dataset after {stage}: {mount.strip()!r}")
    for unit in REQUIRED_UNITS:
        wait_active(unit)
    missing_services = REQUIRED_SERVICES - managed_service_ids()
    if missing_services:
        raise CheckError(f"V2 status lost required applications after {stage}: {sorted(missing_services)}")
    wait_http(
        (
            "curl",
            "--fail",
            "--silent",
            "--show-error",
            "--unix-socket",
            "/run/copyparty/http.sock",
            "http://localhost/",
        ),
        "CopyParty",
    )
    key = syncthing_api_key()
    wait_http(
        (
            "curl",
            "--fail",
            "--silent",
            "--show-error",
            "-H",
            f"X-API-Key: {key}",
            "http://127.0.0.1:8384/rest/system/status",
        ),
        "Syncthing",
    )
    wait_http(("curl", "--fail", "--silent", "--show-error", "http://127.0.0.1:8222/alive"), "Vaultwarden")
    wait_http(
        ("curl", "--fail", "--silent", "--show-error", "http://127.0.0.1:8428/victoriametrics/ping"), "VictoriaMetrics"
    )
    wait_http(("curl", "--fail", "--silent", "--show-error", "http://127.0.0.1:3000/api/health"), "Grafana")
    wait_http(("curl", "--fail", "--silent", "--show-error", "http://127.0.0.1:2586/v1/health"), "ntfy")


def browser_sign_in(stage: str) -> None:
    systemctl = shutil.which("systemctl")
    if not systemctl:
        raise CheckError("the VM browser proxy helpers are unavailable")
    systemd_root = pathlib.Path(os.path.realpath(systemctl)).parent.parent
    activate = systemd_root / "bin/systemd-socket-activate"
    proxyd = systemd_root / "lib/systemd/systemd-socket-proxyd"
    if not activate.is_file() or not proxyd.is_file():
        raise CheckError("the VM browser proxy helpers are unavailable")
    with tempfile.TemporaryDirectory(prefix="nas-e2e-authz-", dir="/run") as directory:
        secrets = pathlib.Path(directory)
        values = {
            "admin": "admin-vm-password",
            "operator": "operator-vm-password",
            "alice": "alice-updated-password",
            "baseline": "baseline-vm-password",
        }
        for name, value in values.items():
            path = secrets / name
            path.write_text(value + "\n", encoding="utf-8")
            path.chmod(0o600)
        proxy = subprocess.Popen(
            [str(activate), "--listen", "127.0.0.1:8443", str(proxyd), "127.0.0.1:443"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            wait_http(
                (
                    "curl",
                    "--insecure",
                    "--fail",
                    "--silent",
                    "--show-error",
                    "--resolve",
                    "nas-test.local:8443:127.0.0.1",
                    "https://nas-test.local:8443/identity/",
                ),
                "browser callback proxy",
                60,
            )
            environment = {**os.environ, "NAS_BROWSER_HOST_ADDRESS": "127.0.0.1"}
            command = [
                sys.executable,
                str(REPO / "tests/browser/authz.py"),
                "--origin",
                PUBLIC_ORIGIN,
                "--cockpit-password-file",
                str(secrets / "admin"),
                "--operator-password-file",
                str(secrets / "operator"),
                "--alice-password-file",
                str(secrets / "alice"),
                "--baseline-password-file",
                str(secrets / "baseline"),
            ]
            result = subprocess.run(
                command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600, env=environment
            )
            if result.returncode:
                raise CheckError(
                    f"authenticated browser checks failed after {stage}: {(result.stderr or result.stdout)[-2400:]}"
                )
        finally:
            proxy.terminate()
            try:
                proxy.wait(timeout=20)
            except subprocess.TimeoutExpired:
                proxy.kill()
                proxy.wait(timeout=20)


def schedule_reboot(next_phase: str) -> None:
    write_json(STATE, {"schemaVersion": 1, "phase": next_phase})
    require(("systemctl", "daemon-reload"))
    require(("systemctl", "enable", UNIT.name))
    require(("systemd-run", f"--unit=nas-vm-setup-reboot-e2e-{next_phase}", "--on-active=3s", "systemctl", "reboot"))


def install_resume_unit() -> None:
    command = "/run/current-system/sw/bin/nas-vm-guest-test --setup-reboot-e2e --resume"
    UNIT.write_text(
        "[Unit]\nDescription=NAS VM setup reboot E2E continuation\n"
        "Wants=network-online.target\nAfter=network-online.target\nConditionPathExists=" + str(STATE) + "\n\n"
        "[Service]\nType=oneshot\nExecStart=" + command + "\n\n"
        "[Install]\nWantedBy=multi-user.target\n",
        encoding="utf-8",
    )
    UNIT.chmod(0o644)


def start() -> None:
    if STATE.exists() or RESULT.exists():
        raise CheckError("setup reboot E2E evidence already exists; use a fresh disposable VM")
    SENTINEL.parent.mkdir(mode=0o2770, parents=True, exist_ok=True)
    SENTINEL.write_text("setup-reboot-e2e\n", encoding="utf-8")
    install_resume_unit()
    verify_services("initial setup")
    schedule_reboot("after-first-reboot")


def finish(ok: bool, **extra: Any) -> None:
    payload: dict[str, Any] = {"schemaVersion": 1, "ok": ok, "completedAt": int(time.time()), **extra}
    write_json(RESULT, payload)


def resume() -> None:
    try:
        phase = read_state().get("phase")
        if phase == "after-first-reboot":
            verify_services("the first reboot")
            browser_sign_in("the first reboot")
            schedule_reboot("after-second-reboot")
            return
        if phase == "after-second-reboot":
            verify_services("the second reboot")
            browser_sign_in("the second reboot")
            require(("systemctl", "disable", UNIT.name))
            UNIT.unlink(missing_ok=True)
            require(("systemctl", "daemon-reload"))
            finish(True, phase="complete", verifiedReboots=2)
            return
        raise CheckError(f"unexpected setup reboot lifecycle phase: {phase!r}")
    except Exception as error:
        finish(False, error=f"{type(error).__name__}: {error}")
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify completed setup across two appliance reboots")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--start", action="store_true")
    group.add_argument("--resume", action="store_true")
    arguments = parser.parse_args()
    try:
        if arguments.start:
            start()
        else:
            resume()
    except Exception as error:
        print(f"setup reboot E2E failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
