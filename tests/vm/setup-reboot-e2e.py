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
SENTINEL = pathlib.Path("/tank/shares/e2e-reboot-sentinel.txt")
PUBLIC_ORIGIN = "https://nas-test.local:8443"
REQUIRED_UNITS = (
    "nas-protected-services.target",
    "caddy.service",
    "authentik.service",
    "nas-authentik-proxy-outpost.service",
    "nas-cockpit-sso.service",
    "copyparty.service",
    "syncthing.service",
    "vaultwarden.service",
    "victoriametrics.service",
    "telegraf.service",
    "alertmanager.service",
    "alertmanager-ntfy.service",
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
    "alertmanager",
    "vmalert",
    "grafana",
    "notifications",
}
BRIDGE_UNITS = (
    "caddy.service",
    "nas-cockpit-sso.service",
    "authentik.service",
    "nas-authentik-proxy-outpost.service",
)


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


def failure_diagnostics() -> str:
    """Bounded, read-only bridge-unit state before the failing VM is discarded."""
    sections: list[str] = []
    failed = run("systemctl", "--failed", "--no-pager", timeout=30)
    sections.append(f"failed units:\n{(failed.stdout or failed.stderr)[-1500:]}")
    for unit in BRIDGE_UNITS:
        state = run(
            "systemctl",
            "show",
            unit,
            "--property=ActiveState,SubState,NRestarts,Result,ExecMainStartTimestampMonotonic,"
            "ExecMainExitTimestampMonotonic",
            timeout=15,
        )
        sections.append(f"{unit}:\n{(state.stdout or state.stderr).strip()}")
    journal = run(
        "journalctl",
        "-b",
        "-u",
        "caddy.service",
        "-u",
        "nas-cockpit-sso.service",
        "-n",
        "120",
        "--no-pager",
        timeout=30,
    )
    sections.append(f"caddy and cockpit bridge journal:\n{(journal.stdout or journal.stderr)[-6000:]}")
    return "\n".join(sections)


def report_failure(error: Exception) -> None:
    print(f"setup reboot E2E failed: {error}", file=sys.stderr, flush=True)
    try:
        print(failure_diagnostics(), file=sys.stderr, flush=True)
    except Exception as diagnostic_error:
        print(f"failure diagnostics unavailable: {diagnostic_error}", file=sys.stderr, flush=True)


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
    failed = run("systemctl", "--failed", "--no-pager", timeout=30)
    journal = run(
        "journalctl",
        "-b",
        "-u",
        "nas-managed-services-reconcile.service",
        "-u",
        "nas-v2-apply-failed.service",
        "-n",
        "70",
        "--no-pager",
        timeout=30,
    )
    raise CheckError(
        f"timed out waiting for {unit} to become active: {status.stdout[-1200:]}\n"
        f"failed units: {failed.stdout[-1000:]}\n"
        f"reconcile journal: {journal.stdout[-5500:]}"
    )


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


UNLOCK_SOCKET = "/run/nas-unlock/unlock.sock"
KEEPASS_PASSWORD = "nixos-nas-vm-test-password"
LOCKED_REDIRECT_ROUTES = (
    "/",
    "/console/",
    "/setup/",
    "/setup/api/first-start",
    "/identity/if/user/",
    "/identity/if/admin/",
    "/shares/",
    "/index.html/",
)


def locked_request(path: str, *extra: str) -> tuple[str, str, str]:
    result = run(
        "curl",
        "--insecure",
        "--silent",
        "--show-error",
        "--max-time",
        "20",
        "--resolve",
        "nas-test.local:443:127.0.0.1",
        "--write-out",
        "\n%{http_code} %{redirect_url}",
        *extra,
        f"https://nas-test.local{path}",
        timeout=30,
    )
    if result.returncode:
        raise CheckError(f"locked route {path} was unreachable: {result.stderr.strip()[-400:]}")
    body, _, trailer = result.stdout.rpartition("\n")
    code, _, location = trailer.partition(" ")
    return code, location, body


def unlock_api(payload: str) -> tuple[str, dict[str, Any]]:
    """Call nas-unlock-api exactly as the locked Caddy route forwards a nas_admin request."""
    result = run(
        "curl",
        "--silent",
        "--show-error",
        "--max-time",
        "900",
        "--unix-socket",
        UNLOCK_SOCKET,
        "--header",
        "Host: nas-test.local",
        "--header",
        "Origin: https://nas-test.local",
        "--header",
        "Remote-User: nasadmin",
        "--header",
        "Remote-Groups: nas_admin",
        "--header",
        "Content-Type: application/json",
        "--data-binary",
        "@-",
        "--write-out",
        "\n%{http_code}",
        "http://nas-test.local/unlock/api/activate",
        input_text=payload,
        timeout=960,
    )
    if result.returncode:
        raise CheckError(f"nas-unlock-api was unreachable: {result.stderr.strip()[-400:]}")
    body, _, code = result.stdout.rpartition("\n")
    try:
        document = json.loads(body)
    except json.JSONDecodeError as exc:
        raise CheckError(f"nas-unlock-api returned non-JSON (HTTP {code}): {body[-400:]}") from exc
    return code, document


def verify_locked_browser_surface() -> None:
    """After setup, a locked boot serves only Authentik sign-in and the gated unlock page."""
    for unit in ("caddy.service", "authentik.service", "nas-authentik-proxy-outpost.service", "nas-unlock-api.service"):
        wait_active(unit)
    for path in LOCKED_REDIRECT_ROUTES:
        code, location, _body = locked_request(path)
        if code != "303" or not location.endswith("/unlock/"):
            raise CheckError(f"locked route {path} did not redirect to /unlock/ (HTTP {code} {location})")
    # The outpost's systemd unit is active before its forward-auth listener is ready.
    deadline = time.monotonic() + 180
    while True:
        code, location, body = locked_request("/unlock/")
        if code in {"302", "303", "307"} and location and "unlock-form" not in body:
            break
        if code != "503" or "unlock-form" in body or time.monotonic() >= deadline:
            raise CheckError(f"unauthenticated /unlock/ was not sent to Authentik sign-in (HTTP {code} {location})")
        time.sleep(2)
    code, _location, body = locked_request(
        "/unlock/api/activate",
        "--request",
        "POST",
        "--header",
        "Content-Type: application/json",
        "--header",
        "Remote-Groups: nas_admin",
        "--header",
        "Remote-User: nasadmin",
        "--data",
        json.dumps({"password": KEEPASS_PASSWORD}),
    )
    if code.startswith("2") or "unlocked" in body:
        raise CheckError(f"unauthenticated unlock submission reached nas-unlock-api (HTTP {code})")
    code, _location, _body = locked_request("/identity/-/health/live/")
    if code not in {"200", "204"}:
        raise CheckError(f"Authentik sign-in is not served while locked (HTTP {code})")
    code, _location, body = locked_request("/setup/api/reboot", "--request", "POST", "--data", "{}")
    if code != "303" or "rebooting" in body:
        raise CheckError(f"locked setup API reboot route reached a backend (HTTP {code})")
    if pathlib.Path("/var/lib/nas-control-plane/authentik/api-token").exists():
        raise CheckError("a superuser Authentik API token is stored on disk while locked")
    if not pathlib.Path("/var/lib/nas-control-plane/authentik/outpost-token").is_file():
        raise CheckError("the boot-side Authentik outpost token is missing")


def authentik_started_at() -> int:
    value = require(("systemctl", "show", "--value", "--property=ActiveEnterTimestampMonotonic", "authentik.service"))
    return int(value.strip() or "0")


def activate_after_reboot() -> None:
    status = json.loads(require(("nas-setup", "status")))
    if (
        status.get("runtimeSecretsActive")
        or run("systemctl", "is-active", "--quiet", "nas-protected-services.target").returncode == 0
    ):
        raise CheckError("protected services or runtime secrets remained active across the locked reboot")
    verify_locked_browser_surface()
    require(("nas-vm-guest-test", "--oci-probe", "locked"))
    require(("zpool", "import", "-N", "tank"))
    code, document = unlock_api(json.dumps({"password": "not-the-keepass-password"}))
    if code != "401":
        raise CheckError(f"nas-unlock-api accepted or mishandled a wrong password (HTTP {code}): {document}")
    wait_active("authentik.service", timeout_seconds=120)
    time.sleep(6)
    locked_started = authentik_started_at()
    code, document = unlock_api(json.dumps({"password": KEEPASS_PASSWORD}))
    if code != "200" or document.get("unlocked") is not True:
        failed = run("systemctl", "--failed", "--no-pager", timeout=30)
        journal = run("journalctl", "-b", "-n", "90", "--no-pager", timeout=30)
        raise CheckError(
            f"browser unlock failed (HTTP {code}): {document}\n"
            f"failed units: {failed.stdout[-1200:]}\n"
            f"activation journal: {journal.stdout[-7000:]}"
        )
    wait_active("nas-authentik-proxy-outpost.service", timeout_seconds=120)
    if authentik_started_at() <= locked_started:
        raise CheckError("Authentik was not restarted with the KeePassXC environment after unlock")
    if pathlib.Path("/var/lib/nas-control-plane/authentik/environment").exists():
        raise CheckError("the plaintext first-boot Authentik environment survived unlock")


def verify_services(stage: str) -> None:
    require(("nas-vm-guest-test", "--oci-probe", "verify", "--stage", stage))
    status = require(("nas-setup", "status"))
    try:
        setup = json.loads(status)
    except json.JSONDecodeError as error:
        raise CheckError("nas-setup status did not return JSON") from error
    health = {key: setup.get(key) for key in ("runtimeSecretsActive", "poolPresent", "datasetPresent")}
    if not all(value is True for value in health.values()):
        raise CheckError(f"setup is not complete after {stage}: {health}")
    if run("systemctl", "is-failed", "--quiet", "nas-v2-apply-failed.service").returncode == 0:
        raise CheckError(f"Managed Services V2 rollback is failed after {stage}")
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
    wait_http(("curl", "--fail", "--silent", "--show-error", "http://127.0.0.1:8222/vault/alive"), "Vaultwarden")
    wait_http(
        ("curl", "--fail", "--silent", "--show-error", "http://127.0.0.1:8428/victoriametrics/ping"), "VictoriaMetrics"
    )
    wait_http(("curl", "--fail", "--silent", "--show-error", "http://127.0.0.1:9093/-/ready"), "Alertmanager")
    wait_http(("curl", "--fail", "--silent", "--show-error", "http://127.0.0.1:3000/api/health"), "Grafana")
    wait_http(("curl", "--fail", "--silent", "--show-error", "http://127.0.0.1:2586/v1/health"), "ntfy")
    wait_http(
        (
            "curl",
            "--fail",
            "--silent",
            "--show-error",
            "--max-time",
            "10",
            "--unix-socket",
            "/run/nas-cockpit-sso/ws.sock",
            "http://localhost/console/",
        ),
        "Cockpit",
    )
    wait_http(
        ("curl", "--fail", "--silent", "--show-error", "http://127.0.0.1:9010/outpost.goauthentik.io/ping"),
        "Authentik proxy outpost",
    )


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
            "administrator": "nasadmin-vm-password",
            "operator": "operator-vm-password",
            "alice": "alice-updated-password",
            "baseline": "baseline-vm-password",
            "post-a": "post-a-vm-password",
            "post-b": "post-b-vm-password",
        }
        for name, value in values.items():
            path = secrets / name
            path.write_text(value + "\n", encoding="utf-8")
            path.chmod(0o600)
        # Inherit the journal stream: an unread stderr pipe can stall the proxy.
        # Keep SIGPIPE ignored so a closed browser connection cannot kill the proxy.
        proxy = subprocess.Popen(
            [str(activate), "--listen", "127.0.0.1:8443", str(proxyd), "127.0.0.1:443"],
            stdout=subprocess.DEVNULL,
            stderr=sys.stderr,
            text=True,
            restore_signals=False,
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
                "--administrator-password-file",
                str(secrets / "administrator"),
                "--operator-password-file",
                str(secrets / "operator"),
                "--alice-password-file",
                str(secrets / "alice"),
                "--baseline-password-file",
                str(secrets / "baseline"),
                "--post-a-password-file",
                str(secrets / "post-a"),
                "--post-b-password-file",
                str(secrets / "post-b"),
            ]
            result = subprocess.run(
                command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600, env=environment
            )
            if result.returncode:
                detail = result.stderr or result.stdout
                print(detail, file=sys.stderr, flush=True)
                print(f"browser callback proxy exit status: {proxy.poll()}", file=sys.stderr, flush=True)
                raise CheckError(
                    f"authenticated browser checks failed after {stage}: {detail[:1100]}\n{detail[-1900:]}"
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
    require(("systemd-run", f"--unit=nas-vm-setup-reboot-e2e-{next_phase}", "--on-active=3s", "systemctl", "reboot"))


def start() -> None:
    if STATE.exists() or RESULT.exists():
        raise CheckError("setup reboot E2E evidence already exists; use a fresh disposable VM")
    SENTINEL.parent.mkdir(mode=0o2770, parents=True, exist_ok=True)
    SENTINEL.write_text("setup-reboot-e2e\n", encoding="utf-8")
    verify_services("initial setup")
    schedule_reboot("after-first-reboot")


def finish(ok: bool, **extra: Any) -> None:
    payload: dict[str, Any] = {"schemaVersion": 1, "ok": ok, "completedAt": int(time.time()), **extra}
    write_json(RESULT, payload)


def verify_reboot(stage: str) -> None:
    activate_after_reboot()
    verify_services(stage)
    browser_sign_in(stage)


def resume() -> None:
    try:
        phase = read_state().get("phase")
        if phase == "after-first-reboot":
            verify_reboot("the first reboot")
            schedule_reboot("after-second-reboot")
            return
        if phase == "after-second-reboot":
            verify_reboot("the second reboot")
            finish(True, phase="complete", verifiedReboots=2)
            STATE.unlink()
            return
        raise CheckError(f"unexpected setup reboot lifecycle phase: {phase!r}")
    except Exception as error:
        # The host treats the result file as completion and may discard the VM
        # immediately, so flush failure evidence before publishing that result.
        report_failure(error)
        finish(False, error=f"{type(error).__name__}: {error}")
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify completed setup across two appliance reboots")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--start", action="store_true")
    group.add_argument("--resume", action="store_true")
    group.add_argument("--verify", action="store_true")
    arguments = parser.parse_args()
    try:
        if arguments.start:
            start()
        elif arguments.verify:
            verify_reboot("the final reboot")
        else:
            resume()
    except Exception as error:
        if not arguments.resume:
            report_failure(error)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
