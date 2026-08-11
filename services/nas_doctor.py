#!/usr/bin/env python3
"""Produce one machine-readable appliance authority, drift, and recovery report."""

from __future__ import annotations

import argparse
import grp
import json
import os
import pathlib
import re
import stat
import time
from dataclasses import asdict, dataclass
from typing import Any, Mapping

from nas_operation_lock import COORDINATION_TOKEN_ENV, OPERATION_ROOT, operation_state
from nas_state import StateError, authorities, ensure_safe_tree, registry_digest

VERSION_FILE = pathlib.Path(os.environ.get("NAS_VERSION_FILE", pathlib.Path(__file__).resolve().parents[1] / "VERSION"))
SETUP_STATE = pathlib.Path(os.environ.get("NAS_SETUP_STATE", "/var/lib/nas-setup/state.json"))
SETUP_JOURNAL = pathlib.Path(os.environ.get("NAS_SETUP_JOURNAL", "/var/lib/nas-setup/first-run-journal.json"))
FIRST_START_STATUS = pathlib.Path(os.environ.get("NAS_FIRST_START_STATUS", "/var/lib/nas-first-start/status.json"))
MANAGED_SERVICES_SPEC = pathlib.Path(os.environ.get("NAS_V2_SPEC", "/var/lib/nas-control/services.yaml"))
MANAGED_SERVICES_SCHEMA = pathlib.Path(
    os.environ.get("NAS_V2_SCHEMA", "/etc/nas-control/managed-services-v3.schema.json")
)
MANAGED_SERVICES_PLATFORM = pathlib.Path(
    os.environ.get("NAS_V2_PLATFORM", "/run/nas-control/platform-capabilities.json")
)
MANAGED_SERVICES_PLATFORM_FALLBACK = pathlib.Path("/etc/nas-control/platform-capabilities.json")
MANAGED_SERVICES_EFFECTIVE = pathlib.Path(os.environ.get("NAS_V2_EFFECTIVE", "/run/nas-control/effective.json"))
ALERT_ROUTER_STATE = pathlib.Path(os.environ.get("NAS_ALERT_ROUTER_STATE", "/var/lib/nas-alert-router/state.json"))
OPERATION_GROUP = os.environ.get("NAS_OPERATION_GROUP", "nas-operations")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+-[A-Za-z0-9.-]+$")
LEVELS = {"ok": 0, "info": 0, "warning": 1, "critical": 2, "indeterminate": 1}


@dataclass(frozen=True)
class Check:
    id: str
    status: str
    summary: str
    detail: str | None = None
    remediation: str | None = None


class ManagedServicesDiagnosticError(RuntimeError):
    """Expected V2 compiler/host-inventory failure while diagnosing desired state."""


def _read_json(path: pathlib.Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{path}: top-level value is not an object")
    return value


def _version_check() -> Check:
    try:
        version = VERSION_FILE.read_text(encoding="utf-8").strip()
    except OSError as exc:
        return Check("release.version", "critical", "Release version is unavailable", str(exc))
    if not VERSION_RE.fullmatch(version):
        return Check("release.version", "critical", "Release version is invalid", version)
    return Check("release.version", "ok", f"Running source version {version}")


def _setup_checks() -> list[Check]:
    checks: list[Check] = []
    try:
        state = _read_json(SETUP_STATE)
        journal = _read_json(SETUP_JOURNAL)
        first = _read_json(FIRST_START_STATUS)
    except ValueError as exc:
        return [
            Check(
                "setup.state",
                "critical",
                "Setup state is unreadable",
                str(exc),
                "Inspect and restore the setup journal/state from a trusted backup",
            )
        ]
    journal_status = (journal or {}).get("status")
    if journal_status == "manual-recovery-required":
        checks.append(
            Check(
                "setup.journal",
                "critical",
                "First-start requires manual recovery",
                str((journal or {}).get("error") or "journal stopped at a non-compensatable boundary"),
                "Use nas-setup status and reconcile-first-run before retrying",
            )
        )
    elif journal_status == "failed":
        checks.append(
            Check(
                "setup.journal",
                "warning",
                "First-start journal records a failed attempt",
                str((journal or {}).get("error") or "unknown failure"),
            )
        )
    elif journal_status in {"running", "prepared"}:
        checks.append(Check("setup.journal", "info", f"First-start journal is {journal_status}"))
    elif journal_status == "complete":
        checks.append(Check("setup.journal", "ok", "First-start journal is committed"))
    elif journal is not None:
        checks.append(
            Check("setup.journal", "warning", "First-start journal has an unknown status", str(journal_status))
        )

    state_status = (state or {}).get("status")
    if state_status in {"complete", "complete-unverified"}:
        digest = (state or {}).get("planDigest")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            checks.append(Check("setup.state", "critical", "Completed setup state has no valid plan digest"))
        elif state_status == "complete-unverified":
            checks.append(
                Check(
                    "setup.state",
                    "warning",
                    "Setup completed without final host preflight",
                    remediation="Run the complete preflight and refresh first-start readiness",
                )
            )
        else:
            checks.append(Check("setup.state", "ok", "Setup state is complete and bound to a plan digest"))
    elif state is None:
        status = first.get("status") if first else None
        if status in {"ready", "configuration-invalid", "missing-config"}:
            checks.append(Check("setup.state", "info", f"Initial setup is not complete ({status})"))
        else:
            checks.append(Check("setup.state", "warning", "Setup state is absent and first-start readiness is unknown"))
    else:
        checks.append(
            Check("setup.state", "critical", "Setup state has an invalid completion status", str(state_status))
        )

    if state_status in {"complete", "complete-unverified"} and journal_status != "complete":
        checks.append(
            Check(
                "setup.commit-consistency",
                "critical",
                "Durable setup state and journal commit disagree",
                f"state={state_status}, journal={journal_status}",
            )
        )
    return checks


def _managed_services_platform_path() -> pathlib.Path:
    if MANAGED_SERVICES_PLATFORM.exists():
        return MANAGED_SERVICES_PLATFORM
    return MANAGED_SERVICES_PLATFORM_FALLBACK


def _compile_managed_services() -> dict[str, Any]:
    # Keep the diagnostic command's parser/help surface independent from the
    # runtime-adapter dependency graph. Installed nas-doctor has the complete
    # V2 dependency set; source-level CLI tests should not need libvirt/XML
    # packages merely to parse argv.
    try:
        from nas_v2_accelerator import AcceleratorResolutionError
        from nas_v2_apply import ApplyPaths, compile_paths
        from nas_v2_spec import ManagedServicesV2Error
    except ImportError as exc:
        raise ManagedServicesDiagnosticError(
            f"Managed Services V2 compiler dependencies are unavailable: {exc}"
        ) from exc

    try:
        expected, _plan = compile_paths(
            ApplyPaths(
                desired=MANAGED_SERVICES_SPEC,
                schema=MANAGED_SERVICES_SCHEMA,
                platform=_managed_services_platform_path(),
                effective=MANAGED_SERVICES_EFFECTIVE,
                plan=MANAGED_SERVICES_EFFECTIVE.with_name("plan.json"),
            )
        )
    except (ManagedServicesV2Error, AcceleratorResolutionError) as exc:
        raise ManagedServicesDiagnosticError(str(exc)) from exc
    return expected


def _managed_services_check() -> Check:
    try:
        expected = _compile_managed_services()
    except ManagedServicesDiagnosticError as exc:
        return Check(
            "runtime.managed-services",
            "critical",
            "Managed Services V2 desired state is invalid for this host",
            str(exc),
            "Repair services.yaml with nas-managed-services-control document/replace-document, then reconcile",
        )
    except OSError as exc:
        return Check(
            "runtime.managed-services",
            "critical",
            "Managed Services V2 authority or installed validation metadata is unreadable",
            str(exc),
        )

    try:
        effective = _read_json(MANAGED_SERVICES_EFFECTIVE)
    except ValueError as exc:
        return Check(
            "runtime.managed-services",
            "critical",
            "Managed Services V2 effective state is unreadable",
            str(exc),
            "Run nas-managed-services-control reconcile after repairing the runtime state",
        )
    if effective is None:
        return Check(
            "runtime.managed-services",
            "warning",
            "Managed Services V2 effective state is absent",
            str(MANAGED_SERVICES_EFFECTIVE),
            "Run nas-managed-services-control reconcile",
        )
    if effective != expected:
        expected_generation = expected.get("generation")
        actual_generation = effective.get("generation")
        return Check(
            "runtime.managed-services",
            "critical",
            "Managed Services V2 effective state does not match services.yaml and current host inventory",
            f"desiredGeneration={expected_generation}, effectiveGeneration={actual_generation}",
            "Run nas-managed-services-control reconcile; if drift remains, inspect the finite compiler/reconciler",
        )
    services = expected.get("services")
    count = len(services) if isinstance(services, dict) else 0
    return Check(
        "runtime.managed-services",
        "ok",
        f"Managed Services V2 authority is valid and reconciled ({count} services)",
        str(MANAGED_SERVICES_SPEC),
    )


def _operation_hygiene_checks(*, deep: bool) -> list[Check]:
    checks: list[Check] = []
    if os.environ.get("NAS_OPERATION_COORDINATED"):
        checks.append(
            Check(
                "operations.legacy-environment",
                "warning",
                "Legacy NAS_OPERATION_COORDINATED is set but no longer authorizes nested mutations",
                remediation="Remove the stale environment variable from the shell or service environment",
            )
        )
    if os.environ.get(COORDINATION_TOKEN_ENV):
        checks.append(
            Check(
                "operations.inherited-token",
                "warning",
                "An operation coordination token is present in this diagnostic environment",
                remediation="Run nas-doctor from a clean administrator shell unless it is intentionally nested inside an active NAS operation",
            )
        )
    if not deep:
        return checks
    try:
        metadata = OPERATION_ROOT.lstat()
    except FileNotFoundError:
        checks.append(
            Check(
                "operations.root-policy",
                "warning",
                "Operation coordinator runtime directory is absent",
                str(OPERATION_ROOT),
                "Verify systemd-tmpfiles created the nas-operations runtime directory before privileged administration",
            )
        )
        return checks
    except OSError as exc:
        checks.append(
            Check(
                "operations.root-policy",
                "warning",
                "Operation coordinator runtime directory cannot be inspected",
                str(exc),
            )
        )
        return checks
    try:
        expected_gid = grp.getgrnam(OPERATION_GROUP).gr_gid
    except KeyError:
        checks.append(
            Check("operations.root-policy", "critical", "Dedicated NAS operation group is missing", OPERATION_GROUP)
        )
        return checks
    actual_mode = stat.S_IMODE(metadata.st_mode)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != expected_gid
        or actual_mode != 0o2770
    ):
        checks.append(
            Check(
                "operations.root-policy",
                "critical",
                "Operation coordinator runtime directory ownership or mode is unsafe",
                f"path={OPERATION_ROOT}, uid={metadata.st_uid}, gid={metadata.st_gid}, mode={actual_mode:04o}; expected uid=0, gid={expected_gid}, mode=2770",
                "Restore the systemd-tmpfiles policy and recreate the runtime directory before privileged mutations",
            )
        )
    else:
        checks.append(
            Check(
                "operations.root-policy",
                "ok",
                "Operation coordinator runtime directory has the expected owner/group/mode",
            )
        )
    return checks


def _alert_router_state_checks() -> list[Check]:
    parent = ALERT_ROUTER_STATE.parent
    try:
        corrupt = sorted(parent.glob(f"{ALERT_ROUTER_STATE.name}.corrupt-*"))
    except OSError as exc:
        return [Check("alerts.router-state", "warning", "Alert-router recovery state cannot be inspected", str(exc))]
    if corrupt:
        newest = corrupt[-1]
        return [
            Check(
                "alerts.router-state",
                "warning",
                "Alert-router state corruption was quarantined",
                f"{len(corrupt)} quarantined file(s); newest={newest}",
                "Inspect notification delivery history and remove quarantined state only after determining the corruption cause",
            )
        ]
    return [Check("alerts.router-state", "ok", "No quarantined alert-router state is present")]


def _authority_checks(deep: bool) -> tuple[list[Check], str | None]:
    checks: list[Check] = []
    try:
        registry = authorities()
        digest = registry_digest(registry)
    except StateError as exc:
        return [Check("state.registry", "critical", "State authority registry is invalid", str(exc))], None
    checks.append(Check("state.registry", "ok", f"State authority registry contains {len(registry)} entries", digest))
    for authority in registry:
        if authority.kind == "database":
            status = "indeterminate" if not deep else "info"
            summary = (
                "Database authority requires an export/diff probe"
                if not deep
                else "Database authority is registered for deep nas-state comparison"
            )
            checks.append(Check(f"state.authority.{authority.name}", status, summary, authority.source))
            continue
        path = pathlib.Path(authority.source)
        try:
            mode = path.lstat().st_mode
        except FileNotFoundError:
            if authority.optional:
                checks.append(
                    Check(f"state.authority.{authority.name}", "ok", "Optional authority is absent", authority.source)
                )
            else:
                checks.append(
                    Check(
                        f"state.authority.{authority.name}",
                        "critical",
                        "Required state authority is absent",
                        authority.source,
                    )
                )
            continue
        try:
            if stat.S_ISLNK(mode):
                raise StateError(f"authority root is a symlink: {path}")
            ensure_safe_tree(path)
        except (OSError, StateError) as exc:
            checks.append(
                Check(
                    f"state.authority.{authority.name}",
                    "critical",
                    "State authority contains an unsafe object",
                    str(exc),
                )
            )
            continue
        checks.append(
            Check(
                f"state.authority.{authority.name}",
                "ok",
                "State authority is present and structurally safe",
                authority.source,
            )
        )
    return checks, digest


def build_report(*, deep: bool = False) -> dict[str, Any]:
    checks: list[Check] = [
        _version_check(),
        *_setup_checks(),
        _managed_services_check(),
        *_operation_hygiene_checks(deep=deep),
        *_alert_router_state_checks(),
    ]
    authority, digest = _authority_checks(deep)
    checks.extend(authority)

    try:
        operations = operation_state()
    except OSError as exc:
        operations = {"busyClasses": [], "active": [], "error": str(exc)}
        checks.append(Check("operations.coordinator", "warning", "Operation coordinator is unreadable", str(exc)))
    else:
        if operations.get("busyClasses"):
            checks.append(
                Check(
                    "operations.coordinator",
                    "info",
                    "Privileged operation is active",
                    ", ".join(operations["busyClasses"]),
                )
            )
        else:
            checks.append(Check("operations.coordinator", "ok", "No conflicting privileged operation is active"))

    severity = max((LEVELS.get(check.status, 2) for check in checks), default=0)
    status = {0: "healthy", 1: "degraded", 2: "critical"}[severity]
    return {
        "schemaVersion": 1,
        "generatedAt": int(time.time()),
        "status": status,
        "registryDigest": digest,
        "summary": {
            "ok": sum(check.status == "ok" for check in checks),
            "warning": sum(check.status in {"warning", "indeterminate"} for check in checks),
            "critical": sum(check.status == "critical" for check in checks),
            "info": sum(check.status == "info" for check in checks),
        },
        "checks": [asdict(check) for check in checks],
        "operations": operations,
    }


def _human(payload: Mapping[str, Any]) -> str:
    summary = payload.get("summary", {})
    lines = [
        f"NAS doctor: {payload['status']}",
        (
            "Checks: "
            f"{summary.get('ok', 0)} ok, "
            f"{summary.get('warning', 0)} warning, "
            f"{summary.get('critical', 0)} critical, "
            f"{summary.get('info', 0)} info"
        ),
    ]
    for check in payload["checks"]:
        line = f"[{str(check['status']).upper():13}] {check['id']}: {check['summary']}"
        if check.get("detail"):
            line += f" — {check['detail']}"
        lines.append(line)
        if check.get("remediation"):
            lines.append(f"  Next: {check['remediation']}")
    return "\n".join(lines)


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--json", action="store_true", help="Emit the complete JSON report")
    value.add_argument("--deep", action="store_true", help="Include deeper privileged state and consistency checks")
    return value


def main() -> int:
    args = parser().parse_args()
    payload = build_report(deep=args.deep)
    print(json.dumps(payload, indent=2, sort_keys=True) if args.json else _human(payload))
    return {"healthy": 0, "degraded": 1, "critical": 2}[payload["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
