#!/usr/bin/env python3
"""Enforce service-specific branch-coverage floors from coverage.py JSON."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

FLOORS = {
    "services/nas_ai_config.py": 70.0,
    "services/nas_alert_router.py": 70.0,
    "services/nas_cockpit_api.py": 49.0,
    "services/nas_coding_agent.py": 60.0,
    "services/nas_common.py": 75.0,
    "services/nas_doctor.py": 60.0,
    "services/nas_identity_model.py": 79.0,
    "services/nas_identity_sync.py": 73.0,
    "services/nas_logging.py": 75.0,
    "services/nas_operation_journal.py": 87.0,
    "services/nas_operation_lock.py": 80.0,
    "services/nas_setup.py": 51.0,
    "services/nas_setup_config.py": 82.0,
    "services/nas_state.py": 66.0,
    "services/nas_syncthing_devices.py": 76.0,
    "services/nas_v2_accelerator.py": 77.0,
    "services/nas_v2_apply.py": 61.0,
    "services/nas_v2_backup.py": 72.0,
    "services/nas_v2_bootstrap.py": 62.0,
    "services/nas_v2_caddy.py": 84.0,
    "services/nas_v2_compose.py": 78.0,
    "services/nas_v2_control.py": 39.0,
    "services/nas_v2_editor.py": 61.0,
    "services/nas_v2_entry.py": 11.0,
    "services/nas_v2_exec_runner.py": 57.0,
    "services/nas_v2_libvirt.py": 57.0,
    "services/nas_v2_network.py": 57.0,
    "services/nas_v2_plan.py": 78.0,
    "services/nas_v2_platform_probe.py": 54.0,
    "services/nas_v2_quadlet.py": 76.0,
    "services/nas_v2_readiness.py": 52.0,
    "services/nas_v2_session.py": 58.0,
    "services/nas_v2_source_watch.py": 83.0,
    "services/nas_v2_spec.py": 89.0,
    "services/nas_v2_systemd_native.py": 80.0,
    "services/nas_v2_systemd_reconcile.py": 68.0,
}
TOTAL_FLOOR = 66.0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", nargs="?", default="coverage.json")
    parser.add_argument("--total-floor", type=float, default=TOTAL_FLOOR)
    parser.add_argument(
        "--baseline",
        metavar="REPORT",
        help="coverage.py JSON from the base branch for per-file drift gating",
    )
    parser.add_argument(
        "--max-dip",
        type=float,
        default=5.0,
        help="maximum allowed per-file branch-coverage drop against the baseline",
    )
    args = parser.parse_args()
    try:
        data = json.loads(Path(args.report).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Unable to read coverage report {args.report}: {exc}")
        return 2
    if not isinstance(data, dict):
        print(f"Unable to read coverage report {args.report}: top-level value is not an object")
        return 2
    failures: list[str] = []
    files = data.get("files", {})
    baseline_files: dict[str, object] = {}
    if args.baseline:
        try:
            baseline_data = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"Unable to read baseline coverage report {args.baseline}: {exc}")
            return 2
        if not isinstance(baseline_data, dict) or not isinstance(baseline_data.get("files"), dict):
            print(f"Unable to read baseline coverage report {args.baseline}: files is not an object")
            return 2
        baseline_files = baseline_data["files"]
    for path, floor in FLOORS.items():
        row = files.get(path)
        if not isinstance(row, dict):
            failures.append(f"missing coverage result for {path}")
            continue
        summary = row.get("summary", {})
        actual = float(summary.get("percent_covered", 0.0))
        if actual + 1e-9 < floor:
            failures.append(f"{path}: {actual:.1f}% is below {floor:.1f}%")
        if args.baseline:
            baseline_row = baseline_files.get(path)
            if isinstance(baseline_row, dict):
                baseline_value = float(baseline_row.get("summary", {}).get("percent_covered", 0.0))
                reference = max(floor, baseline_value)
                if actual + 1e-9 < reference - args.max_dip:
                    failures.append(
                        f"{path}: {actual:.1f}% is more than {args.max_dip:.0f}pp below "
                        f"the baseline {baseline_value:.1f}%"
                    )
    total = float(data.get("totals", {}).get("percent_covered", 0.0))
    if total + 1e-9 < args.total_floor:
        failures.append(f"total: {total:.1f}% is below {args.total_floor:.1f}%")
    if failures:
        print("Coverage floor failures:")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print(f"Coverage floors passed; total branch coverage {total:.1f}%")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
