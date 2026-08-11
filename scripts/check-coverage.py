#!/usr/bin/env python3
"""Enforce service-specific branch-coverage floors from coverage.py JSON."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

# Floors for long-lived modules remain at their pre-V2 values. Modules that were
# substantially rewritten as part of Managed Services V2 use the first complete
# post-rewrite fast-suite result as their new regression baseline. This keeps the
# gate meaningful without comparing unrelated V1 and V2 implementations.
FLOORS = {
    "services/nas_ai_config.py": 65.0,
    "services/nas_alert_router.py": 70.0,
    "services/nas_cockpit_api.py": 37.0,
    "services/nas_coding_agent.py": 60.0,
    "services/nas_common.py": 75.0,
    "services/nas_doctor.py": 50.0,
    "services/nas_identity_model.py": 47.0,
    "services/nas_identity_sync.py": 62.0,
    "services/nas_logging.py": 75.0,
    "services/nas_operation_journal.py": 87.0,
    "services/nas_operation_lock.py": 80.0,
    "services/nas_setup.py": 43.0,
    "services/nas_setup_config.py": 82.0,
    "services/nas_state.py": 58.0,
    "services/nas_syncthing_devices.py": 75.0,
}

# The main branch still contains the V1 implementations for these paths. Their
# historical percentages are therefore not comparable to the rewritten V2
# modules. The explicit floors above become the new baseline; subsequent PRs
# are again protected by the ordinary floor and total-coverage gates.
BASELINE_RESET = frozenset(
    {
        "services/nas_ai_config.py",
        "services/nas_cockpit_api.py",
        "services/nas_doctor.py",
        "services/nas_identity_model.py",
        "services/nas_identity_sync.py",
        "services/nas_setup.py",
        "services/nas_state.py",
        "services/nas_syncthing_devices.py",
    }
)

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
        default=2.0,
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
        if args.baseline and path not in BASELINE_RESET:
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
