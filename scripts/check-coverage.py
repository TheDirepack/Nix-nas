#!/usr/bin/env python3
"""Enforce service-specific branch-coverage floors from coverage.py JSON."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

FLOORS = {
    "services/nas_alert_router.py": 70.0,
    "services/nas_cockpit_api.py": 49.0,
    "services/nas_common.py": 75.0,
    "services/nas_doctor.py": 60.0,
    "services/nas_feature_control.py": 58.0,
    "services/nas_feature_model.py": 72.0,
    "services/nas_identity_model.py": 79.0,
    "services/nas_identity_sync.py": 73.0,
    "services/nas_logging.py": 75.0,
    "services/nas_migrate_state.py": 62.0,
    "services/nas_operation_journal.py": 87.0,
    "services/nas_operation_lock.py": 80.0,
    "services/nas_setup.py": 51.0,
    "services/nas_setup_config.py": 82.0,
    "services/nas_state.py": 66.0,
    "services/nas_syncthing_devices.py": 76.0,
}
TOTAL_FLOOR = 66.0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", nargs="?", default="coverage.json")
    parser.add_argument("--total-floor", type=float, default=TOTAL_FLOOR)
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
    for path, floor in FLOORS.items():
        row = files.get(path)
        if not isinstance(row, dict):
            failures.append(f"missing coverage result for {path}")
            continue
        summary = row.get("summary", {})
        actual = float(summary.get("percent_covered", 0.0))
        if actual + 1e-9 < floor:
            failures.append(f"{path}: {actual:.1f}% is below {floor:.1f}%")
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
