#!/usr/bin/env python3
"""Compatibility entry point for the repository Python behavior suite."""

from __future__ import annotations

import pathlib
import subprocess
import sys

root = pathlib.Path(__file__).resolve().parents[1]
raise SystemExit(
    subprocess.call([sys.executable, str(root / "scripts" / "run-unit-tests.py"), "--jobs", "4"], cwd=root)
)
