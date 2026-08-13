#!/usr/bin/env python3
"""Compatibility entry point for the consolidated smart-fuzz runner."""

from __future__ import annotations

import argparse
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.call([sys.executable, "scripts/run-fuzz.py"], cwd=ROOT, env=env)


if __name__ == "__main__":
    raise SystemExit(main())
