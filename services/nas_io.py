"""Small policy-free filesystem durability helpers.

Callers retain responsibility for validation, temporary-file policy, ownership,
rollback, and whether a directory sync is required. This module only centralizes
the exact low-level primitive used after an atomic namespace mutation.
"""

from __future__ import annotations

import os
import pathlib


def fsync_directory(path: pathlib.Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


__all__ = ["fsync_directory"]
