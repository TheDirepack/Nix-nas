"""Deterministic mutation helpers used by the fast and extended fuzz suites.

This deliberately has no third-party dependency so every developer and source-only
release can run a useful fuzz pass. CI increases the case count with NAS_FUZZ_CASES.
"""

from __future__ import annotations

import json
import os
import random
import string
from collections.abc import Iterable, Iterator
from typing import Any

DEFAULT_CASES = max(32, min(int(os.environ.get("NAS_FUZZ_CASES", "256")), 10000))
DEFAULT_SEED = int(os.environ.get("NAS_FUZZ_SEED", "22001"))
MAX_MUTATION_BYTES = 8192

INTERESTING_TEXT = (
    "",
    "0",
    "null",
    "true",
    "false",
    "../",
    "..\\",
    "/",
    "\\",
    "'\"`$;&|<>(){}[]",
    "\x00",
    "\r\n",
    "\u202e",
    "\ud7ff",
    "é",
    "🧪",
    "A" * 4096,
)


def _bounded(value: str) -> str:
    encoded = value.encode("utf-8", errors="ignore")[:MAX_MUTATION_BYTES]
    return encoded.decode("utf-8", errors="ignore")


def mutate_text(corpus: Iterable[str], *, seed: int = DEFAULT_SEED, cases: int = DEFAULT_CASES) -> Iterator[str]:
    """Yield reproducible string mutations with size and runtime bounds."""

    rng = random.Random(seed)
    base = [str(value) for value in corpus] + list(INTERESTING_TEXT)
    seen: set[str] = set()
    alphabet = string.ascii_letters + string.digits + "_-. /:;|&$'\"<>[]{}()\\\r\n\t"

    def emit(value: str) -> Iterator[str]:
        value = _bounded(value)
        if value not in seen:
            seen.add(value)
            yield value

    for value in base:
        yield from emit(value)
    for _ in range(cases):
        value = rng.choice(base)
        operation = rng.randrange(8)
        if operation == 0:
            position = rng.randrange(len(value) + 1)
            value = value[:position] + rng.choice(INTERESTING_TEXT) + value[position:]
        elif operation == 1 and value:
            start = rng.randrange(len(value))
            end = rng.randrange(start, len(value) + 1)
            value = value[:start] + value[end:]
        elif operation == 2:
            value = value * rng.randint(2, 16)
        elif operation == 3:
            value = value[::-1]
        elif operation == 4:
            value = value + "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 64)))
        elif operation == 5:
            value = rng.choice(INTERESTING_TEXT) + value + rng.choice(INTERESTING_TEXT)
        elif operation == 6:
            value = value.swapcase()
        else:
            value = "".join(chr(rng.randrange(0, 256)) for _ in range(rng.randint(0, 64)))
        yield from emit(value)


def json_values(*, seed: int = DEFAULT_SEED, cases: int = DEFAULT_CASES) -> Iterator[Any]:
    """Yield bounded recursively generated JSON-compatible values."""

    rng = random.Random(seed)

    def value(depth: int = 0) -> Any:
        scalar: list[Any] = [None, True, False, 0, -1, 1, 2**31 - 1, "", "x", "../", "\x00", "<script>"]
        if depth >= 3 or rng.random() < 0.55:
            return rng.choice(scalar)
        if rng.random() < 0.5:
            return [value(depth + 1) for _ in range(rng.randrange(0, 6))]
        return {f"k{rng.randrange(0, 20)}": value(depth + 1) for _ in range(rng.randrange(0, 6))}

    for item in [None, [], {}, "", 0, True]:
        yield item
    for _ in range(cases):
        yield value()


def json_texts(*, seed: int = DEFAULT_SEED, cases: int = DEFAULT_CASES) -> Iterator[str]:
    for value in json_values(seed=seed, cases=cases):
        yield json.dumps(value, ensure_ascii=False)
