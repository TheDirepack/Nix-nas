#!/usr/bin/env python3
"""Validate repository TOML and JSON data with precise file diagnostics."""

from __future__ import annotations

import json
import pathlib
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]
JSON_FILES = (
    "renovate.json",
    "tests/fixtures/authentik-identity.json",
    "cockpit/src/manifest.json",
    "flake.lock",
    "setup/first-run.example.json",
    "setup/account-plan.example.json",
    "schemas/managed-services-v3.schema.json",
    "schemas/first-run.schema.json",
    "schemas/account-plan.schema.json",
    "schemas/state-bundle.schema.json",
    "policy/mkforce-allowlist.json",
)


def fail(path: pathlib.Path, error: Exception | str) -> None:
    print(f"{path.relative_to(ROOT)}: {error}", file=sys.stderr)


def main() -> int:
    errors = 0
    book = ROOT / "docs/book.toml"
    try:
        parsed = tomllib.loads(book.read_text(encoding="utf-8"))
        if "multilingual" in parsed.get("book", {}):
            raise ValueError("unsupported mdBook field `book.multilingual`")
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        fail(book, exc)
        errors += 1

    expected_versions = {
        "schemas/managed-services-v3.schema.json": 3,
        "schemas/first-run.schema.json": 2,
        "schemas/account-plan.schema.json": 1,
        "schemas/state-bundle.schema.json": 2,
    }
    for relative in JSON_FILES:
        path = ROOT / relative
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            if relative.startswith("schemas/"):
                if value.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
                    raise ValueError("schemas must use JSON Schema draft 2020-12")
                if value.get("type") != "object" or value.get("additionalProperties") is not False:
                    raise ValueError("top-level schema must be a closed object")
            if (
                relative in expected_versions
                and value.get("properties", {}).get("schemaVersion", {}).get("const") != expected_versions[relative]
            ):
                raise ValueError(f"{relative} must require schemaVersion {expected_versions[relative]}")
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            fail(path, exc)
            errors += 1
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
