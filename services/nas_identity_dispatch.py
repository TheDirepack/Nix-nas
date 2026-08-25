#!/usr/bin/env python3
"""Dispatch Authentik identity commands across setup and steady-state authority.

The public ``nas-identity-sync`` command has one intentionally narrow split:
setup-only mutations use the temporary bootstrap authority, while all normal
projection/status work uses the scoped runtime token. Once bootstrap authority
is retired, setup-only mutations fail closed instead of silently expanding the
runtime service account's permissions.
"""

from __future__ import annotations

import sys

import nas_identity_bootstrap as bootstrap
import nas_identity_sync as runtime


_BOOTSTRAP_COMMANDS = {
    "apply-accounts": "apply-accounts",
    "bootstrap-runtime-token": "provision-runtime-token",
    "retire-bootstrap": "retire-bootstrap",
}


def _bootstrap_argv(arguments: list[str]) -> list[str]:
    command = arguments[0]
    mapped = _BOOTSTRAP_COMMANDS[command]
    tail = arguments[1:]
    if command == "apply-accounts":
        # Setup account plans are accepted only on stdin so passwords never need
        # a persistent plan file. Preserve only the explicit resume confirmation.
        tail = [item for item in tail if item != "-"]
        if any(item != "--confirm-password-reapply" for item in tail):
            raise SystemExit("nas-identity-sync: setup account plans must be supplied on stdin")
    return [sys.argv[0], mapped, *tail]


def main() -> int:
    arguments = sys.argv[1:]
    if not arguments or arguments[0] not in _BOOTSTRAP_COMMANDS:
        return runtime.main()

    original = sys.argv
    sys.argv = _bootstrap_argv(arguments)
    try:
        return bootstrap.main()
    finally:
        sys.argv = original


if __name__ == "__main__":
    raise SystemExit(main())
