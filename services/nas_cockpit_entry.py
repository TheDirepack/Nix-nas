#!/usr/bin/env python3
"""Hardened entry point for the privileged Cockpit control API.

First-run credential submission is owned exclusively by nas-first-run-api over
its root/caddy Unix socket. Historical nas-cockpit-api subcommands that wrote
human credentials to /run or started a second loopback setup server are kept
out of the installed command surface.
"""

from __future__ import annotations

import sys

import nas_cockpit_api

_DISABLED_LEGACY_SETUP_COMMANDS = frozenset({"first-start", "first-start-job-status", "serve"})


def main() -> int:
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    if command in _DISABLED_LEGACY_SETUP_COMMANDS:
        print(
            "nas-cockpit-api: legacy first-run ingress is disabled; use the authenticated /setup/ workflow",
            file=sys.stderr,
        )
        return 2
    return nas_cockpit_api.main()


if __name__ == "__main__":
    raise SystemExit(main())
