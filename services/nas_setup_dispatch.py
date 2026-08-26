#!/usr/bin/env python3
"""Public nas-setup dispatcher.

The legacy nas_setup module remains the library used by the hardened first-start
orchestrator. Its historical ``first-run`` CLI path predates the disposable
bootstrap/permanent trust-domain split and must not remain a second way to
provision the appliance.
"""

from __future__ import annotations

import sys

import nas_setup


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "first-run":
        print(
            "nas-setup first-run is disabled; use the authenticated standalone /setup/ workflow",
            file=sys.stderr,
        )
        return 2
    return nas_setup.main()


if __name__ == "__main__":
    raise SystemExit(main())
