from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ControlPlaneStorageBoundaryTests(unittest.TestCase):
    def test_identity_runtime_switches_from_bootstrap_to_root_not_zfs(self) -> None:
        source = (ROOT / "modules" / "nas" / "config" / "application-services.nix").read_text(encoding="utf-8")

        selector = source.split("config.systemd.services.nas-bootstrap-runtime-select", 1)[1]
        self.assertIn("target=/var/lib/nas-operational", selector)
        self.assertNotIn("target=${lib.escapeShellArg cfg.zfsRoot}", selector)
        self.assertNotIn("mountpoint --quiet -- ${lib.escapeShellArg cfg.zfsRoot}", selector)
        self.assertIn('for name in authentik postgresql nas-secrets', selector)

    def test_no_dedicated_authentik_proxy_outpost_daemon(self) -> None:
        services = (ROOT / "modules" / "nas" / "config" / "application-services.nix").read_text(encoding="utf-8")
        base = (ROOT / "modules" / "nas" / "internal" / "base.nix").read_text(encoding="utf-8")

        self.assertNotIn("nas-authentik-proxy-outpost", services)
        self.assertNotIn("authentik-outposts.proxy", services)
        self.assertNotIn("view_key", services)
        self.assertNotIn("authentikOutpostPort", base)


if __name__ == "__main__":
    unittest.main()
