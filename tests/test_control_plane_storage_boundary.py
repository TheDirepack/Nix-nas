from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ControlPlaneStorageBoundaryTests(unittest.TestCase):
    def test_identity_runtime_switches_from_bootstrap_to_root_not_zfs(self) -> None:
        applications = (ROOT / "modules" / "nas" / "config" / "application-services.nix").read_text(encoding="utf-8")
        hardened = (ROOT / "modules" / "nas" / "config" / "bootstrap-security.nix").read_text(encoding="utf-8")

        selector = hardened[hardened.index("runtimeSelector =") : hardened.index("\nin\n{")]
        self.assertIn("target=/var/lib/nas-operational", selector)
        self.assertNotIn("target=${lib.escapeShellArg cfg.zfsRoot}", selector)
        self.assertNotIn("mountpoint --quiet -- ${lib.escapeShellArg cfg.zfsRoot}", selector)
        self.assertIn("link_authority authentik", selector)
        metadata = applications.split("config.systemd.services.nas-bootstrap-runtime-select", 1)[1]
        self.assertNotIn("ExecStart", metadata)
        self.assertNotIn('rm -rf -- "/var/lib/$name"', applications)

    def test_no_dedicated_authentik_proxy_outpost_daemon(self) -> None:
        services = (ROOT / "modules" / "nas" / "config" / "application-services.nix").read_text(encoding="utf-8")
        base = (ROOT / "modules" / "nas" / "internal" / "base.nix").read_text(encoding="utf-8")

        self.assertNotIn("nas-authentik-proxy-outpost", services)
        self.assertNotIn("authentik-outposts.proxy", services)
        self.assertNotIn("view_key", services)
        self.assertNotIn("authentikOutpostPort", base)

    def test_first_start_status_does_not_require_v2_catalog_before_storage(self) -> None:
        source = (ROOT / "services" / "nas_setup.py").read_text(encoding="utf-8")
        block = source[source.index("def first_start_status") : source.index("def publish_first_start_status")]
        self.assertNotIn('validate_service_request(config["services"])', block)


if __name__ == "__main__":
    unittest.main()
