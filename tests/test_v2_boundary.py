from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_entry  # noqa: F401,E402 — import coverage for nas_v2_entry.py
import nas_v2_systemd_attachments  # noqa: F401,E402 — split attachment boundary
import nas_v2_systemd_native  # noqa: F401,E402 — native activation boundary


class ManagedServicesV2BoundaryTests(unittest.TestCase):
    def test_caddy_projection_is_imported_without_blocking_boot(self):
        module = (ROOT / "modules" / "nas" / "config" / "managed-services.nix").read_text(encoding="utf-8")
        self.assertIn("caddy-managed.conf", module)
        self.assertIn("import ${caddyManagedPath}", module)
        self.assertIn("import nas_v2_managed_paths", module)
        self.assertIn("systemd.services.caddy.wants = [", module)
        self.assertIn('"nas-managed-services-reconcile.service"', module)
        self.assertIn('"nas-managed-services-authentik-reconcile.service"', module)
        self.assertNotIn("systemd.services.caddy.requires", module)
        self.assertNotIn("systemd.services.caddy.after", module)
        self.assertNotIn("nas_service_caddy.py", module)
        self.assertNotIn("services.json", module)

    def test_on_demand_activation_is_native_systemd_socket_proxy(self):
        native = (SERVICES / "nas_v2_systemd_native.py").read_text(encoding="utf-8")
        self.assertIn("systemd-socket-proxyd", native)
        self.assertIn("--exit-idle-time=", native)
        self.assertIn("StopWhenUnneeded=yes", native)
        self.assertIn("SocketMode=0600", native)
        self.assertIn("SocketUser=caddy", native)
        self.assertIn("SocketGroup=caddy", native)
        self.assertIn("WantedBy=sockets.target", native)
        self.assertNotIn("nas-v2-lease-", native)
        self.assertNotIn("nas-v2-idle-", native)

    def test_deleted_wake_protocol_cannot_reenter_authorization_boundary(self):
        self.assertFalse((SERVICES / "nas_v2_wake.py").exists())
        caddy = (SERVICES / "nas_v2_caddy.py").read_text(encoding="utf-8")
        native = (SERVICES / "nas_v2_systemd_native.py").read_text(encoding="utf-8")
        for source in (caddy, native):
            self.assertNotIn("/wake?service=", source)
            self.assertNotIn("nas_v2_wake", source)
        self.assertNotIn("allowedUsers", native)
        self.assertNotIn("allowedGroups", native)
        self.assertNotIn("Remote-User", native)
        self.assertNotIn("Remote-Groups", native)

    def test_v2_reconcile_is_finite_and_desired_state_driven(self):
        module = (ROOT / "modules" / "nas" / "config" / "managed-services.nix").read_text(encoding="utf-8")
        entry = (SERVICES / "nas_v2_entry.py").read_text(encoding="utf-8")
        self.assertIn('desiredPath = "/var/lib/nas-control/services.yaml"', module)
        self.assertIn("systemd.paths.nas-managed-services-reconcile", module)
        self.assertIn("PathChanged = desiredPath", module)
        self.assertIn("nas_v2_entry.py", module)
        self.assertNotIn("while True", entry)
        self.assertNotIn("nas_v2_cli.py", module)
        self.assertNotIn("services.json", module)

    def test_legacy_control_planes_are_absent(self):
        self.assertFalse((SERVICES / "nas_feature_control.py").exists())
        self.assertFalse((SERVICES / "nas_v2_wake.py").exists())
        self.assertFalse((SERVICES / "nas_v2_python_prepare.py").exists())
        self.assertFalse((SERVICES / "nas_v2_systemd.py").exists())
        self.assertFalse((ROOT / "modules" / "nas" / "internal" / "feature-catalog.nix").exists())
        self.assertFalse((ROOT / "modules" / "nas" / "internal" / "capability-registry.nix").exists())
        self.assertFalse((ROOT / "modules" / "nas" / "internal" / "service-registry.nix").exists())

    def test_transaction_bootstraps_before_the_rollback_guard_and_has_no_wake_dependency(self):
        transactions = (ROOT / "modules" / "nas" / "config" / "managed-services-transactions.nix").read_text(
            encoding="utf-8"
        )
        systemd_services = (ROOT / "modules" / "nas" / "config" / "systemd-services.nix").read_text(encoding="utf-8")
        self.assertIn("historyArgs} bootstrap", transactions)
        self.assertIn("A missing applied revision is an unsafe history state", transactions)
        self.assertNotIn("nas-managed-services-wake.socket", systemd_services)


if __name__ == "__main__":
    unittest.main()
