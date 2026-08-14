from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT / "services") not in sys.path:
    sys.path.insert(0, str(ROOT / "services"))

import nas_v2_entry  # noqa: F401,E402 — import coverage for nas_v2_entry.py


class ManagedServicesV2BoundaryTests(unittest.TestCase):
    def test_caddy_projection_is_imported_and_reloaded_from_v2_output(self):
        module = (ROOT / "modules" / "nas" / "config" / "managed-services.nix").read_text(encoding="utf-8")
        self.assertIn("caddy-managed.conf", module)
        self.assertIn("import ${caddyManagedPath}", module)
        self.assertIn("import nas_v2_managed_paths", module)
        self.assertIn("nas-managed-services-caddy-reload", module)
        self.assertIn("PathChanged = caddyManagedPath", module)
        self.assertNotIn("nas_service_caddy.py", module)
        self.assertNotIn("services.json", module)

    def test_wake_socket_is_caddy_only_and_socket_activated(self):
        module = (ROOT / "modules" / "nas" / "config" / "managed-services.nix").read_text(encoding="utf-8")
        self.assertIn('wakeSocketPath = "/run/nas-control/wake.sock"', module)
        self.assertIn("systemd.sockets.nas-managed-services-wake", module)
        self.assertIn("Accept = true", module)
        self.assertIn('SocketMode = "0600"', module)
        self.assertIn('SocketUser = "caddy"', module)
        self.assertIn('SocketGroup = "caddy"', module)
        self.assertIn('StandardInput = "socket"', module)
        self.assertIn('RestrictAddressFamilies = [ "AF_UNIX" ]', module)
        self.assertIn("nas-managed-services-wake.socket", module)

    def test_v2_wake_protocol_contains_no_identity_assignment_logic(self):
        wake = (ROOT / "services" / "nas_v2_wake.py").read_text(encoding="utf-8")
        self.assertIn('set(query) != {"service"}', wake)
        self.assertNotIn("allowedUsers", wake)
        self.assertNotIn("allowedGroups", wake)
        self.assertNotIn("Remote-User", wake)
        self.assertNotIn("Remote-Groups", wake)
        self.assertNotIn("X-Authentik-", wake)

    def test_on_demand_idle_is_native_systemd_not_resident_reaper(self):
        systemd = (ROOT / "services" / "nas_v2_systemd.py").read_text(encoding="utf-8")
        wake = (ROOT / "services" / "nas_v2_wake.py").read_text(encoding="utf-8")
        self.assertIn("StopWhenUnneeded=yes", systemd)
        self.assertIn("OnActiveSec=", systemd)
        self.assertIn("nas-v2-idle-", systemd)
        self.assertIn("nas-v2-lease-", systemd)
        self.assertIn('systemctl, "restart", timer', wake)
        self.assertNotIn("while True", wake)

    def test_v2_runtime_is_compiler_driven_and_legacy_sources_are_absent(self):
        module = (ROOT / "modules" / "nas" / "config" / "managed-services.nix").read_text(encoding="utf-8")
        self.assertIn("services", module)
        self.assertIn("nas_v2_entry.py", module)
        self.assertNotIn("nas_v2_cli.py", module)
        self.assertIn("systemdReconcileArgs", module)
        self.assertIn("postStart", module)
        self.assertNotIn("services.json", module)
        self.assertNotIn("nas_managed_service.py", module)
        self.assertFalse((ROOT / "services" / "nas_feature_control.py").exists())
        self.assertFalse((ROOT / "modules" / "nas" / "internal" / "feature-catalog.nix").exists())
        self.assertFalse((ROOT / "modules" / "nas" / "internal" / "capability-registry.nix").exists())
        self.assertFalse((ROOT / "modules" / "nas" / "internal" / "service-registry.nix").exists())


if __name__ == "__main__":
    unittest.main()
