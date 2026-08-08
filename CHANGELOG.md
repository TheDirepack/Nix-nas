# Changelog

## 2.2.0-alpha.8 — 2026-08-08

- Replace the managed-services metadata skeleton with a transactional one-shot control plane for Podman containers, Podman Compose projects, and libvirt/QEMU VMs; add real create, update, delete, lifecycle, source-staging, export, import, status, and reconciliation commands with rollback through the existing operation coordinator and journal.
- Generate isolated workload networks and real firewalld permanent zones/policies for egress, private-LAN, host, application-to-application, proxy-backend, and declared TCP/UDP access; remove the unsafe VM `--remove-all-storage` behavior and reject unmanaged hostdev/network bypasses.
- Integrate managed HTTP endpoints with the existing Caddy, Authentik, dynamic `service:<id>:<endpoint>` gate, and registry-driven portal; container/Compose web backends bind only to loopback, VMs receive stable private addresses, and Caddy changes are validated and reloaded atomically without another resident proxy/controller.
- Add the zero-idle Cockpit Applications package, explicit `podman-compose` provider, strict managed-service schema, boot/path reconciliation with `RemainAfterExit=false`, and focused runtime/Caddy security tests. Native OIDC provisioning remains fail-closed until its client-secret lifecycle can participate in the same transaction.

## Previous releases

The complete changelog through **2.2.0-alpha.7** is preserved unchanged in [CHANGELOG.history.md](CHANGELOG.history.md).
