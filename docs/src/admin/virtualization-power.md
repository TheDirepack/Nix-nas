# Virtualization, UPS, Vaultwarden, and TFTP

## Virtualization

When enabled, Cockpit Machines manages libvirt/QEMU/KVM. VM disks default to the configured ZFS storage path. Configure bridges, software TPM, virtiofs, and the non-root QEMU policy through `nas.virtualization.*`.

## UPS

NUT owns UPS drivers, monitoring, network-server/client behavior, and shutdown policy. The optional NUT Web UI is administrative and can remain monitoring-only. The monitor credential must be boot-available because safe shutdown cannot depend on the KeePass database already being unlocked.

## Vaultwarden

Vaultwarden owns per-user vault data and clients; Authentik provides OIDC. The admin route requires administrator MFA. Revoking NAS proxy access does not necessarily revoke an already-issued application session, so session revocation must also be performed in Authentik/Vaultwarden when required.

## TFTP

CopyParty provides the optional TFTP endpoint. It is disabled and anonymous read-only by default because TFTP has no login mechanism. CopyParty grants that access to its anonymous `*` VFS principal while the underlying directory stays owned by the service. Enabling anonymous writes is a significant trust decision and should be limited to an isolated trusted LAN.