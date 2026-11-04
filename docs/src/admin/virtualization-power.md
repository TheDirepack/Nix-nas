# Virtualization, UPS, Vaultwarden, and TFTP

## Virtualization

When enabled, Cockpit Machines manages libvirt/QEMU/KVM. VM disks default to the configured ZFS storage path. Configure bridges, software TPM, virtiofs, and the non-root QEMU policy through `nas.virtualization.*`.

Podman container storage moves to `<zfs root>/containers/storage`, and boot creates `/var/lib/containers` as a symlink to it. That symlink is only created when the path is absent. If an installation already has a non-empty `/var/lib/containers` directory (storage written before this layout), `nas-containers-storage-check.service` fails instead of letting Podman start against an empty graphroot. Migrate the old tree while Podman is stopped, then reboot so the symlink is created:

```bash
sudo install -d -m 0710 -o root -g root /tank/containers/storage
sudo cp -a --reflink=auto /var/lib/containers/. /tank/containers/storage/
sudo rm -rf --one-file-system /var/lib/containers
```

Adjust the destination to the configured ZFS root; `/tank` is the default. Disabling `nas.virtualization.enable` keeps the legacy location instead.

## UPS

NUT owns UPS drivers, monitoring, network-server/client behavior, and shutdown policy. The optional NUT Web UI is administrative and can remain monitoring-only. The monitor credential must be boot-available because safe shutdown cannot depend on the KeePass database already being unlocked.

## Vaultwarden

Vaultwarden owns per-user vault data and clients; Authentik provides OIDC. The admin route requires administrator MFA. Revoking NAS proxy access does not necessarily revoke an already-issued application session, so session revocation must also be performed in Authentik/Vaultwarden when required.

## TFTP

CopyParty provides the optional TFTP endpoint. It is disabled and anonymous read-only by default because TFTP has no login mechanism. CopyParty grants that access to its anonymous `*` VFS principal while the underlying directory stays owned by the service. Enabling anonymous writes is a significant trust decision and should be limited to an isolated trusted LAN.