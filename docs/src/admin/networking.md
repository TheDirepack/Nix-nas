# Networking and remote access

NetworkManager owns runtime network profiles. firewalld owns mutable nftables policy. NixOS seeds the initial trusted-interface configuration, after which normal network changes can be made through Cockpit/NetworkManager without maintaining a second NAS-specific network database.

Interfaces not listed in `nas.trustedInterfaces` remain fail-closed by default.

## Normal access

| Purpose | Address |
|---|---|
| Application landing page | `https://<nas-hostname>.local/` |
| Cockpit after unlock | `https://<nas-hostname>.local/console/` |
| Authentik | `https://<nas-hostname>.local/identity/` |
| CopyParty | `https://<nas-hostname>.local/shares/` |
| Native CopyParty share links | `https://<nas-hostname>.local/share/` |

## Locked-state recovery

Locked boot exposes no browser management endpoint. Use the local console, SSH with a provisioned recovery key, or hardware KVM to run `sudo nas-secrets activate`. After activation, use the normal Caddy route and Authentik login.

## Optional ports

Syncthing, NUT, TFTP, and other optional listeners are opened only when their feature and firewall policy require them. Use Cockpit Networking or `firewall-cmd` to inspect the effective runtime policy.
