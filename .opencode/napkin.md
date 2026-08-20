# Napkin Runbook

## Curation Rules
- Re-prioritize on every read.
- Keep recurring, high-value notes only.
- Max 10 items per category.
- Each item includes date + "Do instead".

## Execution & Validation (Highest Priority)
1. **[2026-08-18] Run everything in the VM via `scripts/vm-run.sh`**
   Do instead: use `scripts/vm-run.sh '<cmd>'` (SSH into the VM as admin, sets the right key/port). Examples: `scripts/vm-run.sh 'sudo ss -tlnp'`, `scripts/vm-run.sh 'sudo curl -k https://127.0.0.1:443/'`. Never `curl`/`ss` on the host to infer guest state. Host nix store is dead; all `nix build`/`nix eval`/`nixos-rebuild switch` run inside the VM. Code changes happen on the HOST worktree (the VM's `/var/lib/nas-test/repo` is a synced copy, not the GitHub source); when work is done, sync with `scripts/qemu-test.sh persistent-test` or a manual tar+ssh sync.

## Shell & Command Reliability
1. **[2026-08-16] Host Nix store is not writable**
   Do instead: use `scripts/vm-run.sh` to run Nix inside the VM, e.g. `scripts/vm-run.sh 'cd /var/lib/nas-test/repo && nix build --impure --no-link .#nixosConfigurations.nas-qemu.config.system.build.toplevel'`. To rebuild/switch the running VM: `scripts/vm-run.sh 'cd /var/lib/nas-test/repo && sudo nixos-rebuild switch --flake .#nas-qemu'` (or `scripts/qemu-test.sh persistent-test` for the full suite).

## Domain Behavior Guardrails
1. **[2026-08-18] Caddy bootstrap works pre-secrets; portal needs portal.json**
   Do instead: verified in VM — `caddy.service` runs `--config /run/nas-control/caddy-active.conf --adapter caddyfile` (drop-in `caddy.service.d/overrides.conf`; readonly `/etc/systemd/system/caddy.service` is the stock packaged unit, don't be fooled). Pre-secrets it imports the bootstrap Caddyfile and serves :443. Two open gaps: (a) portal 500s because `index.html` template includes `/run/nas-control/portal.json` which only reconcile writes — the bootstrap path must also produce a default portal.json (or bootstrap should not template it); (b) cockpit.socket still binds :9090 publicly from the packaged unit — `system.nix` only overrides `listenStreams`; need them fully replaced (check `nglListenStreams`/`mkForce` on the whole socket).

2. **[2026-08-16] Cockpit is NOT exposed over network; only via Caddy**
   Do instead: Cockpit must be reachable only as `https://${lanHost}/console` reverse-proxied through Caddy on `:443`; never forward a direct `->9092` guest port. Verify via VM: `scripts/vm-run.sh 'sudo ss -tlnp | grep 9092'` shows loopback-only binds, and `scripts/vm-run.sh 'curl -k https://127.0.0.1:443/console'` works inside guest.

3. **[2026-08-16] HTTP must never be forwarded**
   Do instead: keep `scripts/qemu-test.sh:qemu_network_args` with only `2222->22`, `8443->443` (no `8088->80`); enforce HTTPS-only. Verify `ss -tlnp | grep qemu` shows no `8088`.

4. **[2026-08-16] Caddy needs default keys for setup, rotated on first-run**
   Do instead: ensure `/var/lib/caddy/.local/share/caddy` has default internal CA for `nas_setup prepare-first-start`; on `nas-setup first-run` regenerate with `caddy trust --ca` or `rm -rf /var/lib/caddy/pki && systemctl reload caddy`, and verify `caddy list --ca` shows fresh cert after setup.

## User Directives
1. **[2026-08-16] Single main UI is Caddy portal; Cockpit is emergency-only**
   Do instead: keep `services.cockpit.enable = false` on host; expose all startup config via Caddy portal at `https://nas-test.local/` (V2 `portal.json`); Cockpit disabled when `caddy.service` is active (`Conflicts=caddy.service` on `cockpit.socket`).

2. **[2026-08-16] First boot runs the whole setup through Caddy, not Cockpit**
   Do instead: Caddy must be up pre-secrets with default internal keys, serving the portal + `/console` (Cockpit reverse-proxied, forward-auth gated post-setup). The first-run landing page shows a setup guide (what to configure, where) and a first-account helper. Do NOT gate Caddy on `${secretRoot}/ready` for the bootstrap/portal surface.

3. **[2026-08-16] The admin's first password is the seed for the whole system**
   Do instead: the password set in the first-run flow becomes the system/SSH+admin account password, the Caddy/Authentik admin account password, the admin password for all built-in apps, AND unlocks the KeePass store — or a separately configured KeePass password. SSH stays key-based. Make `nas-setup first-run` register the same password to local PAM admin, Authentik akadmin/admin, and KeePass unlock.

4. **[2026-08-16] Every application routes through Caddy for forward-auth + proxy unless V2 config opts out**
   Do instead: keep all app HTTP/HTTPS routes on Caddy (reverse-proxy.nix `handle` + V2 `routes`); use V2 `listeners`/`exposure` only for non-HTTP or explicit direct ports. No app serves HTTP directly on a forwarded port.
