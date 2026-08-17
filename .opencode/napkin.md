# Napkin Runbook

## Curation Rules
- Re-prioritize on every read.
- Keep recurring, high-value notes only.
- Max 10 items per category.
- Each item includes date + "Do instead".

## Execution & Validation (Highest Priority)
1. **[2026-08-16] Host ≠ Server — probe the VM, not the host**
   Do instead: `ssh -p 2222 admin@127.0.0.1 'sudo ss -tlnp; sudo systemctl status caddy'` or `ssh ... 'curl -k https://127.0.0.1:443/'` inside the QEMU guest; never `curl`/`ss` on the host to infer guest state.

## Shell & Command Reliability
1. **[2026-08-16] Host Nix store is not writable**
   Do instead: use `nix develop .#qemu-test -c ./scripts/qemu-test.sh` / `scripts/vm-start.sh` + `persistent-test` which run Nix inside the VM.

## Domain Behavior Guardrails
1. **[2026-08-16] Cockpit is NOT exposed over network; only via Caddy**
   Do instead: remove `hostfwd=tcp:$HOST_BIND_ADDRESS:$COCKPIT_PORT-:9092` from `scripts/qemu-test.sh:qemu_network_args`; Cockpit must be reachable only as `https://${lanHost}/console` reverse-proxied through Caddy on `:443` (hostfwd `8443->443`). Never re-add direct `9094->9092` forwarding. Verify via VM: `sudo cat /etc/caddy/Caddyfile | grep -A2 cockpit` and `curl -k https://127.0.0.1:443/console` inside guest, not host `ss` on `9094`.

2. **[2026-08-16] HTTP must never be forwarded**
   Do instead: keep `scripts/qemu-test.sh:qemu_network_args` with only `2222->22`, `8443->443` (no `8088->80`); enforce HTTPS-only. Verify `ss -tlnp | grep qemu` shows no `8088`.

3. **[2026-08-16] Caddy needs default keys for setup, rotated on first-run**
   Do instead: ensure `/var/lib/caddy/.local/share/caddy` has default internal CA for `nas_setup prepare-first-start`; on `nas-setup first-run` regenerate with `caddy trust --ca` or `rm -rf /var/lib/caddy/pki && systemctl reload caddy`, and verify `caddy list --ca` shows fresh cert after setup.

## User Directives
1. **[2026-08-16] Single main UI is Caddy portal; Cockpit is emergency-only**
   Do instead: keep `services.cockpit.enable = false` on host; expose all startup config via Caddy portal at `https://nas-test.local/` (V2 `portal.json`); Cockpit disabled when `caddy.service` is active (`Conflicts=caddy.service` on `cockpit.socket`).
