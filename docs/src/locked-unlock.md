# Locked-state unlock

The NAS intentionally starts **locked** when the KeePass-backed runtime secret tree is absent. Authentik, Cockpit, CopyParty, encrypted ZFS datasets, and protected services are unavailable to browsers.

After setup, a browser that opens the NAS while it is locked sees a static notice with these instructions on every path. The notice accepts no input; it cannot unlock the NAS or open Cockpit.

Recover from the local console, SSH using a provisioned recovery key, or hardware KVM. Sign in as the local recovery administrator and activate the secret tree:

```bash
sudo nas-secrets activate
```

Enter the KeePass database password only at the local terminal prompt. The command reads it from standard input; it does not store it in a URL, argument, environment variable, Nix store path, browser storage, or disk file.

Activation performs the following transaction:

1. Verify the KDBX database and optional key file.
2. Materialize all configured service secrets into a private staging directory.
3. Verify the staging directory is mode `0700` before writing secrets.
4. Install a complete new `/run/nas-secrets` tree atomically.
5. Load the ZFS encryption key when enabled.
6. Start the protected service target.
7. Validate Authentik API readiness, CopyParty's Unix socket, and required service state.
8. Roll back to the previous secret tree and service state if validation fails.

`activate-stdin` exists for trusted process integrations. Do not pipe passwords through shell history, command substitutions, or network tools.

## Locked-state troubleshooting

- Confirm that you have console, SSH, or KVM access before changing network or storage state.
- If the password is rejected, retry `sudo nas-secrets activate` at the local recovery terminal.
- If activation rolls back, inspect `systemctl --failed`, `journalctl -u nas-protected-services.target`, and the specific exit message.
- If the KDBX file is missing, restore it before attempting activation.
- An Authentik administrator is not automatically a local recovery administrator.

## Secret activation recovery

Activation requires a successful systemd observation of a loaded protected target
in a stable state. If D-Bus is unavailable or the target is activating,
deactivating, or otherwise transitional, activation refuses to replace the live
secret tree. A failed stop is accepted only when a subsequent successful query
observes the target as inactive or failed.

If cleanup reports status 125, inspect the original error and the reported
primary status, then use console or recovery SSH access to repair systemd and
inspect `nas-protected-services.target`. An unknown initial state or an
unconfirmed rollback stop retains the live secret root and all remaining
staged/previous transaction trees. Preserve the recovery paths printed in the
error output under `/run/nas-secret-runtime/transactions/`; do not delete them
or reboot before recovery, because these runtime copies are volatile. Once
shutdown is established, reconcile the retained trees and restore the known-good
ready-marked tree before restarting previously active consumers. Retry
`sudo nas-secrets activate` only after systemd state is stable and the prior
failure has been reviewed.
