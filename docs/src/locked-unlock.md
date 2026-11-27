# Locked-state unlock

The NAS intentionally starts **locked** when the KeePass-backed runtime secret tree is absent. Cockpit, CopyParty, encrypted ZFS datasets, and protected services stay unavailable until it is unlocked.

## Unlock from the browser

After setup, a locked NAS still runs Authentik so that you must sign in before anyone can try a password.

1. Open the NAS in a browser. Every path redirects to `/unlock/`.
2. Sign in with an Authentik account that is a member of `nas_admin`. Other accounts get HTTP 403.
3. Enter the KeePass database password and select **Unlock**. Loading storage keys and starting services can take a few minutes.
4. When the page reports success, Authentik restarts with its KeePass configuration. Sign in again to reach the portal.

The page sends the password once, over HTTPS, to a root-only Unix socket that passes it to `nas-secrets activate-stdin` on standard input. Nothing stores it. Only one attempt runs at a time, and each failure doubles a delay that starts at 5 seconds and is capped at 5 minutes. `journalctl -t nas-unlock-api` records which Authentik user made each attempt.

While locked, Authentik's user and admin interfaces redirect to `/unlock/`. Authentik uses a signing key generated for this boot only, so any session from before the unlock stops working once it completes.

If Authentik or its outpost cannot start, the browser shows a static notice instead and you must use the recovery console.

## Unlock from the recovery console

Use the local console, SSH with a provisioned recovery key, or hardware KVM. Sign in as the local recovery administrator and activate the secret tree:

```bash
sudo nas-secrets activate
```

Enter the KeePass database password only at the local terminal prompt. The command reads one line of up to 4,096 characters with terminal echo disabled. For browser unlock, the same limit applies and the unlock service passes the password to the activation command over stdin.

## Activation transaction

Activation performs the following transaction:

1. Verify the KDBX database and optional key file.
2. Materialize all configured service secrets into a private staging directory.
3. Verify the staging directory is mode `0700` before writing secrets.
4. Install a complete new `/run/nas-secrets` tree atomically.
5. Load the ZFS encryption key when enabled.
6. Restart Authentik with the KeePass environment and start the protected service target.
7. Validate Authentik API readiness, CopyParty's Unix socket, and required service state.
8. Roll back to the previous secret tree and service state if validation fails.

`activate-stdin` exists for trusted process integrations. Do not pipe passwords through shell history, command substitutions, or network tools.

## Locked-state troubleshooting

- Confirm that you have console, SSH, or KVM access before changing network or storage state.
- If the password is rejected, retry on `/unlock/` after the delay it shows, or run `sudo nas-secrets activate` at the local recovery terminal.
- If `/unlock/` shows the static locked notice, Authentik or its outpost is down. Unlock from the console.
- If activation rolls back, inspect `systemctl --failed`, `journalctl -u nas-protected-services.target`, and the specific exit message.
- If the KDBX file is missing, restore it before attempting activation.
- An Authentik administrator is not automatically a local recovery administrator.

## Secret activation recovery

Activation requires a successful systemd observation of a loaded protected target
in a stable state with no queued job. If D-Bus is unavailable or the target is
activating, deactivating, or has a queued job, activation refuses to replace the
live secret tree. A failed stop is accepted only when a subsequent successful
query observes the target as inactive or failed with no queued job.

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
