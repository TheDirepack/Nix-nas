# Locked-state unlock

The NAS intentionally starts **locked** when the KeePass-backed runtime secret tree is absent. Authentik, Cockpit, CopyParty, encrypted ZFS datasets, and protected services are unavailable to browsers.

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
