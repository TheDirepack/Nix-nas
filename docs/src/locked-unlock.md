# Locked-state unlock

The NAS intentionally starts in a **locked** state when the KeePass-backed runtime secret tree is absent. Authentik, Caddy, CopyParty, encrypted ZFS datasets, and other protected services remain stopped.

Cockpit is the exception. It is the bootstrap and recovery interface and remains available on the trusted LAN at:

```text
https://<nas-hostname>.local:9092/console/
```

Sign in with the local Linux administrator configured by `nas.adminUser`. This is a PAM account, not an Authentik account; Authentik cannot authenticate anyone until it has been unlocked.

Open **NAS Overview** and enter the KeePass database password in **Unlock protected storage and services**. Cockpit launches `nas-secrets activate-stdin` with superuser escalation and sends the password over process standard input. The password is not written to a URL, process argument, environment variable, Nix store path, browser storage, or disk file.

Activation performs the following transaction:

1. Verify the KDBX database and optional key file.
2. Materialize all configured service secrets into a private staging directory.
3. Verify the staging directory is mode `0700` before writing secrets.
4. Install a complete new `/run/nas-secrets` tree atomically.
5. Load the ZFS encryption key when enabled.
6. Start the protected service target.
7. Validate Authentik API readiness, CopyParty's Unix socket, and required service state.
8. Roll back to the previous secret tree and service state if validation fails.

The CLI remains available:

```bash
sudo nas-secrets activate
```

`activate-stdin` exists only for trusted process integrations such as Cockpit. Do not pipe passwords through shell history, command substitutions, or network tools.

## Locked-state troubleshooting

- If Cockpit is unreachable, verify `cockpit.socket`, the trusted-interface firewalld zone, port `9092/tcp`, DNS/mDNS, and the machine's Cockpit certificate.
- If the form reports an incorrect password, test `sudo nas-secrets activate` locally.
- If activation rolls back, inspect `systemctl --failed`, `journalctl -u nas-protected-services.target`, and the specific exit message.
- If the KDBX file is missing, restore it before attempting activation.
- Additional Authentik superusers cannot perform the boot unlock unless they also have an authorized local Cockpit/PAM administrator account.
