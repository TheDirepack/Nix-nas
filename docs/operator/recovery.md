# Recovery runbook

This runbook assumes the operator has the independent KeePassXC database password, the recorded `networking.hostId`, the repository or a verified release archive, and current backups. Never run a destructive disk command against unidentified drives.

## Recovery records to keep offline

Record and update these after every storage or identity change:

- `networking.hostId` and NAS hostname;
- boot-disk and pool member `/dev/disk/by-id/...` paths;
- exact pool topology, ashift, feature flags, dataset hierarchy, mountpoints, encryption roots, and key fingerprints;
- KeePassXC database/key-file locations and an independent copy of the KDBX password;
- latest successful backup snapshot IDs and repository access procedure;
- Authentik hostname, bootstrap email, provider/application names, outpost assignment, and MFA recovery material;
- Syncthing local device ID and the location of its backed-up config directory.

The `installation/` directory contains a destructive fresh-install Disko example and a pool-layout worksheet. They are specifications for recovery, not runtime modules.

## First response

1. Stop writes if the failure may involve storage corruption:

   ```bash
   sudo systemctl stop nas-protected-services.target
   sudo zpool status -v
   ```

2. Capture diagnostics before changing anything:

   ```bash
   sudo zpool status -v > /tmp/zpool-status.txt
   sudo journalctl -b -p warning..alert > /tmp/boot-warnings.txt
   sudo nixos-rebuild list-generations > /tmp/nixos-generations.txt
   ```

3. Confirm drive identities with `ls -l /dev/disk/by-id/` and SMART data. Do not rely on `/dev/sdX` ordering.

## Boot-device failure with an intact data pool

1. Boot a NixOS installer matching the machine architecture.
2. Restore the repository to the intended configuration path.
3. Restore `hardware-configuration.nix`, `local.nix`, and the exact recorded `networking.hostId`.
4. Partition/format only the replacement boot disk. The example in `installation/disko-os-disk-example.nix` is destructive and must contain the exact replacement `/dev/disk/by-id/...` path before use.
5. Import the existing pool without formatting any data disk:

   ```bash
   sudo zpool import
   sudo zpool import -N -f tank
   sudo zfs mount -a
   sudo zpool status -v tank
   ```

   Replace `tank` with `nas.zfsPool`. Omit `-f` unless the previous host failed to export cleanly and the pool identity has been verified.

6. Mount the target root and boot filesystems, then install from the restored flake/configuration.
7. Reboot, verify the pool and dataset mountpoint, then restore secrets and application state as described below.

## Complete host replacement

1. Verify firmware mode, controller mode, drive cabling, and stable `/dev/disk/by-id/...` names.
2. Reuse the recorded host ID. ZFS host identity must remain stable.
3. Recreate only the operating-system disk from the installation specification.
4. Import the existing data pool with `zpool import -N`, inspect it, then mount datasets.
5. Restore the repository, KDBX, Authentik database/media, and critical-state backup.
6. Build and activate the configuration with `installationReady = false` first. Run `./scripts/preflight.sh`, correct the target-specific values, then set it to true and build again.
7. Run the verification checklist at the end of this document before enabling scheduled jobs.

## Existing ZFS pool import

Inspect before importing:

```bash
sudo zpool import
sudo zpool import -N -o readonly=on tank
sudo zpool status -v tank
sudo zfs list -r tank
sudo zpool export tank
```

For the real writable import:

```bash
sudo zpool import -N tank
sudo zfs load-key -a        # only for encrypted datasets after the key is available
sudo zfs mount -a
sudo zfs list -o name,mountpoint,canmount,mounted -r tank
```

The expected appliance dataset is `nas.zfsDataset` mounted exactly at `nas.zfsRoot`. Do not create a replacement dataset over an unmounted recovery target.

## Encrypted-pool or dataset recovery

Restore the KDBX first. On a trusted local console:

```bash
sudo nas-secrets init
sudo nas-secrets show-zfs-key
```

Compare the key fingerprint to the offline record and the dataset property used by this project. Then load the key without echoing it into shell history. After activation:

```bash
sudo nas-secrets activate
sudo zfs get encryptionroot,keystatus,org.nixos:keystore-sha256 -r tank
sudo systemctl status nas-zfs-unlock.service nas-zfs-mount-guard.service
```

Test restored keys against a clone or read-only recovery environment whenever possible.

## KeePassXC recovery

1. Restore the KDBX and optional key file to the paths configured in `nas.secrets`.
2. Check ownership and permissions; the database must not be writable by unrelated users.
3. Run:

   ```bash
   sudo nas-secrets init
   sudo nas-secrets status
   sudo nas-secrets activate
   sudo nas-secrets check-authentik-token
   ```

`init` creates only missing entries. It does not replace existing secrets. If the runtime Authentik token still equals the bootstrap token, Cockpit and `nas-secrets` show a warning; replace it with a scoped read-only token and reactivate.

## Authentik PostgreSQL and media restore

Stop the identity stack before replacing state:

```bash
sudo systemctl stop nas-protected-services.target
sudo systemctl start postgresql.service
```

Restore Authentik media to its backed-up path with original ownership. Restore the custom-format PostgreSQL dump into an empty database using the PostgreSQL version from the active NixOS generation. A typical sequence is:

```bash
sudo -u postgres dropdb --if-exists authentik
sudo -u postgres createdb -O authentik authentik
sudo -u postgres pg_restore \
  --dbname=authentik \
  --clean --if-exists --no-owner --no-privileges \
  /path/to/authentik.dump
```

The exact database/user names must match the installed module configuration and backup metadata. Then run migrations before the worker/server:

```bash
sudo systemctl start authentik-migrate.service
sudo systemctl status authentik-migrate.service
sudo systemctl start authentik-worker.service authentik.service
curl --fail http://127.0.0.1:9000/identity/-/health/ready/
```

After login, confirm there is at least one enabled explicit `nas_admin` member and that `nas_admin` is the only reserved NAS group with Authentik superuser status. Run:

```bash
sudo nas-identity-sync verify-token
sudo nas-identity-sync bootstrap
sudo nas-identity-sync sync
```

## Lost Authentik database with intact filesystem data

1. Bootstrap a new Authentik database using the staged bootstrap credentials.
2. Recreate the NAS proxy provider/application, embedded-outpost assignment, authorization/MFA flows, and application bindings.
3. Keep at least one enabled explicit account in `nas_admin`; recreate any additional trusted administrators and ordinary users with the same usernames and memberships.
4. Verify that the bundled `nas-user-settings` blueprint/flow is present.
5. Restore each user's `nasSyncthingDevices` attribute when that feature is used.
6. Install a scoped runtime token and verify it.
7. Run `nas-identity-sync bootstrap` and `nas-identity-sync status`.

CopyParty access does not need to be regenerated from Authentik. Its native volume/ACL configuration remains authoritative; restoring matching usernames/groups reconnects ACL references without rewriting share definitions.

## CopyParty recovery

Restore `/var/lib/copyparty/user.d/` and the staged native CopyParty databases (`shares.db`, and `sessions.db` when required) to CopyParty's XDG configuration directory. There is no generated Authentik include to recreate.

```bash
sudo systemctl restart copyparty.service
sudo systemctl status copyparty.service
```

Confirm:

- `/shares` and `/shares/admin/copyparty-config` are visible only to `nas_admin`;
- dynamic personal volumes resolve to the intended ZFS paths;
- shared/group volumes reference the correct Authentik group names;
- native share links and flags behave as expected;
- TFTP policy is correct when enabled.

Search Cockpit **NAS Help** for the exact installed CopyParty `--help` and `--help-flags` output when rebuilding configuration.

## Syncthing identity recovery

Restore the complete Syncthing configuration directory, including `config.xml`, `cert.pem`, and `key.pem`; those files preserve the local device identity and REST API key. Restore user device declarations in Authentik's `nasSyncthingDevices` attributes. Then:

```bash
sudo systemctl start syncthing.service
sudo nas-identity-sync sync-syncthing
sudo systemctl status syncthing.service
```

Check that only reserved `nas-` folders/devices were reconciled. The global `/syncthing/` UI is admin-only; ordinary users edit declarations through Authentik at `/settings/syncthing`.

## Restic boot/system recovery

Before a full restore, validate and compare a current state bundle when one is available:

```bash
sudo nas-state validate /path/to/nas-state.tar.gz
sudo nas-state diff /path/to/nas-state.tar.gz
```

`nas-state restore` requires an exact hostname confirmation, explicit sensitive-state permission, and creates a rollback bundle before applying authorities. Use `--allow-partial` only when the manifest identifies an understood missing optional authority.


The `nas-boot-system` repository contains `/boot`, machine and SSH identity, the Nix configuration, KeePass, Authentik media/database dump, CopyParty mutable configuration plus staged native share-link databases, Syncthing identity, and selected service state.

When the repository is on the same ZFS pool, import/mount the pool before using Restic. Restore the boot/configuration paths to a staging directory first, compare them, and then copy the required files to the new boot device. A same-pool repository does not help when that pool is lost; use the Syncoid replica or an external Restic repository in that scenario.

## Syncoid replica recovery

Import the destination pool read-only first when practical, inspect snapshots, and select the intended recovery point. Replicate or clone into a new dataset rather than overwriting the only surviving copy. After verifying the recovered dataset tree and the embedded Restic repository, update `nas.zfsDataset`/mount configuration as necessary and perform the normal full verification checklist.

## Failed Nix generation or deployment

For an automatic update failure, `nas-update apply` should restore the previous persistent generation. For manual rollback:

```bash
sudo nixos-rebuild switch --rollback
sudo systemctl --failed
sudo nas-preflight
```

An older generation can also be selected in the bootloader. Do not garbage-collect known-good generations until a recovery drill has succeeded.

## Full restore verification checklist

Before reenabling timers, backups, or external clients, verify:

```bash
sudo zpool status -v
sudo zfs list -o name,mountpoint,mounted -r tank
sudo systemctl --failed
sudo nas-secrets status
sudo nas-secrets check-authentik-token
sudo nas-identity-sync verify-token
sudo nas-identity-sync status
sudo nas-feature-control status
sudo nas-update --status --json
```

Then confirm:

- Authentik login and MFA work;
- at least one enabled explicit `nas_admin` member exists;
- ordinary users manage passwords/MFA/profile and their own Syncthing declarations through Authentik;
- `/syncthing/`, CopyParty configuration, Cockpit administration, and app flags are admin-only;
- personal and shared CopyParty permissions match Authentik groups;
- a test snapshot and restore-safety snapshot can be created;
- a small test file can be restored from backup;
- alert delivery works; and
- Cockpit **NAS Help** loads and search returns generated command/CopyParty help and the final ownership document;
- the `nas-boot-system` Restic restore and Syncoid replica recovery have both been tested.

Perform a quarterly restore drill against disposable media or a VM and record the date, backup snapshot, commands used, failures, and corrective actions.

### Web unlock after recovery

If the normal reverse proxy is unavailable because secrets are locked, use `https://<host>.local:9092/console/` from a trusted interface. Authenticate with the local Linux administrator, open NAS Overview, and run the unlock form. If Cockpit is unavailable, use the local console and `sudo nas-secrets activate`; do not weaken the firewall or expose the recovery port publicly.
