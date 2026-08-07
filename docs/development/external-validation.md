# External validation

The QEMU tests cover appliance behavior with virtual disks and loopback services. `scripts/live-validation.sh` covers hardware, remote reachability, independent storage, and deployed credentials. Destructive drills require an exact `NAS_LIVE_CONFIRM` value.

## Locked boot and unlock

Run after a cold boot with a mode-0600 KeePass password file. Set
`NAS_COCKPIT_CA_FILE` to the exported Caddy CA certificate so the drill verifies
the real trust chain rather than using an insecure probe. Set
`NAS_REMOTE_PROBE_HOST` to an independent client that can test the trusted-LAN
Cockpit endpoint; the same CA file path must exist there. `NAS_WRONG_KEEPASS_PASSWORD_FILE`
additionally proves failed activation does not commit secrets.

```bash
sudo NAS_LIVE_CONFIRM=LOCKED_BOOT \
  NAS_KEEPASS_PASSWORD_FILE=/run/keys/nas-keepass-password \
  NAS_WRONG_KEEPASS_PASSWORD_FILE=/run/keys/wrong-password \
  NAS_COCKPIT_URL=https://nas.local/ \
  NAS_COCKPIT_CA_FILE=/etc/ssl/certs/nas-caddy-ca.pem \
  NAS_REMOTE_PROBE_HOST=validation-client \
  NAS_REMOTE_COCKPIT_URL=https://nas.local/ \
  NAS_REMOTE_COCKPIT_CA_FILE=/etc/ssl/certs/nas-caddy-ca.pem \
  ./scripts/live-validation.sh locked-boot
```

## CopyParty, personal volumes, and WebDAV

Use a disposable Authentik account and personal volume. `NAS_COPY_NATIVE_SHARE_URL` can point to a temporary native CopyParty share link.

```bash
NAS_COPY_USER=validation \
NAS_COPY_PASSWORD_FILE=/run/keys/validation-password \
NAS_COPY_BASE_URL=https://nas.local/dav/users/validation/ \
NAS_COPY_EXPECTED_PATH=/tank/shares/users/validation \
NAS_COPY_NATIVE_SHARE_URL=https://nas.local/share/TEMPORARY_TOKEN \
./scripts/live-validation.sh copyparty
```

## Authentik blueprint and browser authorization

The command verifies the deployed blueprint through the Authentik API and runs the Chromium authorization matrix against administrator, selectively granted, and baseline accounts.

```bash
NAS_AUTHENTIK_ORIGIN=https://nas.local \
NAS_AUTHENTIK_TOKEN_FILE=/run/nas-secrets/authentik/api-token \
NAS_OPERATOR_PASSWORD_FILE=/run/keys/operator-password \
NAS_ALICE_PASSWORD_FILE=/run/keys/alice-password \
NAS_BASELINE_PASSWORD_FILE=/run/keys/baseline-password \
NAS_SOURCE_ROOT=/etc/nixos \
./scripts/live-validation.sh authentik
```

## Syncoid replication and clone restore

The drill creates a disposable child dataset, replicates it, clones the replicated snapshot, verifies a marker through the clone, and removes the temporary source and clone.

```bash
sudo NAS_LIVE_CONFIRM=SYNCOID_DRILL \
  NAS_SYNCOID_SOURCE=tank/nas/validation \
  NAS_SYNCOID_TARGET=backup-host:backup/nas/validation \
  ./scripts/live-validation.sh syncoid
```

## Restic independent backup and restore

The drill writes a marker under `NAS_RESTIC_SOURCE`, creates a new Restic snapshot, restores that exact snapshot to independent storage, and compares the marker.

```bash
sudo NAS_LIVE_CONFIRM=RESTIC_DRILL \
  RESTIC_REPOSITORY=/mnt/independent/restic \
  RESTIC_PASSWORD_FILE=/run/keys/restic-password \
  NAS_RESTIC_SOURCE=/tank/validation \
  NAS_RESTIC_RESTORE_TARGET=/mnt/restore-drill \
  ./scripts/live-validation.sh restic
```

## Observability and alert routing

The drill writes and queries a synthetic Influx line-protocol series in VictoriaMetrics, checks vmalert rules, injects and queries a temporary NAS alert-router notification, verifies configured retention flags, and polls ntfy when enabled.

```bash
sudo NAS_NTFY_TOPIC_FILE=/run/nas-secrets/observability/ntfy-topic \
  ./scripts/live-validation.sh observability
```
