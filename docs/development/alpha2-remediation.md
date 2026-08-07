# 2.2.0-alpha.2 audit remediation

This note records remediation performed after reviewing the Alpha 24 project audit and the consolidated issue register against the 2.2.0-alpha.1 source tree. A finding is not considered runtime-qualified merely because its source-level fix and regression test pass here; the Nix/QEMU/installer/browser/hardware gates in `external-validation.md` still control install-ready status.

## Fixed in Alpha.2

- Cockpit first-start now passes `NAS_SETUP_ALLOW_ROOT=1` into the transient systemd unit rather than only the `systemd-run` client process.
- The shared operation coordinator no longer chmods the root-owned runtime directory from an unprivileged participant. `/run/nas-operations` is a setgid `root:nas-operations` directory, named locks are created atomically with no-follow semantics, stale metadata is bound to boot/process identity, and `appliance` is globally exclusive.
- Direct update and secret mutations now enter the same coordinator through `nas-operation-run`; setup marks already-coordinated child mutations to avoid nested self-deadlock.
- Native VM first-start scripts prepare the normalized plan, confirm its digest, and include a stale-digest rejection case.
- State staging uses private `/run/nas-state`, export enforces the restore-side expanded-size/member limits, existing heterogeneous path ownership/modes are preserved where policy is known, partial quiesce failure restarts already-stopped units, and rollback capture no longer performs an unnecessary second stop/start cycle.
- Telegraf converts `smart_device.health_ok` to numeric before VictoriaMetrics ingestion. Golden line-protocol contracts cover SMART, systemd, filesystem, ZFS, UPS, and uptime metric naming used by current rules/dashboards.
- Authentik read-only requests have bounded retry/backoff for network, 408/425/429, and 5xx failures. Mutating requests are not automatically replayed.
- Feature readiness fails fast on deterministic 4xx responses, corrupt transaction journals are quarantined, and the feature gate suppresses raw request-line logging.
- Alert-router `updatedAt` is RFC 3339, state replacement fsyncs the parent directory, and reduced at-least-once delivery semantics are documented and tested.
- Structured logging now uses explicit credential-key classification instead of unrestricted substring redaction and decodes byte output deterministically.
- Setup resume revalidates verification/preflight stages instead of trusting journal completion alone.
- Successful update state snapshots have explicit bounded retention.
- CI now runs `ruff format --check`, exposes the aggregate branch floor at the call site, and separates slow maintainer/release integration tests from the fast unit loop.
- Test orchestration preserves `.coveragerc`, isolates subprocess groups, kills leaked descendants, and uses tempfile-backed capture so inherited stdout/stderr descriptors cannot wedge the harness.
- State subprocess output is drained continuously while retaining only the configured bounded prefix, eliminating full-output buffering before truncation.

## Verified stale or already resolved in the current tree

The following consolidated items did not reproduce as active defects in Alpha.2 and were not rewritten merely to satisfy an older report:

- Cockpit overview probes are already concurrent with bounded independent probes.
- Missing alert-router `Content-Length` already returns 411; unsupported transfer framing is rejected.
- The x86_64-only assertion already provides an explicit supported-platform diagnostic.
- Zero-administrator setup state already has an explicit operator-facing diagnostic.
- The source-only Cockpit artifact boundary is already documented in `cockpit/dist/README.md` and release documentation.
- The alert router and portal do not currently share a Starlette/uvicorn transport stack, so the claimed "migration inconsistency" is not a reproduced regression.

## Partially mitigated / still open

- Generic state bundles still cannot reproduce every ACL, xattr, file capability, hard-link, sparse-file, immutable-flag, or application-native database/filesystem semantic. Prefer service-native backup or ZFS snapshot/send for authorities that need those semantics.
- Raw libvirt/application state remains riskier than service-native backup/snapshot. It requires an authority-by-authority backup design rather than another generic recursive-copy patch.
- Restore is still confirmed by hostname rather than a separately designed portable appliance identity, and there is not yet a timed remote-management acknowledgement/deadman rollback for network/firewall-changing restore.
- HMAC state signatures remain appliance-secret tamper detection, not portable asymmetric/offline provenance.
- Systemd-owned ZFS lifecycle helpers are not yet blindly wrapped in the operation coordinator; their startup/shutdown ordering must be proven in NixOS VM tests to avoid introducing lock-order deadlocks.
- Capability route topology/owner lifecycle cross-validation can be tightened further, but production capability policy now fails closed on missing generated registry data and does not accept independent group-name environment overrides.
- Update rollback still depends on the state-restore engine for mutable application rollback; version-aware application migration/downgrade drills remain a full-system qualification item.
- AI resource/model-integrity claims and compiled Cockpit CSP/XSS/runtime behavior still require verification against the exact built closure/browser bundle.

## Qualification still required

Alpha.2 remains source-only until the exact Cockpit lock/distribution is retained and the same revision passes Nix evaluation/builds, native unencrypted/encrypted NixOS tests, official-ISO install/reinstall/reconfigure/update/rollback/reboot, installed-system fuzzing, real browser authorization/layout/accessibility tests, ZAP, ZFS lifecycle/restore drills, independent-client firewall checks, and out-of-band recovery drills.
