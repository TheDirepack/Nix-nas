# Known risks and recovery matrix

This is the current risk register for privileged or multi-authority operations.
Resolved defects belong in executable tests and the changelog; only unresolved
operational boundaries remain here.

| Operation | Remaining failure boundary | Safe retry and recovery |
|---|---|---|
| First-start setup | Pool creation is intentionally non-compensatable. A successful setup can later become `configuration-changed`, `state-drift`, or `complete-unverified` when the normalized plan, authority probes, or final preflight no longer match. | Inspect `nas-setup status` and the journal. Never alter the device list to bypass an interrupted run. Reconcile the failed authority, acknowledge manual recovery explicitly when required, and repeat password mutation only with the dedicated confirmation. |
| Authentik account apply | The planner, journal, read-back verification, and explicit password replay improve convergence, but an accepted password cannot be restored automatically and remote API mutations are still a saga. | Use the sanitized completed/pending plan, re-run structural reconciliation, and deliberately rotate any password whose final value is uncertain. |
| State export and restore | The profile-aware registry, writer quiesce, signed manifest, canonical restore plan, exact unit snapshot, rollback retention, and database comparison digest are not one atomic cross-application ZFS snapshot. Authority roots now have code-owned owner/group/mode policy for restore onto an empty host, and existing heterogeneous subpaths preserve their observed local policy. The generic bundle still does not reproduce every ACL, xattr, capability, hard-link, sparse-file, or application-native database/filesystem semantic, and absent heterogeneous subpaths still require authority-specific restore policy. Raw mutable application/VM trees therefore remain higher risk than service-native backup or ZFS snapshot/send. The HMAC is appliance-secret trust, not a portable public signature. | Preserve KeePass and the bundle signing key through independent recovery media. Prefer service-native backup or ZFS snapshots/send for application and VM storage where available. Validate, diff, and inspect snapshot metadata before restore. Stop or isolate any external writer not included in the generated quiesce set. |
| Syncthing reconcile | Desired state is journaled and owned objects are read back before commit, but Syncthing does not expose one transaction spanning every device and folder mutation. | Re-run reconciliation to converge the prepared generation. Escalate only when an unmanaged object conflicts with a reserved managed identifier. |
| Cockpit operations | Shared conflict classes and atomic reservations prevent incompatible privileged operations. First-start is a detached systemd job with reconnect-safe journal progress; a common cancellation protocol is still not available for every systemd job. | Reload Cockpit and inspect active operation metadata plus the durable setup/update journal. Cancel only through a workflow-specific recovery path; killing the browser does not cancel the operation. |
| Secret activation | Swap rollback is phase-aware and checked, but a failed protected-stack restart after restoring the prior tree still requires operator intervention. | Keep the previous tree, inspect the correlated journal entries, repair the failed unit, then restart `nas-protected-services.target` or reactivate secrets. |
| Update deployment | Candidate source, mutable-state snapshot, Nix generation, and rollback evidence are recorded, but a database migration may not be safely downgradeable and local health does not prove second-host reachability. | Use NanoKVM or another out-of-band path, inspect the manual-recovery marker, and restore application state only under the documented compatibility policy with all writers stopped. |
| Network/firewall state restore | Restoring NetworkManager/firewalld state can still sever remote administration after the mutation begins; there is no independent acknowledgement/deadman rollback yet. | Perform network-affecting restore with NanoKVM/out-of-band access until a timed remote-confirmation rollback contract is implemented and VM-tested. |
| Direct storage lifecycle mutations | Setup/state/update/identity/feature/secret paths now share the operation coordinator, but systemd-owned ZFS lifecycle helpers still require runtime proof before being wrapped because naïve nesting can deadlock protected-target startup. | Treat overlapping manual storage lifecycle operations as unsupported until the native/QEMU service-ordering tests prove a coordinator-safe integration. |

## UI build boundary

The Cockpit package is a React 18 and PatternFly 6 application using the Starter
Kit esbuild/Sass layout. This source-only archive does not include a compiled
browser bundle or npm lockfile because the validation environment could not
reach the npm registry. It must not be treated as an installable appliance
release. A network-enabled builder must generate and retain the lockfile, build
`cockpit/dist`, and complete release preflight.

## Required external evidence

A source-only release is not hardware evidence. Nix evaluation, closure builds,
the native NixOS tests, evaluated service-user ownership tests, the official-ISO
install/reboot harness, firewall behavior, and applicable live drills must pass
before an install-ready designation.
