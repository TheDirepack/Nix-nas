# Audit remediation: 2026-10-04

Baseline: `7ace3266`. This report covers the external `bug-review.md` against
`57da3e8e`, the [project audit](project-audit-2026-10-03.md), and the
[testing audit](testing-audit-2026-10-03.md). The original audits remain historical
records. No release archive or deployment accompanies these changes.

## External review

| Finding | Outcome | Regression evidence |
|---|---|---|
| 1: quoted Python working directory | Emit the raw validated systemd path. | `test_v2_systemd.py`; host user-systemd execution also checked the process working directory. |
| 2: command dollars | Escape dollars in Exec directives, preserving literal Environment values. Apply the helper to Python, exec-runner, readiness, VM, and socket-proxy commands. | Literal dollars, percent signs, quotes, and backslashes in `test_v2_systemd.py`; actual host-systemd argv/environment readback. |
| 3: disk-backed key intermediates | Stream keys through noninteractive sudo. Bootstrap retains its root-only `/run` file; recovery export writes only the requested destination. | `test_zfs_key_staging.py` executes the production shell fragments, refuses operator-side mktemp, checks permissions and cleanup, and injects install failure. |
| 4: destructive storage safety | Inspect lsblk mount/holder ancestry and active swap device identities. Fail closed on incomplete inventory, recheck before destruction, and remove force flags from wipefs/zpool create. | Mounted root/boot partitions, swap, and incomplete-inventory rejection in `test_setup.py`; existing successful command-construction tests updated. |
| 5: ineffective backup settings | Already absent in this checkout. No replacement option or duplicate policy added. | Existing `test_dead_path_cleanup.py` and backup contracts guard the removed rclone option and resticprofile ownership. |
| 6: stale coordination token | Read metadata after the failed nonblocking flock probe. | Deterministic owner-handoff injection in `test_operation_lock.py`. |
| 7: identity header policy drift | Nix and Python read one packaged JSON registry, including all headers copied by the shared Nix helper. | Registry agreement and case-insensitive forbidden-header tests in `test_v2_caddy.py`. |
| 8: unsigned bundle fallback | Remove the production escape hatch; tests use private signing keys and sign deliberate manifest changes. | Missing key still fails with the retired environment variable set; existing signed archive/tampering cases pass. |

## Project audit

F1/F7 share bounded route names: ambiguous hyphenated or oversized pairs use a
SHA-256 name with an ID-incompatible underscore prefix. Ordinary short names
remain unchanged. Tests check distinct proxy/backends, capability expressions,
Caddy socket destinations, and real Linux socket binding at maximum ID lengths.

F2 now recognizes Compose target ownership. F3 honors an explicit empty export
quiesce policy before effective-state discovery. F4 runs database preparation
inside export's recovery scope. F5 rejects static identity headers irrespective
of case. F6 propagates on-demand restart failure and preserves the old reconcile
state; retry then publishes the changed fingerprint. F8 aligns README, security,
and invariant text with browser-only fresh setup, out-of-band locked recovery,
and V2 capability groups.

## Testing audit

| Finding | Source correction |
|---|---|
| T1 | Remove optional/nonbehavioral coverage fillers; keep the focused API, logging, identity, doctor, and storage suites. Unknown Cockpit actions must raise the current API error. |
| T2 | Execute production transaction and rollback shell with dependency-boundary stand-ins and real Git history. Fail seven stages against bootstrap/established revisions, fail systemd during compensation, observe pending state and restored authority, then retry. No test assigns simulated native state to the expected result. |
| T3 | Replace catch-all generated input tests with guaranteed-invalid strategies, exact validation exceptions, unchanged-input assertions, valid controls, and structured redaction checks. Oracle tests detect always-allow and unexpected-runtime-error substitutions. |
| T4 | Generate accounts in the current envelope; explicit valid/invalid examples and a sentinel prove account normalization runs. |
| T5 | Remove the all-module fuzzer declaration. Inventory validation requires Python test candidates; module accounting requires AST imports or explicit importlib loading, rejecting comment-only claims. These inventories describe ownership/discovery, not behavioral coverage. |
| T6 | Remove standalone browser textContent tests and duplicate upstream Alertmanager malformed-JSON tests. Keep custom renderer, alert-header, proxy, and notification-delivery checks. |
| T7 | Label compiler/plan and in-memory bundle tests by their actual scope. Preserve separate real apply, generation-recovery, reconciliation, and transaction fault suites. |
| T8 | Enforce covered/total branch counts for all 44 top-level custom modules, reject invalid metrics, and compare actual branch drift. Preserve the old combined floors as an additional guard. New branch floors derive from the measured audit baseline; the total branch floor is 70%. Both CI callers inherit that canonical default; an executable regression rejects a 68% report through their actual arguments. |
| T9 | Check the compiler's actual rejected input. Add maximum-length/hyphenated IDs, protected/on-demand changes, and generated sequences through real editor CAS and file apply. Stale edits must leave authority and projection bytes unchanged. Native failure/retry uses deterministic reconciliation and transaction tests. |
| T10 | Add regressions for the seven reproduced defects before fixing them, including failed restart retry and export recovery after preparation failure. |
| T11 | Require strategy-specific exits and diagnostics, successful parser/document baselines where applicable, and unchanged authority digests. Report executed/delegated/skipped commands separately; smoke mode runs fewer inputs. Oracle tests reject permission/dependency/crash-style failures. |
| T12 | Feed current fixtures through named overview, managed-service, and source sinks. Check all enabled visible overview controls for horizontal containment and Tab reachability; cancellation must restore focus and send no action. Remove the unsupported all-surfaces claim. |

The transaction shell tests prove project ordering, history recovery, and error
propagation. Their external adapter stand-ins do not prove native OS convergence.
The generated editor/apply sequences observe file transactions, not live service
lifecycle. Browser tests use the built custom UI with mocked backend responses.

## Validation

- Final source preflight: 1,516 deterministic Python tests passed, four skipped;
  49 separate maintainer/tooling tests passed; 78 JavaScript tests passed. Ruff,
  formatting, Pyright, ShellCheck, source/bundle checks, repository data, links,
  and fresh manifest verification passed. Preflight reports **partial** because
  Nix evaluation was explicitly skipped.
- Instrumented deterministic suite: 1,520 ran, four skipped, no failures. Actual
  branch coverage: **71.6% (3,533/4,936)**. The corrected coverage gate passed.
  Generated shell, Nix, browser, and property runs are outside that percentage.
- Focused property/accounting/setup/VM-contract run: 102 tests passed. The three
  expanded projection/stateful/editor-apply tests passed together in a final run.
- Browser qualification: 47 cases per Chromium desktop, Firefox desktop,
  Chromium mobile, and WebKit desktop passed, **188 total**. WebKit initially
  failed to launch on missing host libraries; the passing rerun used locally
  extracted Ubuntu ICU74/libxml2/flite libraries in an isolated browser cache.
- A temporary host user-systemd unit preserved literal command arguments,
  `${HOME}` in Environment, and the unquoted working directory. This checks the
  host version, not the flake-pinned systemd closure. The unit was removed.
- An isolated wheel build included the shared identity registry; importing the
  installed wheel read all 21 headers.

## Remaining qualification: one area

**Native NixOS/QEMU qualification remains open.** No pinned closure build, live
ZFS destruction/encryption drill, installed adversarial runner replay, or live
cross-capability proxy/backend routing test ran for this checkout. The host Nix
store is unavailable and another session owns the shared VM cache/ports. Do not
substitute that session's evidence.

Use a dedicated cache and unused ports to run the canonical VM wrapper:

```bash
NAS_QEMU_CACHE_DIR=/tmp/opencode/nas-remediation-qemu \
NAS_QEMU_SSH_PORT=2322 NAS_QEMU_HTTPS_PORT=9443 \
  ./scripts/qemu-test.sh persistent-test
```

Confirm those ports are free first. Run the pinned native encrypted/unencrypted
checks and installed-command workload in that owned environment before release.
The source-only fixes do not establish install-ready qualification.
