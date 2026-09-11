# NixOS NAS project audit - 2026-09-07

## Overview and scope

This report gives maintainers a targeted cross-subsystem audit of security,
failure handling, external integration, simplification opportunities, and user experience.
It is not an exhaustive review or a security, deployment, or hardware certification.

- Baseline: `5a7b7522385f96cc1af6e57d8b172e57b69f8fda`.
- Audience: maintainers familiar with NixOS, systemd, and the appliance authority model.
- Read [invariants](invariants.md), [architecture](architecture.md), and [known risks](known-risks.md) before implementing recommendations.
- A real system uses this project. Findings require controlled follow-up, not experiments on that installation.
- Future breaking changes need no compatibility migrations under the requested project policy.
- That policy does not remove backup, rollback, recovery-access, or validation requirements.
- This documentation-only PR implements no remediation and changes no version or changelog. Code remains unchanged from the baseline.
- Authorized VM follow-up built and activated the disposable test guest. No production deployment or testing of the real installation occurred.
- Source references use repository-relative paths and verified line ranges from the reviewed checkout; later edits can move them.

## Remediation follow-up - 2026-09-09

The overview, evidence table, finding details, and native follow-up below are the
historical audit record for the reviewed baseline. They have not been rewritten
as evidence for the remediation branch.

Source-level corrections and regression coverage for A01-A22 are implemented on
`audit/project-review-2026-09-07`, including its current uncommitted worktree.
This is an implementation status, not closure or appliance qualification. There
is no final fix revision to record while the remediation remains uncommitted.

| Remediation area | Findings | Source status | Qualification still required |
|---|---|---|---|
| Firewall generation and replacement | A01-A03 | Corrected with regression coverage | Native firewalld activation, replacement/retry, and second-host IPv4/IPv6 allow/deny probes |
| Setup trust, request bounds, capability lifecycle, and reconnect | A04-A06, A13 | Corrected with regression coverage | Installed proxy/socket boundary, abusive-client resource tests, browser reconnect, identity replacement, and reboot flow |
| Backup cleanup and state import bounds | A07-A08, A15 | Corrected with regression coverage | Real native-dump/ZFS failure cleanup and installed-appliance restore drills |
| Guarded updates and rollback | A09, A11 | Corrected with regression coverage | Native timer interleavings, failed candidate activation, health failure, rollback, and reachability checks |
| Caddy lock selection and complete-context validation | A10, A20 | Corrected with regression coverage | Repeated installed-VM lock/unlock/relock, delayed/failed reconciliation, and route probes |
| Effective state, parser, and generation lifecycle | A12, A16-A17, A19 | Corrected with regression coverage | Native activation/concurrency, filesystem-fault, and retention-stress qualification |
| Frontend packaging, validation workflow, VM guidance, and accessibility | A14, A18, A21-A22 | Corrected with regression coverage | CI artifact handoff, browser accessibility, and installed-VM endpoint/locked-state checks |

On 2026-09-09, the current remediation worktree ran:

```bash
env NAS_PREFLIGHT_SKIP_NIX=1 ./scripts/preflight.sh
```

All enabled source-level tiers completed successfully, including repository and
documentation validation, Python behavior/contracts, JavaScript behavior,
frontend bundle checks, Ruff, Pyright, and ShellCheck. The command reported
`Preflight partial: 1 check(s) were not executed: nix`; therefore this is a
source-preflight result only. Nix evaluation, native NixOS tests, QEMU suites,
official-ISO install/reboot, and installed-appliance remediation drills remain
outstanding. The earlier guest evidence below predates these corrections and
does not qualify them.

### Latest checkpoint - 2026-09-10

The checkpoint also includes integration corrections found while advancing VM
qualification. They support the audit acceptance work but do not add or close
separate audit findings.

The current uncommitted checkpoint passes source preflight, including 1,453
Python tests and the JavaScript and static gates. A clean VM run also passed the
first-run GUI, dedicated Authentik outpost credential, CopyParty activation,
and account-operation phases. It later stopped in the Authentik phase at this
harness assertion:

```bash
grep -q 'request_header -Remote-User' "$caddy_config"
```

The VM suite therefore remains incomplete. The failure is an assertion against
the Caddy configuration path selected from `ExecStart`, after the preceding
runtime checks passed; it does not by itself establish an Authentik runtime
failure. Diagnose the active/imported configuration boundary and rerun from a
clean VM before recording native closure.

**Go/no-go:** do not close the findings for release or designate the result
install-ready until the applicable native acceptance evidence above is recorded
against a committed remediation revision and the release checklist passes.

## Evidence and validation limits

Evidence labels distinguish what the audit actually establishes:

- **Isolated reproduction**: a fixture or mock exercises a failure without invoking the real privileged subsystem.
- **Native VM reproduction**: the guest's installed tool or kernel exercises a targeted fixture; this is not full appliance qualification.
- **Code + upstream contract**: project source conflicts with documented or inspected upstream semantics; installed behavior still needs verification.
- **Static risk/proposal**: source supports a failure path or improvement, but the audit did not execute the complete scenario.

The audit records the isolated results below. These targeted checks do not
establish whole-system correctness or qualify the installed production system.
No raw transcripts, real job capabilities, credentials, or installation data appear here.

| Audit evidence | Result | Boundary |
|---|---|---|
| Failed native dump probe | Partial fixture file remained; state absent | Mocked preparation command, not a real database dump |
| Failed preparation cleanup probe | Snapshot destruction failed; state absent | Mocked ZFS, not a real pool |
| Missing effective-state probe | Desired enabled/always state appeared effective | Isolated status model |
| Rollback guard probe | Failed service accepted as cancelled | Mocked systemctl result |
| Setup request-log probe | Literal fixture job ID reached log output | Mocked logger; no real token |
| Negative request-length probe | Handler called `read(-1)` | Mocked stream, not live HTTP framing |
| Firewall dependency-order probe | Missing zone produced `INVALID_ZONE` | Stateful mock respecting native dependency |
| Existing backup tests | 27 passed | Included again in broad Python counts; do not add totals |
| Cockpit and wizard npm audits | Both reported zero advisories | Point-in-time npm coverage only |
| Canonical isolated Python runner | 1,314 passed; 1,318 ran; 4 skipped; 0 failures/errors across 133 files in 29.6 seconds | Explicit exclusions below; coverage not measured |
| Direct Python unittest discovery | Timed out after 240 seconds | Neither a pass nor a diagnosis of a product defect |
| Node suite | 70 passed, 0 failed | Three actionable FormSelect warnings remain: A22 |
| Repository preflight | Original checkout failed on caches; clean baseline run completed as PARTIAL | Python/JavaScript/Nix tiers explicitly skipped in that preflight run |
| Guest build/activation | 59 derivations built successfully; switch returned exit 4 | Failed units prevent a successful activation/qualification claim |
| A01 packet fixture | Unlisted TCP port denied in default drop zone, accepted in `nas-lan` | Independent guest network namespace, not a second physical host |
| A02/A03 native offline validation | Priority zero and missing zone rejected | Temporary system-config directories; live policies unchanged |
| A10 transient oneshot fixture | Second start returned success without rerunning command | Native unit semantics, not a relock drill |
| A16/A19 pure input probes | Cyclic YAML raised `RecursionError`; suffix `-10` failed regex match | No resource-exhaustion measurements or retention stress run |
| A20 native Caddy validation | Unused invalid snippet accepted; importing it rejected | Validator fixture, not a live reload bypass |

### Host commands and final results

The host used Python 3.14.7 and Node 24.20.0. Initial Node validation lacked esbuild;
locked build dependency installation changed no tracked files. Commands from the repository root:

```bash
npm ci --prefix cockpit --ignore-scripts --no-audit --no-fund
npm audit --prefix cockpit --json
npm audit --prefix setup/first-run-wizard --json
node --test tests/js/*.test.mjs
env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_*.py'
env PYTHONDONTWRITEBYTECODE=1 ./scripts/run-unit-tests.py --quiet --timeout 60 --jobs 4 \
  --exclude test_maintainer_core.py --exclude test_maintainer_matrix.py \
  --exclude test_maintainer_release.py --exclude test_contract_tooling.py \
  --exclude test_fuzz_boundaries.py --exclude test_fuzz_custom_inputs.py \
  --exclude test_property_invariants.py --exclude test_secret_security_fuzz.py
```

Direct discovery exceeded its external 240-second budget. The isolated runner
completed with the counts above; its exclusions are not claimed as passing tests.
The separate 27-test backup run overlaps that result. Coverage was not measured.

The original `env NAS_PREFLIGHT_SKIP_NIX=1 ./scripts/preflight.sh` failed the
structure check on existing caches. No preexisting caches were deleted. In a clean
detached worktree at the full baseline, `/tmp/opencode/nas-audit-clean-validation`, this command completed:

```bash
env PYTHONDONTWRITEBYTECODE=1 NAS_PREFLIGHT_SKIP_NIX=1 NAS_PREFLIGHT_SKIP_TESTS=1 ./scripts/preflight.sh
```

Its result was **PARTIAL**, not a full preflight pass. It completed structure,
schema, version, documentation links, inventory, static scan, syntax, manifest,
Cockpit bundle fixture, Ruff lint/format, Pyright (zero errors), and ShellCheck checks.
That run skipped Python, JavaScript, and Nix tiers; independent suite results appear above.

### Authorized VM follow-up and operational boundary

Initially no VM was running and port 2222 refused connections. With user authorization,
`scripts/vm-start.sh` reused cached disposable disks and synchronized the checkout,
including documentation-only changes. The wrapper automatically builds and switches
when the source fingerprint changes; it was not a read-only startup operation.

- Guest: `nas-test`, virtualization reported as `kvm`, NixOS `26.05.20260801.6d65bfc`.
- Installed tools: firewalld 2.4.3, Caddy 2.11.4, Python 3.13.14.
- Build: 59 derivations succeeded. Activation returned exit 4 with `nas-authentik-proxy-outpost` and `nas-v2-apply-failed` failing.
- Read-only journal inspection showed reconcile dependency failure; the mount guard was inactive in the retained guest.
- No root cause is assigned to those environment faults. This retained-disk run is not clean installer qualification.
- The guest remains running for inspection. No production system or production deployment was touched.
- Active NAS firewall policies were never altered. A temporary veth interface received runtime zone membership for the packet fixture only.
- The packet listener, temporary interface membership, veth pair, and network namespace were removed afterward; no persistent firewall configuration changed.
- No full `qemu-test.sh all`, encrypted backup/restore, genuine relock, browser, or hardware drill was performed.

The host still cannot run Nix directly; use the documented VM wrapper, accounting
for its build/switch behavior. npm audits do not cover Nix closures, Open Container
Initiative (OCI) images, or all upstream projects.

## Prioritized finding register

High means a consequential authorization, recovery, exposure, or activation failure
under the stated preconditions. Medium means bounded availability, contract, or
workflow damage. Priority orders follow-up; it is not proof of active exploitation.
P1 should precede the next affected deployment; P2 follows in focused hardening work.
Low covers narrower validation, retention, and accessibility defects. The register contains 22 findings, A01-A22.

| ID | Priority | Severity | Finding | Evidence |
|---|---|---|---|---|
| A01 | P1 | High | Remote-admin policy accepts unmatched LAN traffic | Native VM packet reproduction |
| A02 | P1 | High | World policy uses reserved priority zero | Native VM offline validation + upstream contract |
| A03 | P1 | High | Firewall recreation puts policies before zones | Isolated reproduction + native VM offline validation |
| A04 | P1 | High | Root setup backend trusts loopback callers | Static risk/proposal |
| A07 | P1 | High | Failed native dump leaves untracked artifacts | Isolated reproduction |
| A08 | P1 | High | Failed cleanup deletes recovery inventory | Isolated reproduction |
| A09 | P1 | High | Source-page rebuild bypasses guarded update | Static risk/proposal |
| A10 | P1 | High | Caddy selector cannot reliably follow lock transitions | Native VM unit fixture + static integration risk |
| A17 | P1 | High | Prune failure can delete published generation | Static risk/proposal |
| A05 | P2 | Medium | Setup job capability enters request logs | Isolated reproduction |
| A06 | P2 | Medium | Setup HTTP input/concurrency lacks bounds | Isolated reproduction + static risk |
| A11 | P2 | Medium | Guard cancellation conflates inactive and never-fired | Isolated reproduction |
| A12 | P2 | Medium | Missing effective state becomes apparent availability | Isolated reproduction |
| A13 | P2 | Medium | Wizard loses progress capability and offers invalid reboot | Static risk/proposal |
| A14 | P2 | Medium | Wizard packaging accepts stale source bundles | Static risk/proposal |
| A15 | P2 | Medium | Archive count limit runs after header materialization | Static risk/proposal |
| A16 | P2 | Low | Cyclic YAML escapes typed validation errors | Isolated reproduction |
| A18 | P2 | Medium | Development caches make default preflight fail | Observed preflight failure + static risk |
| A19 | P2 | Low | Retention regex excludes valid generation suffixes | Isolated reproduction |
| A20 | P2 | Medium | Standalone Caddy validation skips unused path snippet | Native VM reproduction |
| A21 | P2 | Medium | VM guide advertises wrong endpoints and lock behavior | Code/document contract mismatch |
| A22 | P2 | Low | Optional-property selector lacks an accessible name | Source + Node rendering warnings |

## Finding details

### A01 - Remote-admin policy accepts more than its port list

- Severity/preconditions: High when the policy activates, traffic enters the configured LAN zone, and the host listens on a LAN-reachable address.
- Source: `services/nas_v2_network.py:242` and `services/nas_v2_network.py:462-470`.
- Evidence: native VM inspection found active policy `nv2m71d0c4a9cc93`, target `ACCEPT`, priority `-300`, ingress `nas-lan`, egress `HOST`, listing TCP 22, 9092, and 443.
- `nft list table inet firewalld` showed an unconditional final accept in `filter_IN_policy_nv2m71d0c4a9cc93`, before the LAN zone rules.
- The [firewalld policy manual](https://firewalld.org/documentation/man-pages/firewalld.policy.html) says the target handles packets unmatched by port/service rules.
- Impact: the management port list is not an allowlist; unmatched host traffic can receive acceptance before intended zone restrictions.
- A disposable namespace client at `192.0.2.2` could not connect to the guest fixture listener at `192.0.2.1:18792` in the default drop zone (exit 1).
- Assigning only the new disposable veth interface to `nas-lan` made that unlisted-port connection succeed (exit 0). Cleanup removed the fixture and membership.
- This confirms unwanted acceptance in the test guest, not production or Internet exposure. It does not expose loopback-bound sockets.
- The namespace provided an independent packet source, not a second physical host; IPv6 and the full access matrix remain untested.
- Fix: use a nonterminal `CONTINUE` policy with explicit management ports, consistent with the intended zone policy.
- Regression acceptance: activate the policy in the pinned VM and probe allowed and disallowed listening ports from a second host.
- Acceptance must include IPv4/IPv6 where supported, a loopback-only listener, and preserved intended management access.

### A02 - Isolated-workload world policy uses reserved priority zero

- Severity/preconditions: High when an isolated workload generates a world/egress policy and the daemon validates it.
- Source: `services/nas_v2_network.py:352-366`, especially the `"0"` argument at line 361.
- Evidence: native firewalld 2.4.3 offline validation in a temporary system-config directory rejected priority zero with exit 139, `INVALID_PRIORITY`, reserved `[0]`.
- The same fixture with priority 50 passed (exit 0). This was an offline validator result, not a live policy mutation or a claim that exit 139 indicated a crash.
- Upstream [firewalld v2.3.1 policy.py](https://raw.githubusercontent.com/firewalld/firewalld/v2.3.1/src/firewall/core/io/policy.py) defines `Policy.priority_reserved = [0]` and rejects it in `_check_config`.
- Impact: the generated policy fails validation, blocking isolated-workload firewall activation rather than expressing the requested outbound default.
- Fix: choose a supported nonzero priority with documented ordering relative to management, host, and other workload policies.
- Regression acceptance: validate both outbound allow and deny projections against the pinned daemon, not just an XML parser.
- Include explicit egress exceptions and confirm that priority changes preserve packet behavior.

### A03 - Firewall replacement creates dependent policies before zones

- Severity/preconditions: High when desired policies reference V2 zones removed or not yet created during replacement.
- Source: `services/nas_v2_firewalld_reconcile.py:241-254`; test gap at `tests/test_v2_firewalld_stateless.py:88-124`.
- Evidence: isolated reproduction reported `INVALID_ZONE` with a dependency-aware mock.
- Native offline follow-up created `audit-policy`, then rejected adding nonexistent ingress zone `audit-zone` with exit 112, `INVALID_ZONE`.
- `--check-config` also rejected a missing-zone fixture with exit 112. All operations used temporary system-config directories, not the active namespace.
- The upstream `Policy._check_config` implementation linked in A02 requires ingress/egress names in `existing_zones`, apart from symbolic zones.
- The reconciler deletes policies and zones, then sorts path keys; `policies/` precedes `zones/`.
- Impact: replacement can stop partway through permanent configuration changes, before validation/reload succeeds.
- Existing tests mock `_apply_zone` and `_apply_policy` independently and only check that each was called.
- Fix: validate the desired graph first, create zones before policies, and preserve recoverable state across partial native API failures.
- Regression acceptance: a stateful subprocess-boundary fixture must reject premature policy creation and pass the corrected sequence.
- Then test first activation, replacement, injected mid-apply failure, and retry against the pinned firewalld daemon.

### A04 - Root setup API treats loopback reachability as authorization

- Severity/preconditions: High during first setup if an unprivileged local process or compromised service can reach host loopback.
- Source: `services/nas_cockpit_api.py:1254-1326`; `modules/nas/config/application-services.nix:204-235`.
- Related gate: `modules/nas/config/caddy-bootstrap.nix:57-63`; completion check at `services/nas_cockpit_api.py:494-498`.
- Evidence: static risk/proposal. The root service accepts plan GET and setup POST without backend caller authentication.
- Caddy forward authentication protects requests through the proxy, not direct TCP connections to `127.0.0.1:8980`.
- Impact: a reachable local caller can obtain the plan and submit privileged setup through the backend, bypassing browser authentication.
- Completed setup blocks resubmission. This is not a claim of unauthenticated Internet access or arbitrary remote code execution.
- Fix: use a permissioned Unix socket accessible only to Caddy, plus narrow backend authorization and a constrained privileged worker.
- Regression acceptance: an unprivileged local account and a representative compromised-service sandbox cannot fetch plans or submit setup directly.
- Authorized setup must still survive temporary identity replacement; completion must continue to reject repeat mutation.

### A05 - Request logging records a bearer job capability

- Severity/preconditions: Medium if a caller can read the relevant logs while the job capability remains usable.
- Source: `services/nas_cockpit_api.py:1238-1259,1276-1284,1311-1312`; `modules/nas/config/caddy-bootstrap.nix:48-55`.
- Evidence: isolated logger probe recorded the literal fixture job ID in a GET request path.
- Job polling and completed-job reboot deliberately use the ID as a bearer capability after Authentik replacement.
- Impact: log access can disclose a status/reboot capability; the report does not include an actual capability or claim broader setup authority.
- Fix: move the narrow ephemeral capability out of URLs into a protected header or secure cookie; redact logs and define expiry/revocation.
- Cookie designs need request-forgery protections and must not become a general browser-authentication bypass.
- Regression acceptance: capture backend/proxy logs for success and failure requests and assert that capability bytes never appear.
- Expired, revoked, unrelated, and malformed capabilities must fail without affecting the authorized job.

### A06 - Setup HTTP server lacks complete request and resource bounds

- Severity/preconditions: Medium for direct loopback callers; slow valid requests also need evaluation through the proxy.
- Source: `services/nas_cockpit_api.py:1291-1294,1315-1326`.
- Evidence: isolated stream probe confirmed `Content-Length: -1` reaches `read(-1)`; concurrency/deadline concerns are static risks.
- The upper-bound check does not reject negative lengths. The configured `ThreadingHTTPServer` adds no socket deadline or bounded worker count.
- Impact: stalled reads or many concurrent requests can consume backend resources and impede setup.
- A front proxy may reject negative framing, so the negative-length probe does not establish a remote proxy bypass.
- Fix: reject negative/ambiguous framing, enforce body and socket deadlines, and bound concurrency using a maintained protocol server where appropriate.
- Regression acceptance: negative, malformed, conflicting, oversized, truncated, and slow bodies fail within stated resource/time limits.
- Test direct backend and proxied paths separately; a valid request must still succeed while abusive connections are rejected.

### A07 - Failed native dump leaves its partial output untracked

- Severity/preconditions: High for backup correctness when a native preparation unit writes output and then fails.
- Source: `services/nas_v2_backup.py:497-512,550-557,590-607`.
- Evidence: isolated preparation mock wrote a fixture artifact, raised, and left the file behind with no runtime state.
- `_native_dump_path` returns only after the unit succeeds; `native_dumps` records the artifact after that return.
- Impact: failure cleanup cannot find the failing job's partial output, violating the staged-artifact cleanup invariant.
- Residue can retain sensitive dump bytes and require manual cleanup. No real data loss or successful backup of partial data was observed.
- Fix: persist a validated cleanup intent before starting the dump, or ensure the helper cleans its own partial output on every failure.
- Keep staging-root confinement and symlink protections intact when recording that intent.
- Regression acceptance: a unit writes a fixture then fails; preparation reports failure, publishes no backup paths, and removes the partial artifact.
- If removal fails, durable state must retain the exact cleanup obligation for retry.

### A08 - Preparation cleanup erases retry state even when cleanup fails

- Severity/preconditions: High when preparation fails after creating resources and snapshot/artifact cleanup also fails.
- Source: `services/nas_v2_backup.py:590-611`; retry subcase at `services/nas_v2_backup.py:615-654`.
- Evidence: isolated mock created a snapshot, encountered a later invalid resource, failed destruction, and observed absent state.
- Impact: the command reports cleanup failure but deletes the inventory needed to retry cleanup, orphaning tracked resources.
- This establishes lost recovery bookkeeping, not observed loss of production data.
- Medium subcase: standalone cleanup retains state on failure but does not remove successful snapshot entries; retry attempts to destroy already-destroyed snapshots.
- Fix: persist only outstanding cleanup obligations after each success; remove state only after all obligations complete.
- Treat already-absent owned snapshots as complete only after a reliable native absence check, not by swallowing arbitrary errors.
- Regression acceptance: mixed successful/failed destroys leave only failures in durable state, then a retry succeeds without repeating completed work.
- Include native artifacts, process interruption between updates, and preparation-failure cleanup as well as standalone cleanup.

### A09 - Supported source-page rebuild bypasses the guarded updater

- Severity/preconditions: High when an authorized root administrator chooses `rebuild` or `pull-rebuild` in the supported interface.
- Source: `services/nas_cockpit_api.py:1142-1193`; `cockpit/src/pages/source-page.jsx:53-61`.
- Guarded alternative: `scripts/update-nas.sh` owns candidate source, preflight, mutable-state capture, health checks, and rollback handling.
- Evidence: static risk/proposal. The API invokes `nixos-rebuild switch` directly and can first pull into the active checkout.
- Impact: users can select an update path that omits the appliance updater's safety contract despite operation-lock admission.
- This is unsafe authorized workflow, not privilege escalation; a root administrator already has host authority.
- Fix: keep source inspection read-only and route supported deployment actions through the existing `nas-update` authority.
- Expose candidate review, asynchronous progress, health results, and recovery state instead of a parallel switch operation.
- Regression acceptance: every supported UI activation reaches the guarded updater; a failing candidate leaves the previous system recoverable.
- Test state capture, health failure, independent reachability requirements, rollback failure, and clear UI recovery guidance.

### A10 - Caddy selector does not reliably rerun or await generated configuration

- Severity/preconditions: High when secret/setup state changes after the selector's first successful start, especially relocking.
- Source: `modules/nas/config/caddy-bootstrap.nix:121-135,158-180`.
- Evidence: a native transient oneshot with `RemainAfterExit=yes` created a temporary marker on its first run. After marker deletion, a second start returned 0 without recreating it.
- The fixture unit was stopped/reset afterward. Read-only inspection of `nas-caddy-bootstrap.service` showed `ActiveState=active` and `RemainAfterExit=yes`.
- A `Type=oneshot` service with `RemainAfterExit=true` remains active; starting that active unit does not rerun its command.
- See [systemd.service](https://www.man7.org/linux/man-pages/man5/systemd.service.5.html) and [systemd.path](https://www.man7.org/linux/man-pages/man5/systemd.path.5.html).
- The selector also starts reconciliation asynchronously, checks `caddy-managed.conf` immediately, and does not watch that generated file.
- Impact: bootstrap/full configuration selection can become stale; relocking may not drop the full configuration as intended.
- This does not prove a live protected endpoint remained usable after relock; backend availability and authorization still matter.
- Fix: make selection rerunnable and tie full-config selection to successful generation readiness, with explicit fail-closed relock behavior.
- Regression acceptance: repeat locked/unlocked/relocked transitions in a real VM, including delayed and failed reconciliation.
- Verify the active Caddy configuration and second-host routes after each transition; full configuration must disappear after relock.

### A11 - Guard cancellation cannot distinguish a fired rollback from an unused guard

- Severity/preconditions: Medium if rollback has failed, completed, or been collected before cancellation checks service activity.
- Source: `services/nas_guarded_apply.py:115-123`; production narrowing at `modules/nas/config/managed-services-transactions.nix:72-79`.
- Evidence: isolated mock returned a failed service result and cancellation still returned success.
- Cancellation refuses only `is-active` return code zero, then resets failed status; inactive/not-found results can also describe an already-fired rollback.
- Impact: the generic guard contract can claim cancellation without proving rollback never started.
- Production rollback stops reconciliation first, narrowing the race. This is not proof of a production false commit.
- Fix: record a durable fired/claimed outcome and coordinate commit/cancel against it rather than relying on current unit activity.
- Preserve failure evidence instead of resetting it before the transaction outcome is established.
- Regression acceptance: never-fired, active, failed, completed, and collected cases have distinct correct outcomes.
- Validate actual timer/reconcile interleavings in a VM before claiming production transaction safety.

### A12 - Missing effective state is reported as available desired state

- Severity/preconditions: Medium when effective state is absent, malformed, or lacks a desired service during status/launch checks.
- Source: `services/nas_v2_editor.py:243-271`; `services/nas_v2_control.py:78-129`; `services/nas_cockpit_api.py:353-371`.
- Evidence: isolated missing-file probe reported a desired enabled/always service as effective and runtime-available.
- The live systemd overlay adds activity but does not repair the false effective-state fields.
- Impact: the UI confuses requested configuration with compiled availability; the managed-job allowlist also consumes `effective`.
- The audit does not establish that an arbitrary job launches successfully, only that this admission predicate can use fallback desired state.
- Fix: report effective state as unknown/unavailable until valid compiled state exists; keep desired mode visible in its own field.
- Disable job launch when compiled availability cannot be established.
- Regression acceptance: missing, malformed, and incomplete effective documents cannot produce an eligible job or a verified-availability badge.
- Valid effective state and live activity must remain separate, accurate outputs.

### A13 - Wizard refresh loses job tracking; completed response loses reboot capability

- Severity/preconditions: Medium when the page refreshes during setup or submission returns an already-completed status.
- Source: `setup/first-run-wizard/src/steps/ConfirmStep.jsx:54-73,108-110,120-127`; `setup/first-run-wizard/src/index.jsx:55-70`.
- Backend contract: `services/nas_cockpit_api.py:1238-1247` requires a completed job with a 24-hex-character ID for reboot.
- Evidence: static risk/proposal. Job state exists only in React state; app initialization fetches the plan, not a resumable job association.
- Impact: refresh loses polling capability while temporary Authentik sessions may have been invalidated during setup.
- Distinct bug: the completed-response branch explicitly sets an empty job ID but still follows the completed UI path; reboot cannot satisfy backend validation.
- Fix: design safe resumable job association and capability lifecycle, coordinated with A05. Do not persist bearer IDs in localStorage.
- For an existing completed response, obtain an authorized completed-job association or disable reboot with explicit recovery guidance.
- Regression acceptance: refresh/reconnect during identity replacement resumes only the authorized job without resubmitting destructive setup.
- Test already-completed submission, expired capability, lost browser state, successful reboot, and backend rejection.
- UX acceptance: present `complete-unverified` as a warning with verification/recovery guidance, not equivalent verified success.

### A14 - Wizard packaging checks presence, not source integrity

- Severity/preconditions: Medium when wizard source changes but committed distribution files do not get rebuilt.
- Source: `modules/nas/internal/documentation-tools.nix:89-124`; `setup/first-run-wizard/build.js:8-42`.
- Pipeline references: `scripts/ci-qualification.sh:189-212`; `.github/workflows/release.yml:163-170`.
- Evidence: static risk/proposal. Cockpit runs `build.js --check`; wizard packaging only tests nonempty files and copies them.
- The wizard builder has no check mode. The cited qualification/release blocks rebuild and verify Cockpit, not the wizard.
- Impact: reviewed wizard corrections can be absent from the shipped interface, including fixes to first-setup behavior.
- Fix: share source-bound build metadata/integrity logic across both esbuild frontends and verify reproducible output in packaging and CI.
- Include the wizard lockfile in recurring dependency audits, not just this audit session's zero-advisory result.
- Regression acceptance: modify wizard source without rebuilding and require packaging/check mode to fail; rebuilding must restore success.
- CI must build/audit both lockfiles and detect missing, stale, or tampered assets without silently rewriting them in check mode.

### A15 - Archive count limit does not bound header materialization

- Severity/preconditions: Medium when an administrator imports a crafted or malformed state bundle.
- Source: `services/nas_state.py:797-814,959-963`; manifest authentication at `services/nas_state.py:881-886`.
- Evidence: static risk/proposal. `getmembers()` materializes archive headers before the member-count check rejects excess entries.
- Validation extracts before loading the manifest and checking its hash-based message authentication code (HMAC).
- Impact: a bundle can consume parsing/memory resources before count limits or authenticity rejection protect the caller.
- This is not a signature bypass; existing path, object-type, and extracted-byte checks still have value.
- Fix: bound streaming member count, metadata, names, and decompressed bytes during parsing, before accumulating an unbounded list.
- Keep extraction confined and fail closed before restore mutation; do not weaken manifest authentication to simplify streaming.
- Regression acceptance: use a deliberately small test count limit and many empty members, without a large payload, to prove early rejection.
- Also cover metadata-heavy headers, truncation, bad HMAC, valid small bundles, and bounded cleanup after failure.

### A16 - Cyclic YAML escapes the typed validation boundary

- Severity/preconditions: Low when an administrator edits desired-state YAML to include a recursive alias.
- Source: `services/nas_v2_spec.py:59-100`; `_plain` recursively normalizes before structural schema validation.
- Evidence: isolated `parse_yaml_text("loop: &loop [*loop]")` raised `RecursionError: maximum recursion depth exceeded`.
- Impact: a tiny input aborts parsing outside the expected `ManagedServicesV2Error` contract; this is not unauthenticated remote code execution.
- Alias-driven amplification is a potential resource risk, but exponential growth and resource exhaustion were not measured.
- Fix: reject cycles and enforce depth/node budgets during normalization, returning a typed, actionable validation error.
- Regression acceptance: keep the minimal cyclic fixture, add bounded deep/wide cases, and require prompt typed rejection without a traceback.
- Valid acyclic aliases must retain defined behavior; shrink any generated failing cases to small regression fixtures.

### A17 - Pruning failure can discard the generation just published

- Severity/preconditions: High when publication succeeds and subsequent pruning raises an exception.
- Source: `services/nas_v2_entry.py:183-195`; `services/nas_v2_generation.py:147-149,182-205`.
- Evidence: static risk/proposal based on control flow; this failure was not injected or reproduced. The unrelated guest activation is not evidence for this path.
- Publication switches the current link. Pruning runs inside the same exception scope, whose handler calls `discard_generation(generation)`.
- Impact: cleanup intended for unpublished output can delete the published tree, leaving current and compatibility links dangling.
- Fix: explicitly separate unpublished cleanup from post-publication maintenance; never discard a tree selected as current.
- Schedule pruning after successful activation and make pruning failure non-destructive to current output and recovery evidence.
- Regression acceptance: inject pruning failure after publication and verify current still resolves with all expected artifacts.
- Also test pre-publication failure cleanup, failed activation retention, and a later successful pruning retry.

### A18 - Default development preflight rejects normal development artifacts

- Severity/preconditions: Medium for contributors who run documented Python tests or install frontend dependencies in the checkout.
- Source: `scripts/validate-structure.py:193,221-244`; documented workflow at `docs/development/README.md:26,36-44`.
- Evidence: original-checkout preflight failed while listing existing caches; source confirms default rejection of `__pycache__` and `node_modules`.
- A clean detached baseline worktree completed the reduced PARTIAL preflight described above; it does not resolve the normal-checkout workflow conflict.
- A Cockpit-specific environment exception exists, but default checks still conflict with ordinary test/install output and wizard dependencies.
- Impact: contributors must clean or work around generated artifacts before normal validation, obscuring useful failures and slowing feedback.
- No preexisting caches were removed for this report, and this is not a product-runtime security defect.
- Fix: separate clean release/package staging requirements from development validation; use documented hermetic output/cache locations where useful.
- Preserve strict artifact exclusions for shipped archives rather than weakening release cleanliness checks.
- Regression acceptance: from a clean checkout, install both frontends, run documented tests, then run development preflight without deleting generated directories.
- Package staging must still reject unwanted caches, dependencies, credentials, and runtime state.

### A19 - Retention excludes generation suffixes the allocator creates

- Severity/preconditions: Low after repeated allocations for the same revision reach suffixes beginning with `1`, such as `-10` or `-100`.
- Source: `services/nas_v2_generation.py:25-26,35-58,152-174`.
- Evidence: isolated `_GENERATION_NAME_RE.fullmatch("a" * 40 + "-10")` returned no match.
- The allocator creates suffixes 2 through 9999; `[2-9][0-9]*` excludes 10-19, 100-199, and other valid suffixes starting with `1`.
- Impact: pruning skips these generated directories, retaining unnecessary `/run` output. This is separate from A17's published-tree deletion risk.
- Fix: align accepted names with allocated integer suffixes of at least 2, preferably through one shared naming contract.
- Regression acceptance: accept 10, 19, and 100; reject invalid suffixes; allocate more than 20 generations and verify bounded retention while preserving current.
- No full retention stress test was performed in this audit.

### A20 - Caddy validation does not exercise the unused path-route snippet

- Severity/preconditions: Medium when generated path-route content is invalid only when imported into an appliance site.
- Source: `services/nas_v2_caddy.py:307-320,337-353`; `services/nas_v2_apply.py:326-334`; `tests/test_v2_caddy_validate.py:47-83`.
- Evidence: Caddy 2.11.4 accepted an unused `(nas_v2_managed_paths)` snippet containing `audit_invalid_directive` with exit 0, `Valid configuration`.
- Adding a local HTTP site that imports the snippet made validation fail with exit 1 for an unrecognized directive.
- The generator defines path handlers inside that snippet; standalone validation does not import it into the appliance site. The cited route test repeats that blind spot.
- Impact: invalid path content can pass pre-publication checks and reach later activation, potentially after files publish or dependent services start.
- Live Caddy reload still rejects invalid imported configuration; this is a validation blind spot, not a reload authorization or syntax bypass.
- Fix: validate the full staged appliance configuration, importing generated paths in their actual site context before publication.
- Regression acceptance: reject the malformed-snippet fixture before publication and validate generated route semantics within actual site imports, including valid path and hostname routes.

### A21 - VM documentation contradicts harness endpoints and locked-boot policy

- Severity/preconditions: Medium when a contributor follows the VM guide to inspect or qualify appliance access.
- Source: `docs/development/vm-testing.md:60-65,143-144`; `scripts/qemu-test.sh:45-51`; `docs/development/invariants.md:18-20`.
- Evidence: code/document contract mismatch. The guide advertises HTTP 8088 and direct Cockpit 9094; the harness forwards only SSH 2222 and HTTPS 8443 by default.
- It also says Cockpit remains reachable while locked and Caddy stops, conflicting with the recovery-plane invariant and bootstrap configuration.
- Impact: contributors use nonexistent endpoints and may test against the wrong browser-authorization expectations.
- Fix: document HTTPS and the authenticated `/console` path; distinguish bootstrap guidance from locked-state out-of-band recovery, without promising browser management while locked.
- Regression acceptance: add a lightweight documentation contract check against one harness endpoint definition and review lock-state instructions against invariants.
- Avoid proliferating brittle source-string tests. No documentation correction outside this report is included in this PR.

### A22 - Optional-property picker has no accessible name

- Severity/preconditions: Low when a screen-reader user reaches an object with optional fields in the schema editor.
- Source: `cockpit/src/schema-editor.jsx:185-234`, especially the `FormSelect` at lines 212-221.
- Evidence: the element has neither `id` nor `aria-label`, and its parent provides no associated label. Node rendering emitted `FormSelect requires either an id or aria-label` three times despite 70 passing tests.
- Impact: the unnamed control makes its purpose difficult to identify with assistive technology; placeholder option text is not an associated control label.
- Fix: provide a unique, meaningful accessible label for each schema path, using an associated label or suitable `aria-label`.
- Regression acceptance: assert accessible names for nested pickers, treat actionable component warnings as test failures, and run axe plus browser keyboard/screen-reader checks.
- No browser-based accessibility audit was performed; the observed evidence is source inspection and rendering warnings, not a complete accessibility assessment.

## Reproducibility of targeted native checks

Use only an authorized disposable guest with the installed tool versions recorded
above. These fixtures do not require editing project code or active NAS policies.
Run each shell block separately. They create temporary files and clean them on exit.

The priority fixture uses an isolated firewalld system-config directory; it must
not point at `/etc/firewalld`. Expected validator exits are 139 for zero and 0 for 50:

```bash
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$work/policies"
for priority in 0 50; do
  printf '<policy target="CONTINUE" priority="%s"><ingress-zone name="HOST"/><egress-zone name="ANY"/></policy>\n' "$priority" > "$work/policies/audit-policy.xml"
  if firewall-offline-cmd --system-config="$work" --check-config; then
    printf 'priority=%s exit=0\n' "$priority"
  else
    printf 'priority=%s exit=%s\n' "$priority" "$?"
  fi
done
```

For A03, use another empty temporary system-config directory. Create `audit-policy`
with `--new-policy=audit-policy`, then issue `--policy=audit-policy --add-ingress-zone=audit-zone`
without creating that zone. The second command returns 112; a missing-zone XML
fixture also fails `--check-config`. Supply `--system-config` on every offline command.

This Caddy fixture validates files only; it does not start a listener or reload Caddy:

```bash
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
printf '(nas_v2_managed_paths) {\n audit_invalid_directive\n}\n' > "$work/Caddyfile"
caddy validate --config "$work/Caddyfile" --adapter caddyfile
printf 'http://127.0.0.1:18791 {\n import nas_v2_managed_paths\n}\n' >> "$work/Caddyfile"
if caddy validate --config "$work/Caddyfile" --adapter caddyfile; then
  printf 'unexpected acceptance\n'
else
  printf 'imported snippet rejected: exit=%s\n' "$?"
fi
```

For A10, in the disposable guest create a unique transient unit with
`systemd-run --unit=<unique-name> --property=Type=oneshot --property=RemainAfterExit=yes -- /run/current-system/sw/bin/touch <temporary-marker>`.
Wait for its first marker and active state, delete only that marker, then issue
`systemctl start <unique-name>.service`. The second start returns 0 without creating
the marker. Stop/reset the unique fixture unit and remove its temporary directory.
Do not substitute `nas-caddy-bootstrap.service`; genuine lock transitions remain a separate acceptance test.

For A01, construct a disposable veth pair and namespace on a verified nonoverlapping
`192.0.2.0/30` network. Bind a temporary guest listener to `192.0.2.1:18792` and connect
from namespace address `192.0.2.2`, first in the default drop zone and then with only
the new guest interface assigned to `nas-lan`. Read the existing policy/nftables
rules without editing them. Use guaranteed cleanup for listener, runtime membership,
veth pair, and namespace. The recorded deny/allow result proves this IPv4 fixture only.

Pure host probes from the repository root require the existing project Python dependencies:

```bash
env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=services python3 -c 'import nas_v2_spec as s; s.parse_yaml_text("loop: &loop [*loop]")'
env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=services python3 -c 'import nas_v2_generation as g; print(bool(g._GENERATION_NAME_RE.fullmatch("a" * 40 + "-10")))'
```

The expected current results are `RecursionError` and `False`, respectively, not
passing acceptance tests. Temporary audit helper scripts were not committed;
the fixture descriptions and commands above make their key results reviewable without those files.

## Simplification and external-project candidates

These are static proposals, not additional proven vulnerabilities or instructions
to add every package. Evaluate maintenance cost, closure size, authority boundaries,
and failure behavior before selecting an upstream dependency.

| Candidate and current target | Tradeoff | Acceptance before adoption |
|---|---|---|
| [firewalld D-Bus settings](https://firewalld.org/documentation/man-pages/firewalld.dbus.html) for `nas_v2_firewalld_reconcile.py` | Replace XML-to-many-CLI mutations with native settings; D-Bus does not promise a cross-object transaction | Preserve owned namespace, validate dependencies, inject partial failures, verify runtime with second-host traffic |
| Existing `nas-update` for `source_control` | One guarded update authority; asynchronous API/progress work remains | Remove supported direct-switch path and pass A09 failure/recovery tests |
| [systemd Unix sockets](https://www.freedesktop.org/software/systemd/man/latest/systemd.socket.html) for setup backend | Filesystem caller boundary instead of loopback trust; proxy access and privilege split still need design | Pass A04/A05/A06 tests and prove only intended proxy identity can connect |
| [sd_notify](https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html) and native service readiness | Reduce custom polling where upstream supports notifications; HTTP-only apps still need bounded HTTP probes | Use actual readiness, not process existence; test delayed readiness and timeout without growing a custom HTTP parser |
| [Upstream Cockpit applications](https://cockpit-project.org/applications.html) for storage, networking, Podman, and machines | Avoid duplicate management views; upstream surfaces may expose broader operations than appliance policy permits | Retain NAS-specific orchestration only; test authorization, navigation, and appliance ownership boundaries |
| [PatternFly](https://www.patternfly.org/) async progress; evaluate [AJV](https://ajv.js.org/) and [JSON Forms](https://jsonforms.io/) for schema editor/model | Standard interaction/validation can reduce handwritten code; widget integration and bundle cost may outweigh savings | Reuse the canonical JSON Schema, retain backend semantic validation, measure bundle/accessibility costs, introduce no second schema |
| Shared [esbuild](https://esbuild.github.io/) integrity helper for both frontends | Remove divergent stale-bundle contracts; helper becomes shared release-critical code | Both clean builds and deliberate stale-source checks pass A14 acceptance |
| [Restic](https://restic.readthedocs.io/), native database backup tools, and [OpenZFS](https://openzfs.github.io/openzfs-docs/) send/snapshot | Prefer maintained consistency/storage primitives over expanding generic `nas_state` filesystem semantics; recovery spans multiple tools | Demonstrate independent restore drills, preserve authority inventory, and document each backup failure domain |
| Generate a specification mirror from one canonical document | `docs/development/managed-services-v2-spec.md` and `spec/managed-services/README.md` compete as large specification entry points | Select one authority, generate or link the other, fail CI on drift, preserve useful anchors |
| Closure/image software bill of materials (SBOM), [OSV](https://osv.dev/), and [vulnix](https://github.com/nix-community/vulnix) evaluation | Extend beyond npm; Nix naming, backports, and OCI mapping create false positives | Scan pinned closures/image digests, record provenance and reviewed exceptions with expiry; never treat zero npm advisories as whole-system clearance |
| Subprocess-boundary fixtures plus small native VM integration tests | Mocks stay fast but must not invent native acceptance rules | Use realistic firewall zone/policy dependencies and run allow/deny, partial-failure, reload, and retry scenarios on the pinned daemon |

## Coverage matrix and known limitations

Depth describes selected paths, not complete files or subsystems. A finding-free
row does not mean that area is safe, correct, or fully tested.

| Area | Review depth | Evidence covered | Remaining gap |
|---|---|---|---|
| Firewall generation/reconcile | Deep targeted | A01-A03, native IPv4 namespace traffic, nftables inspection, offline validator and order fixture | IPv6/full matrix, second physical host, complete live replacement/retry |
| Setup backend/proxy boundary | Deep targeted | A04-A06, handler, unit, proxy routes | Local sandbox reachability and live HTTP resource behavior |
| Backup preparation/cleanup | Deep targeted | A07-A08, isolated failures, 27 existing tests | Real database failures, ZFS cleanup, independent restore |
| Update and guarded apply | Deep targeted paths | A09, A11, direct dispatch and cancellation | Full updater audit, VM timer interleavings and rollback drills |
| Caddy selection and route validation | Deep targeted | A10 transient native unit, A20 native unused/imported snippet comparison | Repeated genuine lock transitions, full appliance import/route checks |
| Effective state/generations/parser | Deep targeted paths | A12, A16, A17, A19; fallback, cycle/regex probes, publication control flow | Full compiler, concurrent activation, filesystem fault behavior, retention stress |
| Setup UX and frontend delivery | Deep targeted paths | A13-A14, A22, source/build comparison and render warnings | Browser reconnect, axe/keyboard/screen-reader checks, bundled runtime behavior |
| State import/restore | Partial | A15, extraction/authentication ordering | Complete restore logic and filesystem semantics |
| Identity, secrets, projections, runtime libraries | Partial/contextual | Authority docs and intersecting setup/control paths | Full authorization, reconciliation, secret lifecycle review |
| Developer validation and dependencies | Targeted/partial | A18/A21, 1,314 Python passes with exclusions, 70 Node passes, npm audits, PARTIAL preflight | Excluded suites, discovery timeout diagnosis, coverage, Nix/OCI advisories, supply-chain provenance |
| Retained disposable test guest | Targeted native follow-up | Successful 59-derivation build, attempted switch with exit 4, tool/kernel fixtures | Resolve failed units, clean installer qualification, full QEMU and encrypted recovery drills |
| GPU, libvirt PCI passthrough, all Nix profiles | Not exhaustively reviewed | No completeness claim | Specialist review and relevant hardware/native tests |
| Actual setup hardware and production installation | Not exercised | No production deployment or test | Destructive setup qualification, hardware recovery and production-specific evidence |

Existing limitations remain in [known-risks.md](known-risks.md), rather than being
recounted as new findings: no command-only fresh setup path, generic state-bundle
ACL/xattr limitations, the need for independent backup, and network-restore deadman gaps.
Preserve the documented out-of-band recovery plane throughout follow-up work.

## Next steps and closure criteria

- All findings remain open for follow-up; this documentation-only audit implements no remediation and authorizes no production change.
- Assign owners and acceptance evidence before scheduling focused remediation changes. Add behavioral tests before changing privileged behavior; do not change the documented invariant authorities.
- Address A01-A03 together as the first native-firewall qualification effort. Fixing activation order or priority alone must not enable A01's broad acceptance of unmatched traffic; require both successful activation and allowed/denied traffic tests before affected deployment.
- Next, coordinate A04-A06 as one setup trust/capability and resource-bound design, including A13's dependent reconnect behavior. Backend authorization, capability confidentiality/expiry, and request bounds need combined acceptance even though A05/A06 are P2.
- Prioritize recovery bookkeeping A07/A08 and publication safety A17 next, before unrelated usability work or refactoring. Complete the remaining P1 work, including A09/A10, before its next affected deployment; P2 follow-up may be scheduled separately where it is not a dependency of a P1 closure.
- Use the [testing guide](testing.md) and VM wrappers; do not infer appliance behavior from the non-Nix host.
- Preserve the distinction between passing isolated suites, PARTIAL preflight, targeted native fixtures, and the guest's failed activation. Diagnose the guest faults before clean qualification; passing unit tests do not replace it.
- For each closure, record the fix revision, reproduced failure, passing regression, native evidence where required, and remaining limitations.
- Maintain existing operational limitations in [known-risks.md](known-risks.md), without duplicating that register here. Future breaking changes need no compatibility migrations, but still require backup, rollback, and out-of-band recovery evidence.
- Evaluate simplification candidates only when they remove a concrete maintenance burden without adding another authority.
- Follow the [release qualification checklist](release-checklist.md) before any install-ready claim. This report does not certify that all issues were found.
