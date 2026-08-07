# Combined Alpha 18 and Alpha 20 review remediation register

This is the single deduplicated implementation register for `nixos-nas-project-review-alpha18.md` and `nixos-nas-project-review-alpha20.md`. Each source finding ID appears exactly once. Repeated findings are merged into one authority-level remediation instead of being tracked as separate fixes.

Status describes implementation in this source tree. It does not substitute for the external Nix evaluation, compiled Cockpit bundle, QEMU, official-ISO, or hardware evidence listed in `external-validation.md`.

## Deduplicated findings

| Deduplicated issue | Source findings | Status | Implementation and evidence |
|---|---|---|---|
| AI gate credential staging | `A18:C-01` | Implemented | Secret activation stages and installs the gate API key before enabling the AI gate; activation tests cover enabled and disabled AI paths. |
| Feature-gate lock ownership | `A18:C-02`, `A20:C01` | Implemented; VM identity proof required | The shared lock lives in the gate-owned control directory and all gate/CLI/reaper transitions use the same coordinator. |
| Pre-swap secret rollback | `A18:C-03` | Implemented | Secret activation is phase-aware and cannot stop a previously working protected stack before the swap boundary; rollback restart failures are surfaced. |
| Exact release input tree | `A18:C-04`, `A20:C03` | Implemented | Release assembly uses an exact reviewed regular-file set in an isolated staging tree, rejects links/special files and extras, and never walks ignored checkout content. |
| State-manifest semantics | `A18:C-05`, `A20:C04` | Implemented | Validation enforces the closed schema, exact authority and payload sets, recomputed completeness, profile digest, signature, and compatibility contract. |
| Installable Cockpit artifact contract | `A20:C02` | Implemented in complete-release path | A complete release requires the retained npm lock plus the compiled distribution; source-only archives use an unmistakable name and are rejected by Nix packaging. |
| Cockpit output integrity and asset closure | `A20:C05`, `A20:H38` | Implemented | Build metadata hashes every emitted file and verifies all CSS-referenced assets; Nix installs only the verified distribution. |
| Automatic first-start lifetime and readiness refresh | `A18:H-15`, `A20:C06`, `A20:H01` | Implemented; VM lifecycle proof added | The enabled oneshot remains active, republishes status on restart, and every overview recomputes readiness instead of trusting a boot cache. |
| First-start admission and appliance-wide exclusion | `A20:C07`, `A20:H15`, `A20:M14`, `A18:M-22` | Implemented | The Cockpit request atomically reserves conflict classes; the systemd child claims the exact reservation and then holds the appliance lock for the transaction. |
| Destructive plan binding | `A20:C08` | Implemented | The reviewed normalized plan is SHA-256 bound, including storage, features, setup controls, and keyed authenticators for actual password values. |
| Exact feature rollback | `A18:H-01`, `A20:H11` | Implemented | Feature transactions snapshot observed unit activity and durable policy, then restore both on failure, including on-demand runtime state. |
| Gate mutation serialization | `A18:H-02`, `A20:H12` | Implemented | Wake, reap, gate requests, and CLI policy changes retain the same cross-process lock across the full mutation. |
| Bounded feature commands and live health | `A18:H-03`, `A18:H-04`, `A20:H13`, `A20:H14` | Implemented | System commands have deadlines/output bounds and cached wake results are revalidated against backend health before authorization. |
| Optional-state absence semantics | `A18:H-05`, `A20:H16` | Implemented | Missing optional authorities are explicit manifest entries, participate in diff, and require an explicit restore-absence policy. |
| Profile-exact state authority registry | `A18:H-06`, `A18:H-14`, `A20:H17` | Implemented | The generated registry follows enabled profiles and covers identity, applications, network/firewall, operations, and optional feature authorities. |
| Point-in-time export boundary | `A18:H-07`, `A20:H18` | Implemented with documented boundary | Known writers are quiesced and one snapshot epoch is recorded; the remaining non-atomic cross-application boundary is explicit in known risks. |
| Canonical transactional restore | `A18:H-08`, `A18:H-09`, `A18:H-10`, `A20:H19`, `A20:H20`, `A20:H21` | Implemented | Restore uses code-owned order, a global operation lock, exact unit-state capture, checked stop/reload/restart, rollback-first application, and a durable journal. |
| Bundle trust, retention, and database drift | `A18:H-11`, `A18:H-12`, `A18:H-13`, `A20:H22`, `A20:H23`, `A20:H24` | Implemented | Bundles are appliance-authenticated, rollback retention is bounded, and normalized logical database dumps produce meaningful comparison digests. |
| Archive-local restore policy | `A18:M-06`, `A18:M-07`, `A18:M-08`, `A18:M-09`, `A20:H25`, `A20:H26`, `A20:H27`, `A20:H28` | Implemented | Archive ownership/modes are ignored, local policy is enforced, free space is checked, rollback roots are repaired, and producer/application compatibility is validated. |
| First-run journal correctness | `A18:H-16`, `A18:H-17`, `A18:H-18`, `A20:H02`, `A20:H03`, `A20:H04` | Implemented | Manual recovery requires acknowledgment, completed steps are postcondition-checked, final state is durable before completion, and journal lifecycle has fault tests. |
| Password-aware resume fingerprint | `A18:H-19`, `A20:H05` | Implemented | The aggregate fingerprint includes keyed authenticators of password values without storing reusable password hashes or plaintext. |
| Setup completion authority | `A20:H06` | Implemented | Complete and complete-unverified states are tied to the current normalized plan and live authority probes; drift and configuration changes are distinct states. |
| Journal UI and detached setup job | `A18:M-21`, `A20:H07`, `A20:H08` | Implemented | Cockpit displays authoritative journal/job state, launches a dedicated systemd job, reads bounded private inputs through no-follow descriptors with exact single-line secret validation, removes runtime inputs on every path, and follows progress after browser reconnect. |
| Fail-closed setup controls | `A20:H09`, `A20:H10` | Implemented | Recovery bypass is rejected before privileged work, preflight skipping is not a normal UI path, and missing/invalid setup data cannot be interpreted as completion. |
| Authentik saga containment | `A18:H-20` | Implemented with explicit non-compensatable boundary | Prepared plans, read-back verification, sanitized journals, and deliberate password replay make structural reconciliation safe; accepted password changes remain explicitly non-reversible. |
| Detached update and migration rollback | `A18:H-21`, `A18:H-22`, `A18:H-23`, `A18:H-24`, `A20:H29`, `A20:H30`, `A20:H31`, `A20:H32`, `A20:H33`, `A20:M06` | Implemented; remote-host proof remains external | Updates build in a detached candidate, snapshot mutable state, require complete preflight, verify local manageability, promote only after success, and fail loudly when rollback is incomplete. |
| Exact firewall ownership | `A18:H-25`, `A18:H-26`, `A18:H-27`, `A20:H34`, `A20:H35` | Implemented | One generated NAS zone replaces additive mutation; no default-zone bootstrap exposure occurs, and the guard checks interface/profile/rules plus stale exposure. |
| Standalone default module | `A18:H-28`, `A20:H36` | Implemented; Nix evaluation proof required | The default flake module composes required core, AI, CopyParty module, and overlay inputs instead of exporting an incomplete fragment. |
| Atomic exact release publication | `A18:H-29`, `A18:H-30`, `A18:H-31`, `A20:M01`, `A20:M02`, `A20:M03` | Implemented | Release files are assembled outside the checkout, verified against an exact manifest, and published as one atomic directory set. |
| Single Cockpit dependency graph | `A20:H37` | Implemented in CI | One job resolves/builds the lock and bundle once; all downstream evaluation, build, VM, installer, and release work consumes those exact bytes. |
| Secret transaction hygiene | `A18:M-01`, `A18:M-02`, `A18:M-03`, `A18:M-04` | Implemented | Staging is runtime-memory-backed, transaction names are unique, rollback restart errors are checked, and raw secret serialization avoids line-format ambiguity. |
| Setup subprocess deadlines | `A18:M-05` | Implemented | Setup adapters enforce timeout and output limits; timeout, truncation, nonzero status, and privilege-expiry paths are behaviorally tested. |
| Profile composition boundaries | `A18:M-10`, `A20:M20` | Implemented to authority boundary | Profiles remain composition presets, but optional services now drive exact state, feature, endpoint, backup, and validation registries rather than a fixed base stack. |
| Single sources of truth and drift report | `A18:M-11`, `A18:M-32`, `A20:M23` | Implemented | Generated registries own service/state definitions and nas-doctor reports setup, authority, feature, migration, and active-operation drift in one contract. |
| Narrow QEMU/release source inputs | `A18:M-12`, `A18:M-13`, `A20:M04`, `A20:M05` | Implemented | VM and installer inputs come from the exact staged release/file set rather than ignored/untracked checkout content or a broad host share. |
| Unambiguous source-only artifacts | `A18:M-14`, `A20:M07` | Implemented | Source packages use the concise `Nix OS NAS <display-version> source.zip` filename, while the canonical archive root and provenance retain the explicit source-only/unverified state; complete packaging still refuses absent Cockpit/Nix/QEMU evidence. |
| Behavioral coverage and fault tests | `A18:M-15`, `A18:M-16`, `A20:M10`, `A20:M12` | Implemented and raised | Coverage gates were not lowered; privileged adapters, journals, reservations, restore, setup drift, and state schemas have behavioral failure-path tests. |
| Rendered React and systemd lifecycle tests | `A20:M11`, `A20:M13` | Implemented in QEMU path | Selenium drives the compiled NAS page through refresh and a PatternFly confirmation modal, while the VM verifies first-start RemainAfterExit and restart behavior. |
| Release evidence enforcement | `A18:M-17`, `A20:M21`, `A20:M22` | Implemented in complete-release path | Main runs native VM and official-ISO install/reboot jobs; commit-matched evidence is required before complete release packaging. |
| Control-plane decomposition and typed contracts | `A18:M-18`, `A20:M17`, `A20:M18` | Materially implemented | Feature, identity, setup schema, operation lock/journal, doctor, migration, and state domains are separate modules with dataclasses/closed JSON contracts at persistence and privilege boundaries. |
| Shell-wrapper reduction | `A18:M-19` | Implemented where authority exists | Cockpit dispatches fixed systemd units and Python adapters; remaining shell is limited to Nix-generated service glue, release tooling, and live/VM orchestration. |
| mkForce containment | `A18:M-20` | Implemented | Only one documented unit-umask compatibility override remains and structure validation prevents unreviewed growth. |
| Concurrent Cockpit overview | `A18:M-23`, `A20:M16` | Implemented | Read-only probes execute concurrently with individual deadlines and partial error reporting. |
| Explicit direct-Cockpit host policy | `A18:M-24`, `A18:M-31`, `A20:M15` | Implemented | Reusable modules default direct LAN recovery and mutable local passwords off; the appliance profile must opt in explicitly. |
| Starter Kit React/PatternFly migration | `A18:M-25` | Implemented | The custom package uses React 18, PatternFly 6, source-to-dist esbuild/Sass structure, exact output verification, and no legacy DOM renderer. |
| Strict Cockpit CSP | `A18:M-26` | Implemented | The package manifest no longer permits unsafe inline script/style execution. |
| Truthful update naming | `A18:M-27` | Implemented | The non-deploying action and unit are named update-preview and describe candidate validation rather than a lightweight check. |
| Release provenance and deterministic modes | `A18:M-28`, `A20:M08`, `A20:M09` | Implemented | Provenance records revision, builder, validation/evidence, and source classification; archive modes are canonical instead of inherited from the workstation. |
| Non-regular release input rejection | `A18:M-29` | Implemented | Release assembly rejects symlinks, devices, sockets, FIFOs, and every unreviewed extra before archiving. |
| Explicit mutable-state migrations | `A18:M-30`, `A20:M19` | Implemented | nas-migrate-state plans known schemas, refuses unknown formats, locks globally, backs up first, and atomically applies only confirmed migrations; the obsolete firewall version marker was removed. |
| Known-risk accuracy | `A20:M24` | Implemented | The risk matrix now describes only remaining non-atomic or externally provable boundaries and no longer claims first-start is browser-synchronous. |

## Remaining proof boundaries

- The current local artifact is source-only because this environment cannot resolve the complete npm dependency graph or execute Nix/QEMU. The complete-release path requires the retained Cockpit lock/distribution and commit-matched VM and installer evidence.
- Authentik password mutation cannot be automatically compensated after the remote authority accepts it; recovery therefore converges structural state and deliberately rotates uncertain passwords.
- Quiesced application export is not a single atomic snapshot across PostgreSQL and every external application. The bundle records the boundary and restore remains rollback-first.
- Local route, firewall, listener, and TLS checks do not prove second-host reachability; out-of-band recovery remains required for deployment.

## Machine-checkable deduplication

`tests/test_combined_review_register.py` verifies that every Alpha 18 and Alpha 20 finding identifier appears exactly once in this document and that retired contradictory risk wording does not return.
