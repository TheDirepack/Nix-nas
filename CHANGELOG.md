# Changelog

## 2.2.0-alpha.8 — 2026-08-10

- Make KeePassXC secret existence checks fail closed: exact `ls --flatten` membership distinguishes an absent entry from a database/listing failure, and secret-group creation errors are no longer silently ignored.
- Bound Authentik and Hugging Face credential setters at 4096 characters and revalidate generated Grafana, NUT Web GUI, and ZFS machine keys as exact 64-hex secrets before runtime staging.
- Add adversarial secret-transaction coverage for missing/symlinked ready markers, accidental success without commit, irreversible commit-cleanup failure, and post-move ready-marker substitution.
- Add fake-KeePass behavioral tests proving lookup failures cannot fall through into add/edit mutations and wire the new security regressions into the dedicated security runner.
- Synchronize release metadata to `2.2.0-alpha.8`; this remains a source-only development artifact until the exact Nix, QEMU, installer, and browser qualification gates complete.

## 2.2.0-alpha.7 — 2026-08-08

- Fix Pi network namespace construction (remove `mount --bind /proc/self/ns/net` that overwrote `/run/netns/pi`), provide DNS inside the namespace via `/etc/netns/pi/resolv.conf` pointing at `10.200.1.1` and `systemd-resolved` `DNSStubListenerExtra`, and clean up teardown without `umount` of the ip-managed namespace.
- Harden coding-agent authorization to require Authentik-validated identity JSON (`NAS_AUTHENTICATED_IDENTITY_JSON` from the portal gate, checked via `capability_allowed("coding")`), remove the unconditional `root`/`SUDO_USER` bypass, and keep Linux group sync as an opt-in insecure fallback (`NAS_CODING_INSECURE_UID_AUTH=1`) for terminal `sudo` callers. Add the `coding` capability to the development fallback registry so `nas_admin` bypass and `nas_allow_coding` checks work without a registry file in tests.
- Preserve the provider credential lifecycle hardening from the in-progress `nas_ai_config.py` work (explicit `PRESENT`/`ABSENT`/`UNKNOWN` credential probe and atomic env-file updates).
- Synchronize `VERSION`, `README`, `flake.nix`, and `cockpit/package.json` to `2.2.0-alpha.7` per `docs/development/artifact-naming.md`.

## 2.2.0-alpha.6 — 2026-08-07

- Harden the Alpha.5 Pi coding-agent and runtime provider subsystem against the 2.2.5 review's critical findings: align Pi launcher with the pinned 0.75.4 interface, confine coding sessions to `nas-ai-coding.slice`/`nas-ai-coding-sessions.target` with loopback-only egress and `InaccessiblePaths` for host secrets, make provider ID mapping injective (hyphen-only `^[a-z][a-z0-9-]{0,47}$`), and make provider credential + endpoint updates one atomic transaction with `NAS_SKIP_LLAMA_SWAP_RESTART` deferred restart and full rollback of Keepass, env, and config on failure.
- Enforce provider `apiKey` must equal derived `LLAMA_SWAP_PEER_*_API_KEY` and reject reserved `LLAMA_SWAP_API_KEY`/`LLAMA_SWAP_CODING_API_KEY`, stage provider keys via private `/run/nas-secrets` temp, block all managed llama.cpp flags including `--ctx-size`/`-c`, validate selector/peer namespace collisions, and validate candidate config with the pinned llama-swap parser before commit with parent-directory fsync.
- Move coding-agent lifecycle to an explicit `nas-ai-coding-sessions.target`, bind transient `nas-ai-coding-session-*.service` with `PartOf/BindsTo` and `RuntimeMaxSec=14400`, validate existing workspace roots are traversable/writable by `nas-code-agent` with ACL guidance, and document write-only vs read confinement.
- Register `/var/lib/nas-code-agent` as an optional state authority, track transient slice memory instead of the preparatory oneshot, distinguish `credentialReferenceConfigured`/`credentialStaged` in `nas_ai_config.public_view`, journal provider deletion, and reuse the secret-transaction helpers.
- Preserve artifact naming: canonical `2.2.0-alpha.6` packages as `Nix OS NAS 2.2.6 source.zip`.

## 2.2.0-alpha.5 — 2026-08-07

- Fix the Alpha.4 browser-authorization, Cockpit operation-ownership, release-provenance, and virtualization feature-lifecycle regressions found by the 2.2.4 review.
- Continue state/validation hardening around secure browser secret files, curl credential encoding, NetworkManager runtime profile reload, and VM lifecycle qualification.
- Begin the Pi Coding Agent integration as an optional, on-demand child of the existing llama-swap AI runtime; llama-swap remains the single provider/model authority and Pi receives no upstream provider credentials. Reuse the pinned nixpkgs `pi-coding-agent`, which resolves to the maintained `earendil-works/pi` source at this release pin, instead of installing Pi from npm at runtime.
- Add Cockpit-managed runtime AI configuration for NAS-managed local GGUF/llama.cpp backends plus llama-swap remote/cloud peers, model allowlists, KeePass-backed provider credentials, peer timeouts/request filters, and coding-role selectors/fallback policy. Provider secrets are sent only over stdin to the secret tool and are stored outside YAML; local launcher arguments are validated as argv and manual llama-swap model definitions remain read-only.
- Reuse llama-swap's upstream `peers` and selector mechanisms for OpenRouter and generic OpenAI-compatible services instead of introducing LiteLLM or making Open WebUI a second provider/router authority; wire the existing `nas.ai.llamaSwap.globalTtl` policy into generated llama-swap configuration and expose lifecycle tuning in Cockpit.
- Preserve the human-facing artifact convention: canonical `2.2.0-alpha.5` packages as `Nix OS NAS 2.2.5 source.zip`.
- This remains source-only/unverified until exact Nix evaluation/build, native/encrypted VM tests, installer/reboot/rollback, browser authorization, and hardware recovery qualification run on this revision.

## 2.2.0-alpha.4 — 2026-08-07

- Standardized human-facing package names as `Nix OS NAS <display-version> source.zip` / `release.zip`; `2.2.0-alpha.4` is displayed as `2.2.4` in artifact filenames while `VERSION` and provenance remain canonical. Packaging-only rebuilds do not increment the software version.

- Fixed the Alpha.3 release-blocking nested state coordination bug by honoring the validator's raise-on-failure/`None`-on-success contract for coordinated export and restore.
- Moved Cockpit mutation ownership to the actual lock-owning workers for identity, Syncthing, updates, protected restart, and feature changes, eliminating parent/child coordinator self-conflicts.
- Made state restore profile-aware and service-order safe: NetworkManager/firewalld are restored to their prior active state before reload, and generated restore-unit policy now follows enabled networking/firewall features.
- Corrected KeePass disaster-recovery ownership to the configured administrator and `users` group while retaining mode `0600`.
- Made update rollback phase-aware, reversible after source promotion, and explicit about ephemeral candidate recovery evidence.
- Hardened common privileged subprocess execution with bounded streaming output retention and process-group timeout termination; setup now uses the same runner.
- Removed plaintext ntfy password hashing from argv, moved live-validation web credentials to stdin-backed curl configs/password files, and hardened operation-root fallback ownership.
- Added exact state source provenance and removed duplicate state-diff filesystem hashing.
- Began the Alpha.4 memory pass with a VictoriaMetrics cache budget/cgroup pressure target, 60-second baseline telemetry, ntfy SQLite history, balanced Syncthing Go/resource tuning, shorter on-demand idle windows, and a shorter llama-swap model TTL.
- Added a named ZFS-backed libvirt `nas-zfs` storage pool at the configured VM path; Cockpit/default-pool selection still requires installed-system qualification.
- This remains source-only/unverified development artifact until exact Nix evaluation/build, native/encrypted VM tests, installer/reboot/rollback, browser authorization, and hardware recovery qualification run on this revision.

## 2.2.0-alpha.3 — 2026-08-07

- Replaced the caller-controlled `NAS_OPERATION_COORDINATED=1` bypass with a verifiable live ancestor-operation token tied to PID/boot/start identity and the PID that actually owns every claimed Linux `flock`.
- Added explicit state-authority restore policy metadata (owner, group, root mode, strategy) so restore to an empty host does not guess `root:root`.
- Made state subprocess timeouts terminate the entire child process group before rollback/recovery continues.
- Hardened operation-root fallback mode, Authentik retry pacing, common command timeouts, alert-router corrupt-state handling, and feature-probe SSRF regression coverage.
- Added Cockpit package-version consistency to the central version contract and synchronized the Cockpit package metadata.
- Expanded inline transaction/timeout documentation and regression coverage for the Alpha.2 review findings.
- Removed the separate state-operation lock bypass, moved reservation expiry to monotonic time, added first-start result retention and corrupt alert-state quarantine, and made `nas-doctor --deep` verify coordinator runtime policy.
- Applied and verified Ruff 0.16.1 formatting across the Python tree; both `ruff format --check` and `ruff check` now pass, Cockpit package metadata is part of the version contract, and release provenance records the real build timestamp plus available static-tool versions.

## 2.2.0-alpha.2 — 2026-08-07

- Hardened the shared appliance operation coordinator: `appliance` is now globally exclusive, lock files are atomically created under a dedicated setgid `nas-operations` runtime directory, PID metadata is bound to boot/process identity, and direct update/secret mutations enter through the same coordinator.
- Fixed Cockpit first-start transient-unit environment propagation and updated both VM first-run paths to confirm the server-normalized plan digest, including stale-digest rejection.
- Hardened state export/restore with private `/run/nas-state` staging, export-side restore-limit enforcement, heterogeneous local ownership/mode preservation, safer partial-quiesce recovery, single-quiesce rollback capture, and profile-aware quiesce units.
- Fixed SMART boolean ingestion before VictoriaMetrics and added representative line-protocol metric fixtures covering every current alert/dashboard metric family.
- Hardened Authentik read-side outage behavior with bounded exponential retry/jitter while keeping mutations non-replayed; expanded Syncthing malformed/boundary/control-character tests.
- Hardened feature-gate, alert-router, structured-logging, setup-resume, update-snapshot retention, and corrupt-journal behavior; documented reduced at-least-once alert-router semantics and secret transaction phases.
- Added `ruff format --check`, made the aggregate coverage floor explicit in CI, and split slow release/tooling integration tests from the fast unit loop.
- Hardened test orchestration itself: coverage cleanup no longer deletes `.coveragerc`, bounded runners terminate whole subprocess groups on timeout, and state-command output is drained continuously with bounded retained output instead of buffering an unbounded child stream in memory.
- This remains source-only and unverified until the exact Cockpit dependency artifact and complete Nix/QEMU/browser/installer/hardware evidence are retained for this revision.

## 2.2.0-alpha.1 — 2026-08-06

- Started the 2.2 alpha line with a verification-focused architecture covering deterministic boundary fuzzing, property invariants, adversarial protocol inputs, source and installed executable fuzzing, browser/layout checks, package-consumer checks, and broader install/upgrade/failure paths.
- Made the executable test inventory authoritative for all 47 currently discovered NAS-owned installed and maintainer executables; new commands must declare focused tests and strategy-appropriate fuzzing before validation passes.
- Hardened trusted identity-group parsing and the on-demand authorization endpoint against embedded controls, duplicate query fields, malformed scopes, oversized/invalid feature identifiers, and ambiguous bad-input/service-failure responses discovered by adversarial testing.
- Replaced the remaining CopyParty SQLite CLI backup construction with Python's SQLite backup API and added regressions that forbid dynamic `.backup`/`.restore` meta-command paths.
- Added security scanning contracts for command/code injection, SQL construction, unsafe deserialization, insecure temporary files, archive extraction, shell format strings, generated-shell and SQLite meta-command injection, unsafe HTML/JavaScript sinks, archive traversal, secret leakage, and other privileged-boundary regressions; CI also runs Semgrep, Bandit, and npm high-severity audit checks.
- Added `test-matrix.py` as one bounded source/security/fuzz/browser/native/installer orchestration entry point with JSON evidence and fail-closed `--require-all` release mode.
- Expanded browser tests across Chromium, Firefox, WebKit, small-phone through desktop viewports, 200% font scaling, hostile oversized content, keyboard focus, accessibility checks, and real installed Cockpit/Authentik authorization/rendering.
- Expanded installation qualification to a guarded packaged-source round trip, fresh official-ISO installation, repeated `nixos-install`, full installed-system adversarial testing, `nixos-rebuild dry-activate`/`test`/`switch`, and a second boot of the switched generation with persistence checks.
- Added explicit branch-coverage regression floors for every control-plane service module, including alert routing, diagnostics, logging, migration, and operation locking.
- Added reusable-module/profile evaluation targets plus negative Nix fixtures that must reject unsafe trusted-interface, ZFS dataset, TFTP, replication, and firewall configurations for the expected assertion instead of merely failing somewhere during evaluation.
- Made isolated Python test execution bounded and parallelizable per test file; the local source suite accounts for 322 tests (321 passing here and the Hypothesis-only property tier skipped because Hypothesis is unavailable), while CI supplies Hypothesis from the pinned Nix test shell.
- Tightened the dynamic web-security harness so ZAP requires immutable images, local/private targets by default, explicit authorization for active scans, fatal warnings by default, and a hard outer process timeout; added regressions for these safety boundaries.
- Expanded shared defensive-plumbing tests for subprocess timeouts/truncation, malformed systemd state, capability-registry corruption, JSON fallback, and feature dependency cycles; every packaged service module now clears its declared branch-coverage floor.
- Hardened the packaged-source round trip after testing exposed Python ZIP extraction dropping executable bits: release assembly now verifies stored Unix modes, and CI validates members before extracting with a mode-preserving consumer.
- This remains source-only and unverified until the exact Cockpit dependency bundle and complete Nix/QEMU/browser/installer execution evidence are retained for this commit.

## 2.1.0-alpha.25 — 2026-08-06

- Reworked the operator documentation around common tasks, added a clearer manual landing page, split runtime account management out of first-start setup, and added contributor architecture/release-qualification guides.
- Polished the React/PatternFly Cockpit experience with clearer operator-facing section names, application labels, maintenance wording, and first-start terminology while keeping privileged decisions in the existing backend boundary.
- Simplified executable comments to local safety/compatibility constraints, refreshed component README files, and removed stale implementation-oriented wording from operator pages and CLI help.
- Improved `nas-doctor` human output with a concise check summary and inline remediation steps while preserving the machine-readable JSON contract.
- This remains a source-only development artifact until the exact Cockpit lock/distribution and NixOS/QEMU/installer/hardware qualification evidence are available.

## 2.1.0-alpha.24 — 2026-08-06

- Added a schema-backed capability and group registry shared by Nix exports, Caddy authorization, Python policy, setup data, Cockpit-facing metadata, documentation, and regression tests; unknown route capabilities now fail closed.
- Added bounded structured operation logging, a dedicated unprivileged VictoriaMetrics alert router, and initial privileged-service hardening documentation and assertions.
- Replaced the remaining Prometheus-family runtime stack with Telegraf direct ingestion into VictoriaMetrics, native VictoriaMetrics Grafana datasource provisioning, and vmalert notifications sent directly through the NAS router; removed Prometheus, its exporters, Alertmanager, the notification bridge, and the unused Authentik Prometheus listener.
- Consolidated Ruff and Pyright configuration in `pyproject.toml`, added non-root unit-test CI, made Cockpit CI reject a missing lockfile instead of resolving a floating graph, and fixed the Cockpit Scheduler backend-name mismatch.
- The local source suite passes 243 tests and Python/shell syntax checks. This artifact remains source-only and unverified because the supplied tree lacks `cockpit/package-lock.json` and compiled `cockpit/dist`, npm registry access was unavailable, and this environment cannot execute Nix, QEMU, or official-ISO qualification.

## 2.1.0-alpha.23 — 2026-08-06

- Merged and deduplicated the Alpha 18 and Alpha 20 audits into one remediation register and added executable regressions for every release-blocking and high-risk finding.
- Completed the Cockpit Starter Kit React/PatternFly Sass build contract and retained exact output hashing, asset closure checks, and one-lockfile CI reuse.
- Hardened operation coordination with atomic asynchronous reservations, exact reservation claims, reconnect-safe job results, and cleanup on every launch or child failure path.
- Bound setup resume to keyed password authenticators and read private systemd request/password files through bounded no-follow descriptors with exact single-line secret validation.
- Added state migrations, unified drift reporting, reusable-module host-policy controls, release provenance enforcement, and broader behavioral failure-path coverage without claiming unavailable Nix/QEMU evidence.
- This local artifact remains explicitly source-only and unverified until the pinned npm bundle and complete NixOS/QEMU/official-ISO gates run.

## 2.1.0-alpha.22 — 2026-08-06

- Added `nas-doctor`, a single machine-readable authority, setup, feature-policy, migration, and active-operation drift report with fail-closed severity and recovery guidance.
- Added `nas-migrate-state`, which plans registered schema upgrades, refuses unknown state formats, acquires appliance-wide conflict classes, creates private backups, and atomically applies migrations only after exact confirmation.
- Moved host-wide mutable PAM-password policy and direct Cockpit LAN recovery exposure behind explicit reusable-module options; the appliance profile opts in while imported modules remain fail-closed by default.
- Reworked CI so one job resolves the Cockpit dependency graph and builds one hashed PatternFly bundle; every Nix, closure, VM, and installer job consumes those exact lock/output bytes.
- Made the official-ISO install/reboot path run on every main-branch build and retain commit-bound QEMU and installer evidence for complete release packaging.
- Required complete releases to embed exact regular-file QEMU and official-installer evidence matching the packaged Git commit; provenance records hashes for each evidence file.
- Kept this local artifact source-only and unverified because the current environment cannot resolve the npm graph or execute Nix/QEMU/official-ISO validation.

## 2.1.0-alpha.21 — 2026-08-06

- Reconciled the Alpha 18 reliability review against the current React/PatternFly tree and replaced its remaining source-contract assurances with behavioral state, packaging, setup, operation-lock, and recovery tests.
- Made feature-policy persistence rollback restore the exact observed pre-change unit state; gate and reaper transitions now hold the cross-process generation lock through unit operations, enforce command deadlines, and revalidate cached service health.
- Reworked `nas-state` around a strict profile-aware authority registry, exact schema and payload-set validation, explicit absent-state semantics, canonical restore order, HMAC-signed manifests, database comparison digests, quiesced snapshot metadata, checked runtime reactivation, secure rollback retention, and space preflight.
- Made first-start execution bind to the server-normalized plan digest, revalidate completed stage postconditions, hard-stop manual-recovery journals, commit final state before journal completion, distinguish complete-but-unverified setup, and require explicit confirmation before repeating account password mutations during resume.
- Added shared cross-process conflict classes for first-start, identity, runtime, storage, update, network, secrets, and state operations; Cockpit publishes active jobs and disables incompatible PatternFly controls while backend locks are held.
- Made release and installer inputs use an exact reviewed regular-file set, reject ignored extras, symlinks, FIFOs, devices, and manifest omissions, stage outside the checkout, verify archive/manifest equivalence, and publish the release directory atomically.
- Replaced additive firewalld seeding with one generated owned zone, persistent NetworkManager zone assignment, exact rule validation, and checks for stale protected exposure on other active zones.
- Changed updates to build from a detached candidate worktree, capture mutable state before activation, verify interface addresses, routes, zone assignment, listeners, and trusted TLS routes, promote source only after a persistent switch, and persist manual-recovery evidence when rollback fails.
- Kept this artifact source-only: the validation environment still lacks Nix evaluation/build/QEMU evidence and cannot fetch the npm lock graph needed to compile the React/PatternFly distribution.

## 2.1.0-alpha.20 — 2026-08-06

- Replaced the transitional hand-written Cockpit DOM interface with a React 18 and PatternFly 6 application based on Cockpit Starter Kit conventions.
- Migrated first-start, unlock, feature policy, identity capability, memory, ZFS, service, timer, link, and allow-listed operation views to PatternFly components and React state.
- Removed runtime `innerHTML`, selector-driven event wiring, browser `confirm`, custom status-pill rendering, and the dependency-free source-copy build.
- Preserved stdin-only KeePassXC password delivery and moved destructive and privileged confirmations into explicit PatternFly forms and modals.
- Added an esbuild/Sass production bundle with source-hash metadata, stale-distribution validation, recursive source documentation, and Nix packaging that refuses an absent or incomplete React bundle.
- Marked this archive source-only because npm dependencies and the compiled browser distribution could not be fetched in the validation environment; complete release validation remains mandatory before installation.

## 2.1.0-alpha.19 — 2026-08-06

- Added `nas-first-start.service`, enabled by default, to publish safe first-boot setup state before Cockpit starts; the NAS page now presents missing, invalid, ready, and complete states and runs the resumable setup workflow with stdin-only KeePassXC input.
- Kept destructive storage creation explicitly operator-confirmed: Cockpit displays the exact root-owned pool plan and the backend repeats only the server-derived stable device paths to the guarded setup CLI.
- Fixed the remaining secret-activation outage path by making rollback phase-aware before the directory swap, checking protected-stack restart failures, staging exclusively under runtime tmpfs, and using unique transaction directories.
- Added the missing AI gate credential to secret staging, corrected the locked-boot drill to use the supported lock command, validated the Caddy trust chain, and made destructive live drills clean up through traps.
- Moved the custom Cockpit package to a Starter-Kit-compatible `src/` to reproducible `dist/` build, removed the unsafe inline-script policy, installed only verified build output, and added direct first-run transport coverage.
- Added one-transaction feature `set-many`, generation-journaled and read-back-verified Syncthing reconciliation with symlink-safe directory handling, parent-directory fsync for identity state, bounded subprocess output, and a less destructive explanatory-comment policy.
- Restored a current risk register and recovery matrix, corrected release packaging to include the Cockpit `dist/` payload, and documented the external NixOS/QEMU/live evidence still required before install-ready designation.

## 2.1.0-alpha.18 — 2026-08-06

- Reconciled the Alpha.14 architecture review against the current Alpha.17 tree and fixed the still-valid evaluation, transaction, authorization, backup, firewall, update, packaging, and release-evidence findings.
- Made feature start and state changes rollback-safe across partial unit starts and durable-state failures; added explicit healthy, degraded, failed, expected-resident, and observed-active reporting.
- Bounded and deprivileged the on-demand gate, required the llama-swap API key before AI wake, replaced client-visible backend diagnostics with correlation IDs, and generated a unit-scoped polkit allowlist.
- Added resumable first-run and account-operation journals plus a scoped Authentik automation service account/token for routine reconciliation after bootstrap.
- Packaged the Python control plane as one application with console entry points and committed closed schemas for setup, account, feature, service-registry, and state-bundle inputs.
- Added `nas-state export`, `validate`, `diff`, and guarded rollback-first `restore` for mutable appliance authorities, including sensitive-state opt-in and safe archive extraction.
- Added explicit appliance profiles, a generated service/endpoint registry, machine-checked `mkForce` policy, direct flake module exports, and x86_64-only release claims until AArch64 has complete build/test evidence.
- Moved backup staging and isolated restore verification to disk-backed scratch space, added PostgreSQL/SQLite/XML recovery checks, required explicit same-pool rollback-only opt-in, and strengthened failed-update persistent-profile rollback.
- Made preflight distinguish partial from complete evidence, added branch-coverage floors, fixed CI runner/concurrency scope, and made release publication atomic across archive, checksum, manifest, and provenance.

## 2.1.0-alpha.17 — 2026-08-06

- Reorganized the centralized development backlog and removed `docs/development/backlog.md`; durable deployment and immutable-dependency boundaries now live in focused development documents, while current unresolved risks remain separately tracked.
- Split feature policy, identity modeling, and setup schema/secret handling into `nas_feature_model.py`, `nas_identity_model.py`, and `nas_setup_config.py` while preserving existing command entry points.
- Extracted secret-tree activation into a transaction library with BATS success, rollback, partial-stage, inactive-target, and signal-interruption fault coverage.
- Expanded the installed-browser authorization matrix to cover every `nas_allow_*` capability, a no-grants baseline account, administrator-only global Syncthing access, and the ordinary-user Syncthing settings route.
- Replaced checklist-only live validation with executable locked-boot, CopyParty/WebDAV, Syncoid restore, Restic exact-snapshot restore, Authentik/browser, and observability drills.
- Added dependency policy for the reviewed Copyparty input and the optional HuggingFaceModelDownloader artifact so nested locks and unverified Go hashes are never hand-edited or faked.
- Added completion contracts that prevent the retired backlog, monolithic service policy blocks, missing transaction tests, or incomplete browser/live validation surfaces from returning.

## 2.1.0-alpha.16 — 2026-08-06

- Removed narrative, historical, section-banner, and self-explanatory comments from Python, Nix, shell, tests, and generated configuration.
- Reduced explanatory code-comment lines from 320 to 30 while retaining concise security, destructive-operation, compatibility, and generated-state constraints.
- Moved installation choices, option behavior, and ShellCheck suppression rationale into operator/development documentation.
- Replaced contract tests that depended on comment wording with behavioral source-contract assertions.
- Added comment-policy tests that reject long comment blocks, source-level backlog markers, review history, and Python section comments.

## 2.1.0-alpha.15 — 2026-08-06

- Reorganized documentation into operator, development, and concise history/backlog surfaces.
- Added `AGENTS.md` as the required compact handoff and reading order for coding agents.
- Removed superseded audit transcripts and release-by-release implementation essays from the active tree after preserving their durable decisions in `docs/development/history.md`.
- Split the monolithic architecture contract test into identity, operations, and tooling suites.
- Split documentation/Cockpit packaging out of `account-tools.nix` into `documentation-tools.nix`, leaving account/runtime packaging focused.
- Replaced duplicated shell grep contracts with `validate-structure.py` and executable Python contract tests.
- Reduced `preflight.sh` to a small validation orchestrator and added in-memory Python syntax validation.
- Corrected generated documentation to reference `zfs-tools.nix` instead of the nonexistent `storage-tools.nix`.

## 2.1.0-alpha.14 — 2026-08-06

- Split the NAS internal context into primitive/shared values, the runtime
  feature catalog, and Caddy helpers; removed the misleading MFA alias and made
  duplicate internal exports fail Nix evaluation instead of silently shadowing.
- Added a committed JSON Schema contract for the Nix-generated feature catalog
  and made the Python controller reject unknown catalog, probe, and memory
  fields against that contract.
- Reworked feature application/status paths to reuse one graph calculation,
  batch systemd state and memory reads, use typed missing-file errors, and share
  subprocess parsing with the Cockpit backend.
- Replaced release-specific preflight assertions and embedded alpha-review
  documents with durable repository-data validation and stable operator docs.
- Changed the administrator password-hash option from an empty-string sentinel
  to a nullable value, moved the local KeePass example to root-owned state, and
  validated hardware readiness from evaluated filesystem configuration.
- Narrowed ZFS option types, removed the one-value `platform.nix` indirection,
  corrected AI option text/style, and retained the upstream Copyparty lock graph
  unchanged for reproducible Nix verification.
- Expanded CI to run Ruff across all Python services/tests and Pyright over the
  privileged service code; added direct Cockpit action/argument tests and
  feature-schema/systemd batching regressions.
- Expanded direct Cockpit JavaScript coverage to all six shipped modules,
  including API transport, escaping/formatting, DOM rendering, initial refresh,
  action execution, and stdin-only unlock; the behavior suite now has 14 tests.
- Replaced committed test login material and SSH password authentication with a
  per-install ephemeral Ed25519 key injected only into the disposable QEMU
  guest; the test administrator password is locked.

## 2.1.0-alpha.13 — 2026-08-06

- Added `nas-setup` for complete idempotent first-run setup, secure account
  population, guarded storage creation, personal-directory provisioning,
  Syncthing reconciliation, feature application, and password-free status.
- Added Authentik account create/update/password/disable plans while preserving
  unrelated groups and optionally deactivating only setup-managed accounts.
  Runtime account apply preserves omitted fields so password-only changes do not
  strip existing capabilities; explicit `--group` values replace reserved groups.
- Added strict setup/account-plan schemas that reject unknown fields and
  malformed policy switches rather than silently using defaults.
- Added persistent JSON validation that rejects plaintext passwords and accepts
  only private, non-symlink, one-line password files opened exactly once.
- Added repeated exact-device confirmation, block-device/type validation,
  underlying-device deduplication, traversal rejection, and destructive opt-in
  for single, stripe, mirror, and RAIDZ1/2/3 pool setup with reviewed defaults.
- Made mutating setup commands preserve KDBX ownership by requiring the
  configured local administrator, maintaining sudo authorization during long
  runs, and using noninteractive privileged calls after the initial prompt.
- Reject account plans that would leave no enabled explicit `nas_admin`, while
  writing replacement administrators before demoting the only current
  administrator.
- Fixed the installed `nas-preflight` command to validate the configured source
  checkout through `NAS_CONFIG_DIR` instead of the immutable wrapper directory.
- Expanded both unencrypted and encrypted QEMU paths plus unit tests to exercise
  first-run, encrypted-dataset creation, and runtime account CLI behavior end to
  end.

## 2.1.0-alpha.12 — 2026-08-06

- Added two NixOS `runNixOSTest` QEMU checks: a full-stack appliance test and an encrypted-ZFS create/export/lock/unlock lifecycle test, plus an installable `nas-qemu` configuration.
- Added an official-ISO installer harness that verifies the NixOS checksum, installs to fresh qcow2 disks, reboots, and runs the complete guest suite.
- Installer reuse now preserves only a completed, source-matched OS installation and always recreates the ZFS data disk, eliminating stale configuration and cross-run pool state.
- Added in-guest locked-state, ZFS, KeePass transaction, Authentik/API, default-deny/allow/admin authorization, header-spoof, CopyParty, anonymous read-only TFTP, custom-command, AI lifecycle, observability, Syncthing, Vaultwarden, and final-health checks.
- Re-runs Python, Node, JSON/TOML, repository preflight, and Nix flake evaluation inside each test VM.
- Fixed timer attribute replacement, removed NixOS `requiresMountsFor`, migrated to `pkgs.libargon2`, forced CopyParty UMask, and corrected host-ID/evaluation conflicts.
- Replaced ShellCheck-unreachable optional-string exits with runtime guards for UPS and ZFS tools, conditionally emitted encryption-only variables, and added the missing protected network dependency.
- Removed the invalid mdBook `multilingual` field.
- Added an independent observability `serviceGid` option, corrected its collision diagnostic, and made the ZFS mount guard part of the protected target so every unlock revalidates the mount.
- Rebuilt Cockpit-ZFS with Node.js 22 and a matching Yarn Berry on host/build platforms to avoid the Node 24.15+ PnP/Tailwind failure.
- Fixed TFTP so its documented anonymous principal can read the volume, writes remain denied by default, and the ZFS-backed directory is created after mount verification rather than under the hidden bind target.
- Retargeted CI away from the intentionally incomplete production placeholder and added a dedicated KVM integration job.

## 2.1.0-alpha.11 — 2026-08-05

- Changed `nas_admin` from an exactly-one invariant to an explicit one-or-more trusted-superuser group; one member is created by default and existing superusers may add more.
- Added bootstrap repair that explicitly adds enabled `akadmin` when the superuser group is empty; bare user-level superuser flags are not treated as NAS group authority. Administrator discovery merges explicit membership from both user and group API expansions.
- Added a minimal locked-state Cockpit unlock form using `nas-secrets activate-stdin`, Cockpit superuser escalation, and stdin-only KeePass password delivery.
- Kept direct Cockpit TLS available on trusted interfaces while the protected KeePass/ZFS/application stack is locked.
- Expanded searchable Cockpit documentation to cover routes, UIs, permissions, superusers, locked recovery, services, observability, networking, schedules, storage, backups, virtualization, AI, UPS, runtime paths, installed versions, command help, source references, and review history.
- Fixed Syncthing-disabled result shape, Syncthing parent directory ownership, strict Authentik device attribute parsing, atomic-write read races, and identity synchronizer readability.
- Decoupled vmalert and Alertmanager from ntfy while retaining optional ntfy routing.
- Added tests for multiple administrators, bootstrap membership, disabled Syncthing, malformed device attributes, missing CopyParty parent shares, and Cockpit unlock input behavior.
- Kept the NixOS 26.05 stable channel.

## 2.1.0-alpha.10 — 2026-08-05

- Changed every non-admin capability to explicit Authentik `nas_allow_*` membership; baseline users and guests now receive no NAS application permissions.
- Changed the CopyParty personal-volume template from `nas_users` to `nas_allow_files`.
- Added explicit `nas_allow_syncthing` policy for device reconciliation and the Authentik settings flow.
- Added authorization-only Caddy gates for files, WebDAV, Syncthing self-service, and Vaultwarden SSO without waking unrelated feature units.
- Gated Vaultwarden OIDC initiation through the Authentik `nas_allow_vault` capability while preserving native client/API routing.
- Replaced Prometheus storage and rule evaluation with single-node VictoriaMetrics plus vmalert; retained Prometheus-format exporters, Grafana, Alertmanager, and ntfy.
- Made VictoriaMetrics always-on and kept Grafana independently on-demand.
- Configured VictoriaMetrics with its native `/victoriametrics` HTTP path prefix so VMUI, APIs, Grafana, vmalert, Caddy, and readiness checks use one consistent URL space.
- Moved Authentik API readiness into Authentik's own `ExecStartPost`; removed the dependent identity-sync readiness probe.
- Replaced the hand-written 90-attempt secret-activation loop with bounded curl retries, explicit service-failure checks, and distinct exit codes.
- Verified secret staging directories are mode `0700` before writing.
- Expanded Cockpit privileged-action tests across the complete allowlist and replaced a source-text assertion with behavioral mocking.
- Anchored the hfdownloader Renovate matcher to its update comment and adjacent tag.
- Fixed defensive identity/device validation, optional warning-file reads, hostname lookup, and systemd output parsing.
- Added an Alpha.10 review disposition and reprioritized remaining work.

## 2.1.0-alpha.9 — 2026-08-05

- Made CopyParty the sole authority for volumes, paths, ACLs, flags, quotas, indexing, and native share links.
- Removed Authentik `nasShare*`/`share-*` translation, generated CopyParty includes, generated share-directory creation, and custom share ownership/symlink policy.
- Reworked `nas-identity-sync` to enforce the reserved Authentik model and reconcile only optional reserved Syncthing objects.
- Kept `nas_admin` as the sole Authentik-superuser group and rejected zero or multiple enabled administrators.
- Removed the Python portal and custom user-settings service; Caddy now renders the lightweight landing page and redirects settings to Authentik.
- Added an Authentik Prompt + User Write blueprint for `attributes.nasSyncthingDevices`; removed the second Syncthing-device settings database.
- Kept the upstream global Syncthing UI administrator-only and preserved unrelated manually managed Syncthing objects.
- Added native CopyParty dynamic personal volumes, an administrator configuration volume, and native share administration for `nas_admin`; personal users receive `rwmd.` rather than CopyParty application-admin permission.
- Added optional Syncoid replication for the managed ZFS dataset and children.
- Narrowed Restic to `nas-boot-system` recovery, added `/boot`, and defaulted its repository to ZFS storage when no external repository is configured.
- Added machine/SSH/Nix identity state and staged CopyParty `shares.db`/`sessions.db` to Restic without traversing the bind-mounted ZFS share tree.
- Added strict Syncoid target validation for empty, whitespace-containing, or option-like destinations.
- Documented that same-pool Restic is not independent protection and should be carried to another pool by Syncoid or replaced with an external repository.
- Removed repository ownership, writable-parent, and symlink-policy validation from `nas-update` while retaining sanitized Git, fast-forward checks, tests, build/health validation, and rollback.
- Added searchable Cockpit documentation for the final authority model, migration steps, CopyParty configuration, Authentik settings, Syncoid, and Restic recovery.
- Retained bootstrap/scoped Authentik token separation, configurable bootstrap email, strict feature-state validation, runtime availability probes, batched Cockpit status, installation-ready CI, Disko examples, and expanded recovery guidance.
- Replaced LLDAP plus Authelia with native Authentik and PostgreSQL.
- Replaced the KeePassXC Secret Service/D-Bus/desktop dependency with interactive `keepassxc-cli --pw-stdin` operations.
- Replaced Apprise/custom alert bridging with native ntfy and `alertmanager-ntfy` services.
- Kept hfdownloader on its digest-pinned OCI image pending reproducible native Go packaging.

## 2.1.0-alpha.8 — 2026-08-05

- Consolidated shared policy code, removed implicit Nix `with` scopes, split the Cockpit frontend, improved CI, and separated former LLDAP machine credentials.

## 2.1.0-alpha.7 — 2026-08-05

- Added authenticated on-demand service wake/readiness/idle-stop behavior and reduced resident memory.

## 2.1.0-alpha.6 — 2026-08-05

- Added Cockpit feature modes, per-user UI capability policy, simplified reviewed updates, and memory planning.

## 2.1.0-alpha.5 — 2026-08-05

- Replaced the original KeePass account registry with a directory-backed identity translator and separated generated/mutable Copyparty configuration.
