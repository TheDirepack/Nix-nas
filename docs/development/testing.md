# Testing and validation

Source checks reject malformed input, unsafe code patterns, and missing test contracts before CI starts Nix builds, browser engines, or full QEMU installation tests.

## Verification matrix harness

`./scripts/test-matrix.py` is the single orchestration entry point. It records bounded pass/fail/skip evidence without pretending unavailable tools ran.

```bash
./scripts/test-matrix.py list
./scripts/test-matrix.py fast --report test-evidence/fast.json
./scripts/test-matrix.py security --report test-evidence/security.json
./scripts/test-matrix.py fuzz --report test-evidence/fuzz.json
./scripts/test-matrix.py all --require-all --report test-evidence/full.json
```

The local matrix `fast` command runs source and security checks only. The
generated smart-fuzz tier is explicit (`test-matrix.py fuzz`) and should be run
locally during pre-merge qualification. CI qualifies the full-stack QEMU
matrix and the official-ISO installer tier on every pull-request commit;
schedule, main pushes, and explicit `full` dispatches additionally run the installed adversarial
qualification. A `full` dispatch requires every qualification tier, including installed-command and active ZAP checks. `all` additionally runs
the smart-fuzz, Nix configuration/negative-fixture matrix, built-browser,
native NixOS VM, and official-ISO installer tiers. Each stage has an outer
deadline; missing heavyweight tools or reviewed frontend artifacts are reported
as **skipped** unless `--require-all` is supplied. In `--require-all` mode, the
source stage also forces complete preflight, so missing Ruff, Pyright,
ShellCheck, Nix, or reviewed Cockpit artifacts cannot be hidden as a partial
source pass.

The CI pipeline summary applies event- and dispatch-tier requirements. A job required for that run must succeed; a skipped required job fails pipeline qualification rather than being accepted as an intentional skip.

## 1. Fast source validation

```bash
./scripts/preflight.sh
```

Preflight checks repository structure and data, version and policy contracts, documentation links, the custom-executable inventory, static security boundaries, Python syntax and behavior, shell syntax, JavaScript/JSX source contracts, the Cockpit bundle when available, and the Authentik fixture. Generated fuzz/property work is opt-in through `NAS_PREFLIGHT_INCLUDE_FUZZ=1`; when enabled, preflight delegates to the same `scripts/run-fuzz.py` orchestrator used elsewhere rather than maintaining its own seed, case count, or mutation loop. Nix, Ruff, Pyright, ShellCheck, and complete Cockpit bundle checks run when their tools or artifacts are available.

The offline Authentik fixture uses a private temporary identity lock unless the caller supplies an explicit lock path, keeping source validation isolated from host runtime state.

Useful focused commands:

```bash
./scripts/run-unit-tests.py --jobs 4
python3 -m unittest tests.test_adversarial_security -v
./scripts/run-security-tests.py
./scripts/security-static-scan.py
./scripts/run-fuzz.py
./scripts/run-fuzz.py --suite boundaries --suite properties --jobs 2
./scripts/run-fuzz.py --suite javascript --jobs 1
nix develop .#test -c python3 -m unittest tests.slow_managed_service_stateful -v
node --test tests/js/*.test.mjs
node cockpit/build.js --check-source
```

Workflow syntax is checked with `actionlint` in the static CI job. It is also
included in the `.#test` development shell for local validation:

```bash
nix develop .#test -c actionlint .github/workflows/ci.yml
```

`tests/custom-script-contracts.json` is the executable coverage authority. Every NAS-owned installed command and every executable repository-maintenance script must declare focused tests plus an adversarial/whole-process strategy. Installed commands must also declare an installed-system test. `scripts/validate-test-inventory.py` discovers the executable surfaces and fails closed when a command is added, removed, or assigned an unsupported strategy without updating the test architecture.

The `qemu-test` development shell includes the host-side QEMU, SSH, archive,
Git, Python, and core utility commands required by the wrapper.

## 2. Smart fuzzing and generated properties

The project does not maintain a project-local RNG mutator. **Hypothesis** is the canonical engine for Python structured input and stateful testing: it owns generation, edge-case search, shrinking, reproduction, and rule-based operation sequences. Project code defines strategies and invariants rather than manually generating thousands of arbitrary strings.

`scripts/run-fuzz.py` is an orchestrator, not a fuzzer. Its independent source classes can run in parallel:

- `boundaries` — parser, identifier, path, normalization, and decoder properties from `tests/test_fuzz_boundaries.py`.
- `custom-inputs` — pure input-boundary and service-adapter properties for every `services/nas_*.py` module from `tests/test_fuzz_custom_inputs.py`.
- `properties` — cross-object, round-trip, metamorphic, and validation properties from `tests/test_property_invariants.py`.
- `stateful` — `RuleBasedStateMachine` lifecycle sequences and differential projection checks from `tests/slow_managed_service_stateful.py`.
- `security` — generated secret/logging/transaction properties from `tests/test_secret_security_fuzz.py`.
- `javascript` — shrinking frontend value-space properties from the isolated `tests/js-fuzz/` fast-check workspace.
- `executable-contracts` — one-pass whole-process checks for behavior that cannot be modeled efficiently in-process, such as argument-injection sentinels, unknown-option handling, signal death, tracebacks, syntax/source checks, and preflight behavior.

Reusable Python generators live in `tests/fuzz_strategies.py`. They must not grow a second `random.Random` engine, static payload-blasting loop, global case counter, or home-grown corpus manager.

```bash
./scripts/run-fuzz.py
./scripts/run-fuzz.py --suite boundaries
./scripts/run-fuzz.py --suite stateful --suite security --jobs 2
./scripts/run-fuzz.py --suite javascript --suite executable-contracts --jobs 2
```

The ordinary commands are bounded one-pass qualification and are suitable for
the fast source tier. Immediately before merging a security-sensitive change,
run the same selected suites locally for a sustained search window; each
worker repeats its own suite independently and stops after the requested
duration:

```bash
./scripts/run-fuzz.py --duration-seconds 3600 --jobs 6
```

This long-duration mode is intentionally local-only. CI runs smart-fuzz
suites only when an operator explicitly dispatches the `full` tier after
deterministic qualification has succeeded; ordinary pull-request, push, and
schedule runs never include them. The merge decision should attach the
resulting logs/evidence from the local run. The runner places each suite's Hypothesis
example database under its own system temporary-directory
`nix-nas-hypothesis-*` directory by default. Set
`HYPOTHESIS_STORAGE_DIRECTORY` when reproducing a specific shared corpus. Keep
the generated `node_modules`, reports, and other runtime output outside the
worktree or remove them before commit.

`scripts/fuzz.py` remains only as a stable compatibility entry point for the Hypothesis boundary suite. `scripts/fuzz-executables.py` is retained as a compatibility filename for the executable contract layer; despite the old name it does not perform mutation fuzzing or repeat generic payload lists.

The installed disposable VM uses the same principle in `tests/vm/adversarial-installed.py`. Hypothesis generates strategy-specific **guaranteed-invalid** argv values for each declared command grammar and shrinks failures. Because each example starts a real appliance command, the example budget is intentionally small; repeatedly launching a command with hundreds of generic SQL/XSS/path strings would consume VM time without useful search guidance. Explicit shell-injection and other historically important values remain as regression examples.

Known attack strings belong in deterministic regression tests or Hypothesis `@example` cases when they represent a concrete bug. A generated failure should be minimized by the property engine and, after the implementation is fixed, preserved as a deterministic regression if the example carries lasting security value.

For a genuinely byte-oriented, fast in-process parser where code-coverage feedback can guide mutations, prefer a maintained coverage-guided engine such as Atheris/libFuzzer rather than adding another local RNG loop. Do not wrap subprocess, systemd, QEMU, or browser workflows in byte mutation merely to increase a case counter. If the project later exposes a machine-readable OpenAPI or GraphQL surface, use a schema-aware engine such as Schemathesis rather than generic HTTP request spraying.

GitHub CI runs deterministic checks through the QEMU and installer tiers; it does not run long fuzz searches. Run the generated source-property shards locally only after deterministic qualification succeeds, one suite at a time for the requested sustained search window. The important boundary is tool selection: use the cheapest layer that proves the invariant while preserving higher-fidelity VM or browser checks where those semantics matter.

CI does not cache qualification pass markers. Dependency downloads, immutable installer media, and incremental Nix build outputs may be cached because they accelerate execution without replacing test evidence.

The Cockpit job builds and verifies the frontend artifacts. After the source gates pass, the preparation job consumes those artifacts, round-trips the source archive, and builds or imports the NixOS closure handoff. Browser qualification and KVM/QEMU integration run downstream. Reusing a verified build artifact does not qualify a source or runtime test.

To qualify the cold handoff path on demand, dispatch the GitHub `CI` workflow with
`test-tier=full` and `force-cache-miss=true`. The run uses a unique cache
namespace, so it must export every missing bundle, pass the signed handoff to
the integration jobs, and report cache persistence without overwriting the
normal reusable cache. A normal cache hit remains the default PR and scheduled
path.

## 3. Static security and injection checks

The project-specific scanner rejects high-risk NAS-owned sinks in Python, JavaScript, shell-generating Nix, and generated SQLite workflows. It covers Python `eval`/`exec`, `os.system`, `subprocess(..., shell=True)`, dynamically constructed SQL passed to execution methods, generated-shell `eval`, unsafe SQLite CLI meta-command construction, and raw DOM/JavaScript execution sinks.

```bash
./scripts/run-security-tests.py
./scripts/security-static-scan.py
nix develop .#test -c semgrep --config .semgrep.yml --error services scripts cockpit/src web
nix develop .#test -c bandit -q -r services scripts -ll -ii
npm --prefix cockpit audit --audit-level=high
```

Behavioral adversarial tests additionally send SQL-, shell-, traversal-, CRLF-, and XSS-shaped regression values through setup, identity, feature-control, alert, state, and Cockpit API boundaries. Static scanners are not treated as proof that an interface is safe; behavioral and generated properties are the primary contracts for input handling.

## 4. Coverage regression gates

CI records branch coverage over the control-plane services and applies both an aggregate floor and service-specific floors with `scripts/check-coverage.py`. Every service module has an explicit floor, including alert routing, diagnostics, structured logging, state migration, and operation locking. Floors are regression guards rather than quality scores: raising them should follow added behavioral coverage, not exclusion of difficult branches.

`tests/test_e2e_v2_lifecycle.py` is a deterministic compiler/plan smoke test across runtime declarations; it does not apply or launch all native adapters. Focused specification/editor tests cover normalization and round trips. The guest suite additionally loads offline OCI images and tests live create/update/removal, SQLite durability, credential binding, isolation and quiesced ZFS snapshot recovery. It also rejects a running candidate that fails HTTP readiness, checking the candidate's startup witness, readiness timeout and restored desired bytes/live state.

A separate `vm-oci-persist` fixture remains installed for secret lock/unlock, reboot and Nix generation/package transitions. Its verifier observes revision, image, HTTP, exact dataset mount, content/ownership and actual CPU/memory/PID limits without restarting the workload. The native test removes it after qualification; the installer retains it for final browser qualification, which removes it in its disposable overlay after the browser suite. The installed Chromium project alone mutates its metadata through the Services form/YAML editor, including stale-save and invalid-input rejection; the other browser projects share the appliance and keep their existing rendering/authentication responsibilities. See the [testing work list](testing-worklist.md) for remaining gaps.

```bash
./scripts/run-unit-tests.py --coverage coverage.json --quiet --jobs 4
python3 scripts/check-coverage.py coverage.json
```

## 5. Browser, rendering, layout, XSS, and accessibility

The exact compiled Cockpit bundle is tested with lockfile-pinned Playwright and axe dependencies. CI installs Playwright-managed Chromium, Firefox, and WebKit engines and runs desktop and mobile projects.

```bash
npm --prefix cockpit ci --no-audit --no-fund
npm --prefix cockpit run build
npm --prefix cockpit exec -- playwright install chromium firefox webkit
npm --prefix cockpit run test:browser
```

Playwright is used whenever the invariant depends on actual browser semantics: DOM execution/XSS behavior, rendering, interaction, focus, layout, accessibility, or real login flows. Fixed XSS/HTML/URL strings are regression examples, not a pretend fuzzer; do not multiply a small seed list into dozens of mechanically transformed browser cases when the same input-space property can be checked more cheaply with fast-check. Generated browser tests are still appropriate when the property itself requires a browser engine.

HTTP request/response properties that do **not** depend on DOM or browser behavior should use curl or another protocol-aware client instead. In the installed disposable VM, `scripts/qemu-final-browser.sh` uses curl for hostile query strings, encoded traversal, response-status checks, and spoofed identity-header authorization probes against the real Cockpit/Caddy stack. This avoids paying browser startup and rendering cost for tests that only need HTTP semantics.

The browser suite verifies that hostile backend strings remain inert, no executable markup appears, controls work with keyboard focus, serious/critical automated accessibility findings are absent, and the page avoids document-level horizontal overflow across small phones through large desktop viewports. It also repeats layout checks at 200% font scaling and with oversized hostile status text.

The installed-system browser suite separately uses the running Cockpit, Caddy, and Authentik stack. It checks real login and authorization identities, capability grants and denials, XSS-shaped identity data, browser console errors, duplicate DOM IDs, interactive-control geometry, and multiple viewport widths. This gives the project both a deterministic mocked-backend browser layer and a real-appliance browser layer.

Negative login cases must observe Authentik's rendered `Invalid password` alert
before asserting rejection/inertness or clearing cookies for another payload.
An unchanged identity URL or still-visible password field is not proof that the
submission completed. `tests/js/final-vm-login.test.mjs` executes the complete
installed-test callbacks with deferred page/locator I/O to protect this ordering
and retain delayed marker/page-error failures. These source regressions do not
qualify browser rendering, installed authentication or timeout recovery; the
unchanged installed-browser projects and deadlines remain required.

CI retains browser reports and failure attachments even when the existing retry
passes. Outputs live under the runner temporary directory, outside the checkout.
Each `qemu-final-browser.sh` invocation creates a private, unique directory below
`NAS_FINAL_VM_EVIDENCE_DIR` (default: `$NAS_QEMU_CACHE_DIR/evidence`), so the initial
installation and package-upgrade runs cannot overwrite each other's reports,
traces, screenshots or serial console. The directory also retains the associated
installed-system console when available.

Before closing SSH or removing overlays, the final-VM wrapper makes one bounded,
read-only guest diagnostic collection: failed units, selected migration/notifier
unit properties and their boot journal plus the authentication/proxy gate journal.
`result.tsv` records the original workload exit, diagnostic exit and cleanup exit
separately. Diagnostic failure never replaces an existing workload failure;
missing SSH readiness is recorded as diagnostic exit 125. A successful collection
is not a clean-health assertion. Treat traces and journals as potentially
credential-bearing evidence: keep local directories private and review them
before redistribution. CI artifacts expire after seven days; archive evidence
needed for a merge decision before expiry.

Automated accessibility and layout checks cannot detect every visual or usability defect; manual review remains part of release qualification.

## 6. Packaged-source consumer test

CI builds the guarded source archive, validates it as an untrusted consumer, rejects duplicate, traversing, or non-regular ZIP members, then extracts with a Unix-mode-preserving tool. Release assembly separately verifies that each archived file mode matches the staged file, which prevents executable maintenance scripts from silently becoming non-executable in distribution. The consumer then verifies every manifest digest, reruns manifest-aware preflight from the extracted tree, and runs the valid/invalid Nix configuration matrix from that packaged copy. The matrix evaluates every bootable reference configuration while proving the operator hardware placeholder remains non-bootable for the expected missing-root and boot-loader assertions. This catches errors that only appear after file selection, permission encoding, extraction, or archive assembly rather than testing the checkout alone.

## 7. NixOS, QEMU, and installation matrix

Before building closures, CI evaluates the appliance plus each reusable profile and runs intentionally-invalid fixtures that must fail with the exact expected safety assertion:

```bash
./scripts/nix-config-matrix.sh
nix develop .#qemu-test -c ./scripts/qemu-test.sh all
```

The negative fixtures currently cover loopback/duplicate trusted interfaces, invalid ZFS dataset roots, privileged TFTP ports, same-dataset replication destinations, firewall/networking contradictions, retired `nas.backup.remote.*` options and unacknowledged local Restic repositories. A fixture that evaluates successfully—or fails for some unrelated reason—is a test failure. `tests/nixos/valid/` holds paired fixtures that must evaluate and whose own assertions check the generated Restic units and runtime backup policy. `tests/nixos/backup-policy-eval.nix` evaluates the pure backup policy and option migration as a positive/negative matrix.

The heavyweight matrix deliberately uses different system lifecycle paths:

- `static`: source preflight, full flake evaluation, and installable closure builds.
- `native`: normal and encrypted-ZFS `runNixOSTest` appliances with kernel/systemd/block-device behavior.
- `installer`: checksum-verified official NixOS ISO, fresh disk installation, a second declarative `nixos-install` onto the populated root, boot into the installed appliance, the complete guest/security/browser suite, an intentionally invalid candidate that must not activate, a distinct candidate generation followed by `nixos-rebuild --rollback`, return to the reviewed generation, and a second reboot. CI repeats installation with a pinned older NixOS 26.05 package revision, switches back to the current lock, verifies the package transition and persistent authorities, and reruns the final browser checks.
- `clean`: removal of disposable QEMU state.

The reinstall, failed-candidate, candidate-switch, rollback, and final reconfiguration stages keep a persistence sentinel so an installer or activation path that accidentally destroys unrelated state fails the test. The rejected candidate must leave `/run/current-system` unchanged; the rollback drill must remove a candidate-only `/etc` marker; and the second reboot verifies that the restored reviewed generation remains bootable and persistent.

The guest suite deliberately checks states that must never occur: protected services running while secrets are locked; a Cockpit listener or browser management route available while locked; unauthenticated or spoofed identities receiving protected access; destructive setup without exact confirmation; hostile identifiers reaching shell execution; SQL-shaped usernames passing account validation; traversal-shaped device paths; malformed alert requests producing tracebacks; unsafe state/archive members; stale operation residue; and recovery/rollback inconsistencies. It must also prove that initial static setup guidance cannot unlock secrets or create an authenticated Cockpit session, and that post-activation Cockpit access passes through Caddy and Authentik.

Both native guest legs require the managed Authentik projection to remain
condition-skipped and unexecuted before secret activation, with no compiled
effective state. After setup activates secrets, they require that same job to
execute successfully and commit its object manifest. A skipped job is not a
completed oneshot; bootstrap identity reconciliation remains a separate owner.

`tests/test_ntfy_readiness.py` executes ntfy's native service post-start check
against delayed, unavailable, unresponsive and error-returning HTTP listeners.
The delayed-listener fixture assembles a complete stderr line within its original
five-second deadline and isolates the probe in an owned process group for cleanup.
Regression cases force one-byte pipe reads and a failed activation with a live
descendant, without relaxing the connection-refusal or health assertions.
The readiness check must fail closed within its bound and must never publish a
notification. NixOS/installer qualification is still required for the packaged
unit, protected-target lifecycle and notification delivery.

The installed guest also exercises a service identifier absent from the Nix seed. It loads two VM-only BusyBox images from the Nix store, creates an identity-protected routed OCI service with revision-CAS document replacement, updates the running image, verifies that an offline missing-image activation restores both desired and live applied state, and removes the service and its Quadlet, systemd, Caddy, Authentik, and container projections.

Those VM-only images include SQLite for the OCI durability drill. The fixture
creates an authoritative child dataset and a test-only credential, writes an
application identity and task records through finite container-side SQLite/WAL
connections, verifies a new container ID after restart, and checks data and
credential binding after image replacement and failed-update rollback. It stops
the app before taking a consistent snapshot, restores that snapshot into a clone
while retaining the current dataset and a safety snapshot, then activates the
same V2 service/resource identity against the clone. Database integrity, logical
records, numeric owner/mode and credential bytes must match. Definition removal
must retain both datasets and the credential source; explicit fixture cleanup
runs only after these assertions succeed. Cleanup creates an extra snapshot on
each fixture and destroys the clone before the original with `zfs destroy -r`,
so scheduled Sanoid snapshots cannot make cleanup depend on wall-clock timing.
It never uses `-R` to destroy dependent clones outside the fixture, and a cleanup
failure stops before deleting the credential source. A failed guest run leaves
its remaining fixture data available for diagnosis; the guest refuses reuse of
occupied fixture paths.
Inspect or preserve that data before rerunning `persistent-test`: the wrapper
restores both disks to the clean baseline before invoking the guest again, so
the occupied-path check cannot preserve data across that reset. Disposable CI
VMs also do not retain guest disks indefinitely; preserve the required evidence
before their teardown.

`tests/test_vm_oci_durability.py` exercises the guest's verifier against real local
SQLite files, including corrupt/lost records, replaced identity/credential, and
changed mode. That verifies the assertions, **not** installed Podman/ZFS behavior.
Only a successful exact-head unencrypted QEMU/installer run qualifies the drill.

The same installed drill records the effective isolation of the V2 OCI app: the
inspection config must stay non-privileged, read-only-rooted, free of added
capabilities and host PID sharing, attached only to its declared isolated network
and exactly the two declared bind mounts (writable state, read-only credential),
with no Podman socket. Inside the container, the guest checks UID, `NoNewPrivs`,
active seccomp, effective/bounding capability equality, absence of a full
capability mask, read-only `/etc`, and writable state plus tmpfs. This fixture is
a system-level Quadlet, so it runs rootful with container UID 0; the assertions
pin that baseline and record it as a limitation. They are not user-namespace or
rootless isolation evidence, and do not qualify #141 by themselves.
`tests/test_vm_oci_isolation.py` mutates each inspected field and container probe
locally to prove the assertions reject drift without needing Podman.
Concurrent-writer crash recovery, missing/locked credentials, database migration
compatibility, reboot recovery and #139 creator-isolated archive/restore remain
separate qualification obligations. No timeout or retry budget is raised.

`test_v2_quadlet.py` also feeds rendered attachments to the real Quadlet
generator in `--dryrun` mode and inspects the serialized `ExecStart` volume,
tmpfs and device arguments. It covers whitespace, quotes, backslashes and
escaped `%` without starting Podman or requiring a GPU. The Nix test shell sets
the existing `NAS_V2_QUADLET_GENERATOR_BIN` to its pinned Podman generator;
outside that shell the test discovers a local generator or explicitly skips
when none is installed. An explicitly configured but broken generator fails.
This checks generator parsing, not systemd's runtime specifier expansion or
container mount/device access.

The final installed-command workload also records curl-based HTTP adversarial evidence from the same disposable VM. That keeps protocol checks on the real appliance without confusing them with browser-rendering tests.

The official-installer path additionally runs `tests/vm/setup-reboot-e2e.py` after the first-run guest suite. It writes a ZFS-backed sentinel, checks the completed V2 service set (including CopyParty and Syncthing), performs authenticated browser checks, reboots twice, and repeats those storage, service, and browser assertions after each boot. The Python runner writes one machine-readable result for the QEMU wrapper; no interactive continuation is required.

The disposable OCI persistence dataset has a native mount in `vm-common.nix`.
After the reboot harness imports the pool with `-N`, that mount starts after the
root dataset guard and before reconciliation or the OCI owner. It follows the
protected target through stop/reactivation and is conditional on the completed
fixture baseline, so initial setup does not require a nonexistent dataset.
V2 storage declarations do not create or mount host datasets, and persistence
verification observes the exact mount without repairing it.

### VM failure and handoff contracts

The fast PR contract includes executable process-level failure injection, not
only source-text assertions:

```bash
tests/vm/cleanup-failure-injection.sh
tests/vm/resource-failure-injection.sh
```

These cases run the shared VM cleanup/profile libraries through every declared
guest phase, inject ordinary and signal failures, and verify phase timing,
last-command, artifact-path, profiler, cleanup, temporary-secret,
run-owned-dependency, VM-state, and outpost evidence. They also rerun against
the same paths to catch stale processes, secrets, symlinks, and partial
`node_modules` trees. Resource cases cover missing commands, failed Nix and
QEMU starts, unavailable network, disk-full, and hung systemd simulations.

`tests/vm/timeout-budget.json` is the single phase manifest. The timeout
contract executes the real `timeout-budget.sh` functions with slow fake
commands, checks the phase-specific failure label, and verifies that the outer
watchdog is derived from all phase budgets. Bundle consumers must run:

```bash
./scripts/vm-bundles.sh verify-handoff <bundle-directory>
```

This checks every archive checksum, the complete manifest, and the
`vm-drivers` closure-deduplication rule. Missing or corrupt handoffs fail
closed; a missing reusable cache remains a functional cache miss and rebuilds
the exact base as needed.

Pull requests include deterministic browser, both native QEMU, and
official-ISO install/reboot qualification after the source and handoff gates.
Installed adversarial checks run on main pushes, schedules, and explicit
`full` dispatches. Final source fuzz runs on explicit `full` dispatches.
The `installer` tier selects the installer path without qualifying the full
release matrix. The pipeline summary rejects skipped or failed jobs required
by the selected event and tier. Cache persistence warnings do not qualify
source or runtime behavior.

The build job has an exact-reuse path. A commit-keyed, manifest-verified
source archive skips the package/re-extract/reference-evaluation round-trip on
reruns. When all five VM bundle keys are exact cache hits, the build imports
those archives, skips `save-missing`, skips the large handoff upload, and the
integration matrix restores the same cache keys directly. A cache miss exports
only the missing bundle and keeps the short-lived handoff path for the current
run. The core bundle contains boot, recovery, unlock, primary-access, and
deterministic-test packages. Identity, observability, and storage add-ons
remain separate application bundles; `vm-drivers` contains only the small
configuration-sensitive driver delta.

Detailed VM behavior and environment overrides are in [`vm-testing.md`](vm-testing.md).

### Interactive VM testing

For hands-on browser testing of a worktree, use the dev wrapper. It starts (or
reuses) the persistent VM, refreshes the current worktree into it, waits until
Caddy, Authentik, the proxy outpost, and Cockpit SSO are active, probes the
Console redirect, and prints the testing URLs:

```bash
./scripts/vm-dev.sh
```

- Launcher/setup: `https://nas-test.local:8443/`
- Authentik: `https://nas-test.local:8443/identity/`
- Cockpit console: `https://nas-test.local:8443/console/`

Before first-run setup completes, sign in with the bootstrap account
`akadmin` / `nas-admin-first-boot`; setup retires it after verifying the
chosen administrator (see [`../src/admin/first-run.md`](../src/admin/first-run.md)).
Run one-off guest commands with `scripts/vm-run.sh '<command>'`. The host
needs QEMU/KVM; Nix runs inside the guest, so host-side Nix is not required.

## 8. Dynamic web security

The Playwright suite is the deterministic application-level browser layer. Curl handles focused request/response adversarial probes, while the final ZAP workload provisions an independent official-ISO VM and runs broader unauthenticated and authenticated active scans through the loopback-forwarded public Caddy endpoint and protected `/console/` routes while its disposable overlay is alive. The harness does not expose Cockpit's native listener. Local runs require `NAS_ZAP_IMAGE` to be an immutable `@sha256:` image reference; the harness intentionally refuses floating tags. CI uses its committed upstream image digest unless the optional repository variable overrides it, and retains HTML, JSON, and Markdown reports plus the scan's `.addons.json` inventory.

Both wrappers use the shared hash-locked source build and add-on preparation described in
[`dependencies.md`](dependencies.md). A zero scanner exit also requires fresh
reports and verified native add-on evidence from that invocation. Archive hash
or runnable-inventory mismatches fail before the scan; scanner warnings remain
fatal. Authenticated automation requests the same-origin users/me API after
browser discovery and requires HTTP 200, the configured username in its response,
and ZAP's site-scoped logged-in session state. The fatal URL test checks status
and username together; the requestor's response-code warning is not a fatal test.
Browser success counters alone cannot qualify authentication. Native fixtures
must exercise accepted and rejected credentials, reject an authenticated error
response even when it contains the expected username, preserve cookie mutations
on the wire and detect the deliberately vulnerable session control. The
installed-security CI job runs these controls
before appliance scanning and retains their evidence. A successful fixture scan
verifies the harness, not appliance security.

The installed workload runs both packaged endpoint scans and both automation
modes even when an earlier scan fails. It uses the shared CI diagnostics helper
to retain independent logs and exit codes under `final-vm/logs/`, then fails the
workload if any scan failed. Authentication guards, finding policy, per-scan
budgets and fresh provenance requirements remain unchanged; collecting later
evidence does not waive an earlier finding.

For a local run:

```bash
nix develop .#qemu-test -c ./scripts/qemu-test.sh installer
NAS_ZAP_IMAGE='registry.example/zaproxy@sha256:<digest>' \
  NAS_ZAP_CONFIRM_ACTIVE=1 NAS_FINAL_VM_WORKLOAD=zap-fuzz \
  nix shell nixpkgs#qemu nixpkgs#openssh nixpkgs#curl -c bash ./scripts/qemu-final-browser.sh
```

`zap-scan.sh baseline` is passive apart from normal crawling; `zap-scan.sh full` actively attacks the target and requires `NAS_ZAP_CONFIRM_ACTIVE=1`. The wrapper accepts loopback, link-local, RFC1918, and `.local` targets by default; scanning a public target requires the separate `NAS_ZAP_ALLOW_PUBLIC_TARGET=1` override. ZAP warnings are failures by default, and an outer process timeout bounds the entire container even if the scanner itself stalls. The disposable QEMU harness supplies the active-scan confirmation when it owns the target. ZAP is supplementary because the most important NAS boundaries include authenticated Cockpit operations, Caddy/Authentik authorization, Unix-socket control planes, local privileged commands, storage operations, and recovery workflows that a generic web scanner cannot fully model.

## Evidence policy

Do not claim Nix, QEMU, browser-engine, ZFS, systemd, installer, static-tool, or hardware validation unless that environment actually ran. Source-only artifacts may report locally executed tests and must list every heavyweight tier that remains unexecuted.

The `run-unit-tests.py --group fast` selector is the single authoritative set of
fast-suite exclusions. Preflight, CI unit qualification, and the non-root CI
run all use that selector; targeted integration and tooling tests still run
separately. `--pattern` and `--exclude` remain available for focused runs.

### Installed ZAP observations

The packaged policy keeps session-management discovery (10112) informational,
as specified by [ZAP](https://www.zaproxy.org/docs/alerts/10112/). It does not
change cookie-security, session-verification, or Low+ failure thresholds.

The automation plan runs `scripts/lib/zap-context.js` after passive scanning and
before reports and the native exit-status job. Classified alerts remain in the
reports with their original risk and the reason in Other Info. Classification
requires the exact scan origin, rule, endpoint and evidence:

- Authentik's `authentik_csrf` cookie on the default authentication flow must
  remain readable by its frontend to construct the CSRF header. Session cookies
  and missing Secure/SameSite protections receive no exception.
- Cockpit's network-editor JavaScript includes the static example `10.0.0.1`.
- The decimal SHA-1 constants 1518500249, 1732584193 and 1859775393 in the
  Cockpit Podman/terminal bundles are algorithm constants, not disclosed dates.
- A PII match inside the fractional part of a Cockpit numeric metrics frame
  is informational only when the entire frame parses as nested numeric arrays.
  Standalone card numbers, string/object payloads and truncated frames retain
  their original risk.

Private-IP WebSocket classification additionally requires authenticated scan
mode, whose identity/session assertions run before the classifier. Only address,
route, and DNS properties in complete Cockpit NetworkManager notifications are
classified. For Cockpit's fragmented journal stream, every line containing the
matched IP must be a complete JSON record of firewalld's exact unassigned-source
diagnostic, with the expected systemd unit and identifier. Unauthenticated data,
other properties or journal messages, and incomplete matching records remain
fatal. This does not classify other rules on the management socket. Native ZAP
controls verify that the authenticated NetworkManager and journal observations
pass while unauthenticated observations, real PII and session failures still
fail. Installed authorization checks remain required; a WebSocket URL alone is
not proof of access control.

Proxy disclosure remains enabled: the edge rejects TRACE/TRACK and OPTIONS with
Max-Forwards before routing, while retaining normal CORS OPTIONS. In the
automation plan, rule 40025 also sends a plaintext request to the TLS port as a
blind-spot probe; its 400 rejection differs from the normal HTTPS status and the
rule reports a second, unidentifiable node. Only that exact two-unknown-node
report on an HTTPS origin is classified. Fingerprinted nodes, silent proxy
cookies, and TRACE-enabled findings retain their risk. Installed ZAP and browser
authorization tests must verify the probe policy on the exact candidate head.
Host source tests are not installed qualification.

### Fresh first-start qualification

The default plan is `/var/lib/nas-first-start/first-run.json`. The unencrypted
installed guest starts without that file or a KeePass database. Its browser
creates the plan from discovered disks, reviews it, confirms erasure and submits
setup. It then verifies the permanent administrator and exercises the account
CLI for ordinary users. It does not restart the proxy outpost to make login work.
Encrypted native qualification uses two fresh guests sequentially. Each creates
its custom plan through `nas-setup create-first-start-plan` and rejects stale
digests through both the API and CLI. One completes `first-run
--secret-payload-stdin` through the authorized-root integration; the other
submits a matching encrypted API request and waits for the detached job. Both
require preflight, encrypted storage and the remaining locked-boot, identity,
secret and service assertions. The CLI guest shuts down before the API guest
starts to keep the memory budget bounded.

Run the wizard interaction tests with `npm --prefix cockpit run test:browser --
first-run-wizard.spec.mjs`. These use
controlled API responses; only a successful native/installer run establishes
actual Authentik, systemd and ZFS setup. For hardware acceptance, use the
installation walkthrough unchanged: do not pre-create the default plan, insert
runtime secrets, patch units, or manually restart failed setup components.
Capture the setup journal and repair the owning implementation if that path fails.
