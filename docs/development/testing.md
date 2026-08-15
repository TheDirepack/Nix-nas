# Testing and validation

The 2.2 test architecture is deliberately layered. Cheap source checks reject malformed input, unsafe code patterns, and missing test contracts before CI spends time on Nix builds, browser engines, or full QEMU installation tests.

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
locally during pre-merge qualification. GitHub's fast workflow dispatch is
narrower and may omit heavyweight generated testing. `all` additionally runs
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

This long-duration mode is intentionally local-only. It is not enabled by
ordinary pull-request CI; the merge decision should attach the resulting
logs/evidence from the local run. The runner places each suite's Hypothesis
example database under its own `/tmp/nix-nas-hypothesis-*` directory by
default. Set `HYPOTHESIS_STORAGE_DIRECTORY` when reproducing a specific shared
corpus. Keep the generated `node_modules`, reports, and other runtime output
outside the worktree or remove them before commit.

`scripts/fuzz.py` remains only as a stable compatibility entry point for the Hypothesis boundary suite. `scripts/fuzz-executables.py` is retained as a compatibility filename for the executable contract layer; despite the old name it does not perform mutation fuzzing or repeat generic payload lists.

The installed disposable VM uses the same principle in `tests/vm/adversarial-installed.py`. Hypothesis generates strategy-specific **guaranteed-invalid** argv values for each declared command grammar and shrinks failures. Because each example starts a real appliance command, the example budget is intentionally small; repeatedly launching a command with hundreds of generic SQL/XSS/path strings would consume VM time without useful search guidance. Explicit shell-injection and other historically important values remain as regression examples.

Known attack strings belong in deterministic regression tests or Hypothesis `@example` cases when they represent a concrete bug. A generated failure should be minimized by the property engine and, after the implementation is fixed, preserved as a deterministic regression if the example carries lasting security value.

For a genuinely byte-oriented, fast in-process parser where code-coverage feedback can guide mutations, prefer a maintained coverage-guided engine such as Atheris/libFuzzer rather than adding another local RNG loop. Do not wrap subprocess, systemd, QEMU, or browser workflows in byte mutation merely to increase a case counter. If the project later exposes a machine-readable OpenAPI or GraphQL surface, use a schema-aware engine such as Schemathesis rather than generic HTTP request spraying.

CI currently sequences the generated source-property shards after deterministic QEMU integration. That is an orchestration choice, not a limitation of Hypothesis or fast-check. The important boundary is tool selection: use the cheapest layer that proves the invariant while preserving higher-fidelity VM or browser checks where those semantics matter.

CI does not cache qualification pass markers. Dependency downloads, immutable installer media, and incremental Nix build outputs may be cached because they accelerate execution without replacing test evidence.

After the fast gates pass, one `build` job uses one runner to materialize and verify Cockpit (compiling it on a cache miss), round-trip the source archive, and build the NixOS closures in sequence. Browser qualification and KVM/QEMU integration remain downstream jobs. This runner consolidation does not remove or pass-cache any qualification tier.

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

Automated accessibility and layout checks cannot detect every visual or usability defect; manual review remains part of release qualification.

## 6. Packaged-source consumer test

CI builds the guarded source archive, validates it as an untrusted consumer, rejects duplicate, traversing, or non-regular ZIP members, then extracts with a Unix-mode-preserving tool. Release assembly separately verifies that each archived file mode matches the staged file, which prevents executable maintenance scripts from silently becoming non-executable in distribution. The consumer then verifies every manifest digest, reruns manifest-aware preflight from the extracted tree, and runs the valid/invalid Nix configuration matrix from that packaged copy. The matrix evaluates every bootable reference configuration while proving the operator hardware placeholder remains non-bootable for the expected missing-root and boot-loader assertions. This catches errors that only appear after file selection, permission encoding, extraction, or archive assembly rather than testing the checkout alone.

## 7. NixOS, QEMU, and installation matrix

Before building closures, CI evaluates the appliance plus each reusable profile and runs intentionally-invalid fixtures that must fail with the exact expected safety assertion:

```bash
./scripts/nix-config-matrix.sh
nix develop .#qemu-test -c ./scripts/qemu-test.sh all
```

The negative fixtures currently cover loopback/duplicate trusted interfaces, invalid ZFS dataset roots, privileged TFTP ports, same-dataset replication destinations, and firewall/networking contradictions. A fixture that evaluates successfully—or fails for some unrelated reason—is a test failure.

The heavyweight matrix deliberately uses different system lifecycle paths:

- `static`: source preflight, full flake evaluation, and installable closure builds.
- `native`: normal and encrypted-ZFS `runNixOSTest` appliances with kernel/systemd/block-device behavior.
- `installer`: checksum-verified official NixOS ISO, fresh disk installation, a second declarative `nixos-install` onto the populated root, boot into the installed appliance, the complete guest/security/browser suite, an intentionally invalid candidate that must not activate, a distinct candidate generation followed by `nixos-rebuild --rollback`, return to the reviewed generation, and a second reboot.
- `clean`: removal of disposable QEMU state.

The reinstall, failed-candidate, candidate-switch, rollback, and final reconfiguration stages keep a persistence sentinel so an installer or activation path that accidentally destroys unrelated state fails the test. The rejected candidate must leave `/run/current-system` unchanged; the rollback drill must remove a candidate-only `/etc` marker; and the second reboot verifies that the restored reviewed generation remains bootable and persistent.

The guest suite deliberately checks states that must never occur: protected services running while secrets are locked, unauthenticated or spoofed identities receiving protected access, destructive setup without exact confirmation, hostile identifiers reaching shell execution, SQL-shaped usernames passing account validation, traversal-shaped device paths, malformed alert requests producing tracebacks, unsafe state/archive members, stale operation residue, and recovery/rollback inconsistencies.

The final installed-command workload also records curl-based HTTP adversarial evidence from the same disposable VM. That keeps protocol checks on the real appliance without confusing them with browser-rendering tests.

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

Pull requests run the deterministic source, contract, build, and handoff
checks. Browser, native QEMU, reboot/installer, and generated fuzz tiers are
qualification work: they run on the scheduled workflow, protected main/tag
pushes, or an explicit `workflow_dispatch` full/installer tier. The `full`
tier includes the official installer and installed-VM checks; `installer` is
the narrower on-demand tier for rerunning that portion. The summary still
reports every release-critical job and calls out cache persistence failures as
non-authoritative warnings.

The build job has an exact-reuse path. A commit-keyed, manifest-verified
source archive skips the package/re-extract/reference-evaluation round-trip on
reruns. When all six VM bundle keys are exact cache hits, the build imports
those archives, skips `save-missing`, skips the large handoff upload, and the
integration matrix restores the same cache keys directly. A cache miss exports
only the missing bundle and keeps the short-lived handoff path for the current
run. The core bundle contains boot, recovery, unlock, primary-access, and
deterministic-test packages. Identity, observability, storage add-ons, and AI
remain separate application bundles; `vm-drivers` contains only the small
configuration-sensitive driver delta.

Detailed VM behavior and environment overrides are in [`vm-testing.md`](vm-testing.md).

## 8. Dynamic web security

The Playwright suite is the deterministic application-level browser layer. Curl handles focused request/response adversarial probes, while the final ZAP workload provisions an independent official-ISO VM and runs broader unauthenticated and authenticated active scans against the loopback-only forwarded Cockpit port while its disposable overlay is alive. Set `NAS_ZAP_IMAGE` to an immutable `@sha256:` image reference; the harness intentionally refuses floating tags. CI fails closed when the reviewed repository variable is absent and retains HTML, JSON, and Markdown reports.

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
