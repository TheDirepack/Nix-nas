# Testing and validation

The 2.2 test architecture is deliberately layered. Cheap source checks reject malformed input, unsafe code patterns, and missing test contracts before CI spends time on Nix builds, browser engines, or full QEMU installation tests.

## Verification matrix harness

`./scripts/test-matrix.py` is the single orchestration entry point. It records bounded pass/fail/skip evidence without pretending unavailable tools ran.

```bash
./scripts/test-matrix.py list
./scripts/test-matrix.py fast --report test-evidence/fast.json
./scripts/test-matrix.py security --report test-evidence/security.json
./scripts/test-matrix.py fuzz --cases 10000 --seed 0x4e41533232 --report test-evidence/fuzz.json
./scripts/test-matrix.py all --require-all --report test-evidence/full.json
```

The local matrix `fast` command includes its fuzz tier. GitHub's fast workflow dispatch is narrower and runs no fuzz workloads. `all` additionally runs the Nix configuration/negative-fixture matrix, built-browser, native NixOS VM, and official-ISO installer tiers. Each stage has an outer deadline; missing heavyweight tools or reviewed frontend artifacts are reported as **skipped** unless `--require-all` is supplied. In `--require-all` mode, the source stage also forces complete preflight, so missing Ruff, Pyright, ShellCheck, Nix, or reviewed Cockpit artifacts cannot be hidden as a partial source pass.

The CI pipeline summary applies event- and dispatch-tier requirements. A job required for that run must succeed; a skipped required job fails pipeline qualification rather than being accepted as an intentional skip.

## 1. Fast source validation

```bash
./scripts/preflight.sh
```

Preflight checks repository structure and data, version and policy contracts, documentation links, the custom-executable inventory, static security boundaries, Python syntax and behavior, shell syntax, JavaScript/JSX source contracts, the Cockpit bundle when available, and the Authentik fixture. Its deterministic fuzz smoke tests are opt-in through `NAS_PREFLIGHT_INCLUDE_FUZZ=1`; CI runs fuzzing only in the final parallel stage. Nix, Ruff, Pyright, ShellCheck, and complete Cockpit bundle checks run when their tools or artifacts are available.

The offline Authentik fixture uses a private temporary identity lock unless the caller supplies an explicit lock path, keeping source validation isolated from host runtime state.

Useful focused commands:

```bash
./scripts/run-unit-tests.py --jobs 4
python3 -m unittest tests.test_adversarial_security -v
./scripts/run-security-tests.py
./scripts/security-static-scan.py
./scripts/fuzz.py --cases 5000
./scripts/fuzz-executables.py --cases 5
node --test tests/js/*.test.mjs
node cockpit/build.js --check-source
```

`tests/custom-script-contracts.json` is the executable coverage authority. Every NAS-owned installed command and every executable repository-maintenance script must declare focused tests plus an adversarial strategy. Installed commands must also declare an installed-system test. `scripts/validate-test-inventory.py` discovers the executable surfaces and fails closed when a command is added, removed, or assigned an unsupported fuzz strategy without updating the test architecture.

## 2. Boundary, property, and executable fuzzing

The deterministic boundary fuzzer requires only Python and uses a replayable seed. It exercises parsing and validation boundaries for identity groups, secrets, usernames, alerts, feature catalogs, setup documents, feature identifiers, state members, identity models, structured logs, doctor input, migration schemas, identity-error sanitization, operation classes, operation journals, authorization, endpoint labeling, and loopback-only health/probe URLs.

```bash
./scripts/fuzz.py --cases 50000 --seed 0x4e41533232
```

The source-executable fuzzer runs every maintained executable script with strategy-appropriate hostile arguments. `scripts/run-matrix-fuzz.py` combines the boundary, unittest mutation, and executable fuzz layers under one seed/case contract for the matrix harness. Payloads include traversal strings, command-substitution markers, SQL-shaped input, HTML/JavaScript payloads, control characters, option confusion, and oversized values. It never invokes a shell with attacker-controlled text and checks for signal deaths, Python tracebacks, and marker-file creation.

```bash
./scripts/fuzz-executables.py --cases 20 --seed 0x534352495054
```

The installed VM has a separate command fuzzer in `tests/vm/adversarial-installed.py`. It discovers the installed command strategies from the same inventory and exercises every NAS-owned appliance command in the disposable VM. Destructive ZFS commands use disposable test storage rather than the host or production data.

CI exposes parser fuzzing, boundary unittest mutations, executable fuzzing, Hypothesis properties, randomized secret fuzzing, hostile-input browser fuzzing, installed-command fuzzing, and active ZAP scanning as final parallel workloads. Source and browser shards wait for deterministic integration; release and installer runs also wait for deterministic official-ISO qualification. Installed-command and ZAP jobs each provision a fresh isolated appliance instead of persisting or sharing VM disks or credentials.

CI also runs Hypothesis properties from the pinned Nix test shell:

```bash
nix develop .#test -c python -m unittest tests.test_property_invariants -v
```

CI does not cache qualification pass markers: fast, property, browser, build, VM, and installer gates execute for every run that requires them. Dependency downloads, immutable installer media, and incremental Nix build outputs may still be cached because they accelerate execution without replacing test evidence.

After the fast gates pass, one `build` job uses one runner to materialize and verify Cockpit (compiling it on a cache miss), round-trip the source archive, and build the NixOS closures in sequence. Browser qualification and KVM/QEMU integration remain downstream jobs. This runner consolidation does not remove or pass-cache any qualification tier.

Unexpected deterministic fuzz crashes are retained under `.fuzz-crashes/` with the target, seed, and case. A confirmed crash should become a normal regression test before the implementation is fixed.

## 3. Static security and injection checks

The project-specific scanner rejects high-risk NAS-owned sinks in Python, JavaScript, shell-generating Nix, and generated SQLite workflows. It covers Python `eval`/`exec`, `os.system`, `subprocess(..., shell=True)`, dynamically constructed SQL passed to execution methods, generated-shell `eval`, unsafe SQLite CLI meta-command construction, and raw DOM/JavaScript execution sinks.

```bash
./scripts/run-security-tests.py
./scripts/security-static-scan.py
nix develop .#test -c semgrep --config .semgrep.yml --error services scripts cockpit/src web
nix develop .#test -c bandit -q -r services scripts -ll -ii
npm --prefix cockpit audit --audit-level=high
```

Behavioral adversarial tests additionally send SQL-, shell-, traversal-, CRLF-, and XSS-shaped values through setup, identity, feature-control, alert, state, and Cockpit API boundaries. Static scanners are not treated as proof that an interface is safe; the behavioral tests are the primary contract for input handling.

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

The browser suite verifies that hostile backend strings remain inert, no executable markup appears, controls work with keyboard focus, serious/critical automated accessibility findings are absent, and the page avoids document-level horizontal overflow across small phones through large desktop viewports. It also repeats layout checks at 200% font scaling and with oversized hostile status text.

The installed-system Selenium suite separately uses the running Cockpit, Caddy, and Authentik stack. It checks real login and authorization identities, capability grants and denials, XSS-shaped identity data, browser console errors, duplicate DOM IDs, interactive-control geometry, and multiple viewport widths. This gives the project both a deterministic mocked-backend browser layer and a real-appliance browser layer.

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

Detailed VM behavior and environment overrides are in [`vm-testing.md`](vm-testing.md).

## 8. Dynamic web security

The Playwright suite is the deterministic application-level layer. The final ZAP workload provisions an independent official-ISO VM, runs the existing public/Cockpit scans, and then runs unauthenticated and authenticated active scans against the loopback-only forwarded Cockpit port while its disposable overlay is alive. Set `NAS_ZAP_IMAGE` to an immutable `@sha256:` image reference; the harness intentionally refuses floating tags. CI fails closed when the reviewed repository variable is absent and retains HTML, JSON, and Markdown reports.

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
