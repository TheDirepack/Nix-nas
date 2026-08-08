# Test layout

The test suite is intentionally layered so cheap failures are found before a VM or installer is involved.

- `test_*.py` — fast unit, transaction, negative-path, protocol, and contract tests.
- `test_adversarial_security.py` — hostile SQL-like, shell, XSS, path-traversal, control-character, and malformed-HTTP inputs at privileged boundaries.
- `test_fuzz_boundaries.py` — deterministic seeded fuzz smoke tests that run without third-party dependencies.
- `test_property_invariants.py` — Hypothesis properties for parsers, secrets, identifiers, alert normalization, and managed-service validation (positive generators, round-trip, and metamorphic rejection); CI supplies Hypothesis through the pinned Nix test shell.
- `test_managed_service_stateful.py` — RuleBasedStateMachine for managed-service lifecycle (add/modify/disable/enable/delete/reconcile) with reference-model invariants and differential projection checks (effective/portal/caddy drift).
- `test_service_caddy_validate.py` — generates a Caddy fragment via `nas_service_caddy.generate_caddy_fragment()` and validates it with `caddy validate/adapt/fmt` when the `caddy` binary is present; otherwise skips with `unittest.SkipTest` (CI provides `caddy` via `nix shell nixpkgs#caddy`).
- `test_runner_accounting.py` — meta-test that every `services/*.py` mapping in `custom-script-contracts.json` has an importing behavioral test (AST import check) and that the runner correctly parses skipped/xfail accounting.
- `custom-script-contracts.json` — inventory binding every NAS-owned runtime executable and every Python control-plane module to focused tests. Installed commands also require an installed-system test and fuzz strategy. `scripts/validate-test-inventory.py` fails when new custom code appears without a declared test contract.
- `bats/` — fault injection around secret-tree transactions.
- `browser/authz.py` — installed-system browser authorization and responsive-layout checks against real Cockpit and Authentik sessions.
- `cockpit/e2e/` — Playwright Chromium/Firefox/WebKit and mobile rendering, XSS, interaction, viewport, and axe accessibility tests against the exact built Cockpit bundle.
- `js/` — direct behavior tests for shipped Cockpit JavaScript modules.
- `nixos/` — native NixOS test-driver scenarios.
- `vm/` — official-ISO installation, repeated installation, post-install reconfiguration, guest-side adversarial checks, and encrypted-storage lifecycle validation.

## Matrix harness

Use `./scripts/test-matrix.py list` to see which verification tiers are available on the current machine. `./scripts/test-matrix.py fast` runs source, security, and fuzz tiers with bounded subprocesses; `all --require-all` is the release-oriented path that also requires the Nix configuration/negative-fixture matrix, browser, native-QEMU, and installer tiers and forces complete source preflight. JSON evidence can be retained with `--report`.

## Fuzzing

Quick deterministic fuzzing is part of preflight:

```bash
./scripts/fuzz.py --cases 2000
```

Use a larger count before a release or after changing a parser/boundary:

```bash
./scripts/fuzz.py --cases 50000 --seed 0x4e41533232
```

A crash writes a replay record under `.fuzz-crashes/`. Do not commit crash artifacts; turn each confirmed crash into a deterministic regression test before fixing it.

## Security testing

`scripts/run-security-tests.py` runs the project scanner, Python adversarial tests, JavaScript security tests, and browser-security-spec syntax as one bounded tier. `scripts/security-static-scan.py` is the offline project-specific guard for shell/code execution, dynamic SQL, unsafe deserialization/temp/archive patterns, and dangerous DOM/JavaScript sinks. CI additionally runs the committed `.semgrep.yml` rules, Bandit, and npm audit. Dynamic web checks use Playwright/axe on the built bundle and the installed VM uses real authentication sessions.

Automated security scans are regression barriers, not proof that the appliance is vulnerability-free. Release qualification still requires the QEMU, installer, and hardware/network drills described in the development documentation.

Prefer behavioral tests over broad source substring checks. Cross-file assertions are appropriate for declarative Nix/systemd wiring that cannot be exercised in the fast source suite, but should protect a specific invariant.
