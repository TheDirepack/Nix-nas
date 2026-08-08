# Test layout

The host is never NixOS, so all `pytest` is VM-first. Host preflight checks
only syntax, lint, and structure; the built NixOS closure is the only
place where `pytest` is a gate.

## Where tests run

- Host (cheap, no `/run`): `scripts/validate-python-syntax.py`, `ruff`, `shellcheck`, `pyright`, `validate-structure.py`, `check-version.py`, `validate-cockpit-jsx`, `nix flake check --no-build`. Never `pytest` as a gate on host — `max` has no `nixos-rebuild` closure, no `nas-*` system users, and no tmpfs `/run/nas-state`.
- VM (`nixosConfigurations.nas-qemu` via `checks.x86_64-linux.nas-vm`): all `test_*.py` via `scripts/vm-pytest.sh` or `nix build .#checks.x86_64-linux.nas-vm --show-trace -L` plus BATS, browser, and QEMU installer. See `tests/vm/` and `test/qemu/harness.sh` (8G `vdb` for ZFS `tank`).

For local dev without booting a full VM, `nix develop .#test -c ./scripts/run-unit-tests.py` still works for fast iteration, but a green host run does not replace a green VM run.

- `test_*.py` — fast unit, transaction, negative-path, protocol, and contract tests (run in VM).
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
- `nixos/` — native NixOS test-driver scenarios (the canonical gate: `nix build .#checks.x86_64-linux.nas-vm`).
- `vm/` — official-ISO installation, repeated installation, post-install reconfiguration, guest-side adversarial checks, and encrypted-storage lifecycle validation.

## Matrix harness

Use `./scripts/test-matrix.py list` to see which verification tiers are available on the current machine. `./scripts/test-matrix.py fast` runs source, security, and fuzz tiers with bounded subprocesses; `all --require-all` is the release-oriented path that also requires the Nix configuration/negative-fixture matrix, browser, native-QEMU, and installer tiers and forces complete source preflight. JSON evidence can be retained with `--report`.

Use `scripts/vm-pytest.sh` to run the full `pytest` suite inside the VM:

```bash
scripts/vm-pytest.sh -- jobs=4 pattern=test_coding_agent.py
scripts/vm-pytest.sh -- coverage
```

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

## Writing tests: prefer signals over substrings

Do not confirm behavior by `assertIn("some text", path.read_text())` on generated Nix/Caddy/systemd text. Those checks break on whitespace, quoting, or comment changes and do not prove the runtime behaves.

Use instead:
- **Python behavior**: call the function and assert on its return value (`generate_caddy_fragment(effective)["routes"][0].host == "photos.local"` not `"/photos" in caddyfile`).
- **JSON-schema**: `jsonschema.validate(instance=doc, schema=load_schema())` for managed-service store.
- **Nix evaluation**: `nix eval .#nixosConfigurations.nas-qemu.config.systemd.services.nas-pi-netns.serviceConfig.ExecStart --json` and assert on the evaluated string, not the source file.
- **External validator**: `caddy fmt/validate/adapt` via `tests/test_service_caddy_validate.py` (golden file + `caddy fmt --check`).
- **Runner accounting**: `scripts/run-unit-tests.py --json report.json` and assert on `report["stats"]` rather than stdout substring.

`read_text` substring checks are acceptable only as a single existence guard per declarative file (`assert "nas-code-agent" in module` as smoke), not as per-invariant coverage.
