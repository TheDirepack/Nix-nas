# Test layout

The host is never NixOS, so runtime qualification remains VM-first. Host-side and
Nix development-shell tests are useful for fast feedback, but they do not replace
native NixOS, installer, systemd, ZFS, or browser qualification.

## Where tests run

- Host/source: syntax, lint, structure, security contracts, and source-only behavior.
- Nix test shell: Python unit tests plus Hypothesis property/stateful fuzzing.
- Native NixOS VM: installed services, systemd, storage, authorization, and guest behavior.
- Installer VM: official-ISO install/reinstall/reboot/rollback qualification.
- Browser/runtime jobs: Playwright, installed-browser checks, and ZAP where appropriate.

For local source iteration:

```bash
nix develop .#test -c ./scripts/run-unit-tests.py --jobs 4
```

A green source run does not replace a green VM or installer run.

## Important test groups

- `test_*.py` — fast unit, transaction, negative-path, protocol, and contract tests.
- `test_adversarial_security.py` — explicit regressions for known hostile input classes.
- `test_fuzz_boundaries.py` — Hypothesis-generated parser and validation boundary properties.
- `test_property_invariants.py` — Hypothesis cross-object, round-trip, and metamorphic properties.
- `slow_managed_service_stateful.py` — Hypothesis `RuleBasedStateMachine` lifecycle sequences and differential projections.
- `test_secret_security_fuzz.py` — Hypothesis-generated secret/logging/transaction security properties.
- `test_service_caddy_validate.py` — generated Caddy configuration validated with real Caddy when available.
- `test_runner_accounting.py` — meta-tests for test inventory and runner accounting.
- `custom-script-contracts.json` — inventory binding NAS-owned runtime executables and maintenance tools to focused tests and installed-system contracts.
- `bats/` — fault injection around secret-tree transactions.
- `browser/authz.py` — installed-system browser authorization and responsive-layout checks.
- `cockpit/e2e/` — Playwright browser behavior, XSS, layout, and accessibility tests.
- `nixos/` — native NixOS test-driver scenarios.
- `vm/` — official-ISO installation, guest-side adversarial checks, and encrypted-storage lifecycle validation.

## Smart fuzzing architecture

The repository no longer maintains its own random mutation engine. Structured
Python fuzzing uses **Hypothesis**, which owns input generation, edge-case search,
shrinking, reproduction, and stateful sequences. The project only defines
strategies and invariants.

Run every source fuzz/adversarial class in parallel:

```bash
./scripts/run-fuzz.py
```

Run selected classes:

```bash
./scripts/run-fuzz.py --suite boundaries --suite properties
./scripts/run-fuzz.py --suite stateful
./scripts/run-fuzz.py --suite security
./scripts/run-fuzz.py --suite executable-contracts
```

The source classes are intentionally separate so expensive state-machine or
subprocess security checks do not serialize cheap parser properties. They share
one orchestration convention and can run concurrently.

`tests/fuzz_strategies.py` contains reusable Hypothesis strategies only. It must
not contain a second RNG, payload mutation loop, case counter, or home-grown
corpus engine.

`scripts/fuzz-executables.py` is retained as a compatibility filename, but it is
not a mutation fuzzer. It performs one-pass whole-process adversarial contracts
that property tests cannot model efficiently: argument injection sentinels,
unknown-option handling, signal death/traceback detection, syntax/source checks,
and preflight behavior. Repeating those whole-program checks thousands of times
would add runtime without exploring new state.

Known attack strings belong in deterministic regression tests or Hypothesis
`@example` cases when they represent a specific bug. Large generic SQL/XSS/shell
payload lists are not used as a substitute for structured generation.

For byte-oriented parsers where coverage-guided mutation is genuinely useful,
use a maintained coverage-guided engine such as Atheris/libFuzzer instead of
adding another project-local random loop. Do not introduce a coverage fuzzer for
highly structured inputs that Hypothesis can generate directly.

## Matrix harness

Use `./scripts/test-matrix.py list` to see which verification tiers are available
on the current machine. `./scripts/test-matrix.py fast` runs source, security, and
fuzz tiers with bounded subprocesses. `all --require-all` additionally requires
Nix configuration, browser, native-QEMU, and installer tiers. JSON evidence can
be retained with `--report`.

## Security testing

`scripts/run-security-tests.py` runs the project scanner, Python adversarial tests,
JavaScript security tests, and browser-security-spec syntax as one bounded tier.
`scripts/security-static-scan.py` is the offline project-specific guard for
shell/code execution, dynamic SQL, unsafe deserialization/temp/archive patterns,
and dangerous DOM/JavaScript sinks. CI additionally runs Semgrep, Bandit, and npm
audit. Dynamic web checks use Playwright/axe and ZAP only where those tools match
the target surface.

Automated security scans are regression barriers, not proof that the appliance is
vulnerability-free. Release qualification still requires the QEMU, installer,
and hardware/network drills described in the development documentation.

## Writing tests: prefer signals over substrings

Do not confirm behavior by searching generated Nix/Caddy/systemd text for a
substring when a behavioral or evaluated assertion is available.

Prefer:

- **Python behavior**: call the function and assert on its return value.
- **Property tests**: describe the valid/invalid input space and assert invariants.
- **State machines**: generate meaningful operation sequences and compare with a reference model.
- **JSON Schema**: validate complete documents against the declared schema.
- **Nix evaluation**: assert on evaluated configuration values, not source text.
- **External validators**: use Caddy/systemd/etc. for their native formats.
- **Runner accounting**: assert on structured JSON evidence rather than stdout substrings.

Source-text existence checks are acceptable as small smoke guards, not as primary
behavioral coverage.
