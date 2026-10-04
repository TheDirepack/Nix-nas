# Testing audit: 2026-10-03

## Result

Historical snapshot. Source corrections and current qualification limits are in
[Audit remediation: 2026-10-04](audit-remediation-2026-10-04.md).

Twelve testing weaknesses remain open. Five need high-priority correction;
seven are medium priority. These are priorities for test reliability, not new
security vulnerability ratings. This audit changes no implementation or tests.

Baseline: `4af2d0ea`. The audit concentrates on custom appliance code and its
failure paths. A green suite currently coexists with the seven reproduced code
defects in [the project audit](project-audit-2026-10-03.md).

The problem is not a lack of test files. Some tests exercise the wrong subject,
accept outcomes they should reject, or assert the recovery that the test itself
performs. Test names and coverage declarations overstate what those tests prove.

## Scope and standard

1. Trace test discovery, CI qualification, coverage enforcement, and executable
   inventories.
2. Review failure oracles in compiler/projection, state export/restore,
   reconciliation, generated properties, browser, and installed-command tests.
3. Challenge those oracles with temporary in-memory substitutions, run the
   deterministic source suite with branch instrumentation, and record gaps.

The review read the cited files in full. It also inventoried all top-level
Python test methods and all service coverage entries. This was not a line-by-line
review of every test or a live installed-system qualification.

Tests should exercise **project-owned decisions and effects**: validation,
authorization, command construction, ordering, generated configuration,
transaction state, cleanup, and recovery. Upstream programs are dependencies or
native validators, not separate products for this suite to requalify.

Keep integration checks that establish the project's wiring: generated Caddy
routes deny unauthorized requests, generated units enforce the intended
lifecycle, the mount guard rejects the wrong dataset, and the notification
configuration delivers to the intended topic. Do not remove these because they
use upstream software. Remove independent checks of DOM, upstream JSON parsing,
or other behavior that does not traverse custom code/configuration.

For each privileged workflow, cover the successful baseline once, then build
cases around rejection, partial mutation, failure at each externally visible
step, failed compensation, interruption, conflicting operations, and retry.
Every failure case must assert both the error and the surviving state. Merely
obtaining a nonzero exit or an exception is insufficient. Exhaustive coverage of
all possible failures is not measurable; enumerate supported failure boundaries
and record those not exercised.

## Findings

| ID | Priority | Weakness |
|---|---|---|
| T1 | High | Security/recovery-named tests pass without testing their named behavior |
| T2 | High | Transaction fault matrix fabricates native recovery instead of injecting failures |
| T3 | High | Custom-input properties allow unsafe success and swallow implementation failures |
| T4 | Medium | Account property generator always fails before account validation |
| T5 | Medium | Coverage inventories accept names/comments as execution evidence |
| T6 | Medium | Browser and VM cases independently retest upstream behavior |
| T7 | Medium | Advertised all-runtime E2E never applies or generates native units |
| T8 | High | Branch gate checks the wrong metric and omits 11 custom modules |
| T9 | Medium | Stateful suite avoids hazardous lifecycle states and has a disconnected rejection oracle |
| T10 | High | Existing negative tests miss seven confirmed custom-code defects |
| T11 | Medium | Installed adversarial runner accepts unrelated failures and inflates exercised-command counts |
| T12 | Medium | Browser “every surface/all controls” claims exceed the exercised UI |

### T1: tests that can pass without their subject

Source: `tests/test_nonv2_functional_coverage.py:191-245`.

- `test_cockpit_api_secret_not_logged` only checks that `common.split_groups`
  exists. It neither invokes the API nor captures output containing a secret.
- Hostname/storage, identity scrub/capability, doctor drift, and logging
  redaction tests condition execution on `hasattr`. Their optional targets
  (`validate_hostname`, `scrub_user`, `capability_name`, `check_drift`, `redact`)
  do not exist in the current modules. These branches do no work.
- `test_storage_mount_guard_exists` checks two state helpers are callable; it
  never presents the mount guard with a missing or incorrectly mounted dataset.

Verification: all six named tests passed. Replacing the Cockpit action entry
point with a function that raises on every call did not affect the secret test.

Correction: remove the non-behavioral cases or replace them with tests of the
current API. Assert secret absence in captured output on success, rejection,
timeout, and dependency failure. Exercise actual drift and mount decisions.
An absent expected production function must fail a test, not bypass it.
Keep the real focused suites rather than creating another set of nominal
coverage fillers.

### T2: the transaction fault matrix does not fail a transaction

Source: `tests/test_v2_transaction_faults.py:16-73`.

The six stage labels do not control native execution. Five labels follow the
same code path; only `after-mark-applied` changes history setup. No test invokes
the Nix transaction, NMState, firewall reconciliation, systemd reconciliation,
or Caddy activation. The test creates a local `native` dictionary, overwrites
every value with `old`/`baseline`, and then asserts those assigned values.
It also rewrites the authority to the expected rollback document before
asserting its contents.

The history operations are real and worth testing. They do not establish
cross-subsystem rollback, despite the stage names and final assertion.

Correction: retain the history assertions as history tests. Execute the actual
transaction with dependencies that fail after specified mutations. Assert
untouched/changed/restored projections, desired/applied revisions, service
state, rollback evidence, and manual-recovery status. Include a second failure
during compensation and retry from interrupted state. Do not repair expected
state in the test before observing the production recovery result.

### T3: generated hostile inputs have almost no safety oracle

Source: `tests/test_fuzz_custom_inputs.py:139-259`.

`expected_boundary_error` treats any `ValueError`, `OSError`, or `RuntimeError`
as acceptable and returns `None`. Most callers neither inspect a successful
result nor require an invalid value to be rejected. The compiler property only
changes a display name, then accepts either outcome. Structured tests also
replace many non-object inputs with `{}`, reducing the explored input space.
Four of the five generated test methods have no assertions; the fifth's only
direct assertion checks the constant CLI parser name, not the generated value.

Verification: the compiler property passed with an always-accept compiler and
with a compiler raising an unexpected `RuntimeError`. The text-boundary property
passed with a header validator that accepts a NUL/newline-bearing header.
These substitutions affected memory only, not repository source.

Correction: split guaranteed-invalid strategies from valid strategies. Require
the exact project validation exception for invalid cases. Check invariants on
successful results and unchanged authority/no side effects on rejection.
Unexpected OS/runtime failures must fail unless that particular boundary
explicitly promises to translate them. Keep a few targeted mutation checks
that demonstrate each security oracle detects an always-allow implementation.

### T4: generated accounts never reach account normalization

Sources: `tests/test_fuzz_boundaries.py:143-155` and
`services/nas_setup_config.py:123-143`.

The generated wrapper fixes `schemaVersion: 1` and includes retired `features`.
Current setup rejects the unknown field before reading accounts; removing it
still rejects schema version 1 because the current version is 2. The test
accepts these errors, so every generated account takes the same early exit.

Verification: a sentinel on username validation received zero calls. Both
fixed wrapper defects reproduced with deterministic input. The generated
account value cannot affect whether account validation runs.

Correction: generate accounts inside a current, otherwise valid wrapper.
Add explicit examples for both accepted and rejected accounts and prove the
test reaches the account boundary. Test obsolete envelope versions separately.

### T5: declared module coverage is not exercised coverage

Sources: `tests/test_fuzz_custom_inputs.py:56-103`,
`tests/test_fuzz_architecture.py:49-53`,
`tests/test_runner_accounting.py:51-86`, and
`scripts/validate-test-inventory.py:153-190`.

The custom-input suite lists all 44 service module names in a constant. Its
architecture test searches for those quoted names rather than verifying calls.
For example, activation, apply, history, generation, and systemd reconciliation
appear in the list but have no direct target calls in that suite. Other focused
tests exist; the claim that this fuzzer covers every module does not follow.

The inventory validator establishes paths exist. The “real import” meta-tests
also accept a module-name substring anywhere in the test source.

Verification: a comment-only file containing `# nas_v2_activation`, with no
imports or tests, passed `test_python_modules_mapping_has_real_import`.

Correction: label inventories as ownership/discovery metadata. Require actual
discoverable test IDs, and verify their subject behavior through instrumented
execution or focused mutation checks. Do not equate imports with assertions.
Remove the unused list-as-coverage claim rather than making every pure-input
suite artificially call every module.

### T6: independent upstream tests consume project qualification time

Sources: `cockpit/e2e/ui-security.spec.mjs:417-444` and
`tests/vm/guest-test.sh:677-682,1301-1305`.

The hostile-status corpus browser test creates its own spans, assigns
`textContent`, and checks no executable elements result. No project renderer
handles those values. Its assertion tests the browser's DOM behavior.

The guest suite twice posts malformed JSON directly to upstream Alertmanager
and asserts HTTP 400. Neither case goes through `nas-alert` or the project's
configuration renderer. They requalify upstream input parsing.

Correction: remove the standalone DOM case. Feed hostile data through actual
custom components and interactions. Replace the duplicate Alertmanager parser
checks with custom alert command/header validation and routing/configuration
failure cases. Preserve a single notification delivery integration check for
project-owned credentials, topic, and routing. Real Caddy validation of generated
output is also legitimate project integration coverage, not upstream retesting.

### T7: the deterministic E2E stops at planning

Sources: `tests/test_e2e_v2_lifecycle.py:1-7,119-210` and
`tests/test_v2_functional_coverage.py:679-707`.

The advertised all-runtime E2E calls the compiler, planner, and Caddy renderer.
The “systemd projection” test searches serialized plan actions; it does not call
the native systemd generator. None of its ten tests applies a projection,
reconciles a runtime, injects failure, or observes rollback/removal. Several
assert only keys or nonempty output. One all-primitives test duplicates another
network/storage key check.

The separate test named `test_apply_projection_is_atomic_and_validated` likewise
generates an in-memory bundle and checks two keys. It performs no apply,
validation subprocess, atomic replacement, or failure injection.

Verification: all ten E2E tests passed while native unit generation and `apply`
were replaced with functions that raise if called.

Correction: call these compiler/plan smoke tests. Keep one valid multi-runtime
baseline with exact cross-projection ownership assertions. Put most additional
cases into missing sources, invalid adapters, failed validation, partial writes,
restart failure, failed rollback, and cleanup. Execute real custom apply and
reconcile code with external tools stubbed at the process boundary. Retain VM
coverage where kernel/systemd semantics are required.

### T8: the coverage gate is not a branch-coverage gate

Source: `scripts/check-coverage.py:10-45,85-112`.

The gate reads `percent_covered`, coverage.py's combined statement/branch
percentage, and reports it as “branch coverage”. Baseline drift uses the same
metric. Executed straight-line statements can conceal untested decision edges.

Verification: the measured deterministic suite has **71.5% actual branch
coverage**, but the checker prints **78.3% branch coverage**. A synthetic report
with 990/1,000 statements and 0/100 branches covered in every floored module
passes and prints “90.0% branch coverage”. This is an oracle demonstration,
not a measured result for production code.

Malformed metrics also fail open: putting the string `"nan"` in every checked
percentage and the total passes with “nan%”. Comparisons against a non-finite
float do not reject the report.

Only 33 of 44 service modules have explicit floors. The omissions are:

`nas_guarded_apply`, `nas_v2_activation`, `nas_v2_authentik_blueprint`,
`nas_v2_cli`, `nas_v2_compose_import`, `nas_v2_firewalld_reconcile`,
`nas_v2_generation`, `nas_v2_history`, `nas_v2_nmstate`,
`nas_v2_podman_network`, and `nas_v2_systemd_attachments`.

Selected measured decision-edge coverage from this audit:

| Custom module | Covered branches | Actual branch coverage |
|---|---:|---:|
| `nas_v2_activation` | 6/16 | 37.5% |
| `nas_v2_control` | 13/40 | 32.5% |
| `nas_v2_bootstrap` | 18/46 | 39.1% |
| `nas_v2_libvirt` | 42/92 | 45.7% |
| `nas_v2_session` | 93/190 | 48.9% |
| `nas_guarded_apply` | 55/98 | 56.1% |
| `nas_state` | 282/426 | 66.2% |

These percentages describe executed edges, not correct assertions or the
percentage of failure paths tested. Coverage alone cannot prove recovery.

Correction: enforce actual branch counts/percentage, including baseline drift,
and reject missing module results. Maintain explicit decisions for all custom
modules. Test missing/malformed/non-finite coverage input and zero-branch files.
Raise guards after adding behavioral failure cases; do not exclude difficult
code to improve the score. Track generated shell/UI behavior separately because
`--source=services` does not instrument it.

### T9: stateful qualification explores a safe subset

Source: `tests/slow_managed_service_stateful.py:34-52,78-156,186-205`.

The machine uses short `svc0`-style IDs, one fixed `web` route per service,
persistent systemd daemons, public auth, and valid ports. It changes an in-memory
model and recompiles; it never calls editor CAS, file apply, reconciliation,
state export, or rollback. It cannot explore activation-name collisions,
maximum-length socket paths, capability separation, competing revisions,
partial transactions, or restart failure.

The rejection invariant gives the compiler a copy called `bad`, then asserts
that a different object, `self.services`, still equals its snapshot. It does not
check the passed input or any production desired-state authority.

Verification: the invariant passed with a compiler that clears the supplied
document's services and then raises a route error.

Correction: keep the projection model under its accurate scope. Add constrained
adversarial identifiers/routes and protected/on-demand combinations. For
transaction sequences, drive real custom editor/apply/reconcile functions and
compare independently maintained desired/applied/runtime state. Generate stale
CAS, rejected changes, interruption, failed restart, and failed compensation;
assert the actual authority survives rejection.

### T10: known custom-code failures remain outside the assertions

Sources: `tests/test_v2_caddy.py:294-315,388-399`,
`tests/test_v2_editor.py:202-219`,
`tests/test_v2_state_authority.py:52-55`,
`tests/test_state.py:87-93,707-727`, and
`tests/test_v2_systemd_reconcile.py:42-65,531-609`.

The [project audit](project-audit-2026-10-03.md) provides confirmed examples:

| Missing failure case | Existing test limitation | Required observation |
|---|---|---|
| Hyphenated service/route socket collision | Single short `demo/web` example | Distinct unit/socket/backend ownership across routes |
| Maximum valid IDs | Rejects traversal/control delimiters only | Generated socket is bindable or rejected before mutation |
| Compose status ownership | All-runtime YAML roundtrip does not read matching effective status | Fresh Compose state remains verified with its `.target` owner |
| Explicit empty export quiesce policy | Checks Nix text, not helper selection with valid effective state | No stop calls for the installed small registry |
| Database preparation failure after quiesce | Tests preparation success and stop failure separately | Every stopped unit restored, or explicit manual recovery |
| Lower/mixed-case static identity headers | Tests only `Remote-User` spelling | Case-insensitive rejection across forbidden headers |
| Active on-demand restart failure | Main fixture defaults to persistent start units | Error propagates, old reconcile state survives, outer rollback runs |

Most state-bundle tests explicitly disable export quiescing. That is useful
isolation for archive behavior, but it leaves the export lifecycle needing its
own failure matrix. Existing reconciliation stop/manual-recovery tests are
useful; they do not replace failure cases for the nonpersistent branch.

Correction: add these regressions before fixes and verify they fail on the
current baseline. Then extend the same tests across failed recovery and retry.
Do not resolve these gaps by asserting the current broken result.

### T11: installed adversarial evidence accepts the wrong failures

Source: `tests/vm/adversarial-installed.py:17-32,39-51,71-115`.

The default oracle accepts any exit from 1 through 255, provided stderr contains
no Python traceback and the injection marker is absent. Permission errors,
missing executables/dependencies, and shell-style crash exits can all count as
successful validation. It observes no desired-state digest, service snapshot,
operation journal, or write sentinel other than one injection marker.

The runner uses a fixed generic payload list, despite documentation describing
Hypothesis-generated guaranteed-invalid argv. `protocol-system-test`,
`system-lifecycle`, and `disposable-zfs-lifecycle` entries are skipped but remain
included in the reported `commands` count. The smoke flag only changes report
metadata, not what executes.

Verification: injected exit codes 1, 126, 127, and shell-style 137 all passed the
default rejection oracle. A direct signal-killed child has a negative return
code and would be rejected; the weakness concerns accepted unrelated positive
codes, including wrapper-mapped failures.

Correction: define command-specific rejection contracts and valid baselines
that prove the intended boundary is reachable. Assert diagnostic category and
unchanged state. Generate invalid grammar values rather than spray SQL/XSS at
unrelated command parsers. Report discovered, executed, delegated, and skipped
counts separately; require evidence for delegated lifecycle strategies.

### T12: browser assertions do not cover every claimed surface/control

Sources: `cockpit/e2e/ui-security.spec.mjs:154-179,279-305,366-388` and
`cockpit/e2e/common-xss.spec.mjs:24-79`.

The “every custom UI display surface” corpus opens the overview page only and
requires the hostile value to be visible somewhere. It does not navigate the
six pages or observe every assigned sink. Much of `hostileOverview` changes
retired `featureControl` fields; it does not change the current
`managedServices` labels to the selected corpus value. Some payloads can pass
because a different visible overview string carries them.

The “all visible interactive controls” test checks at most 40 controls on that
page. Its horizontal checks require only intersection with the viewport, not
containment, and it presses Tab once to check focus left the body. A mostly
off-screen control or an unreachable later control satisfies those assertions.

Correction: use current backend fixtures and name each custom sink/page under
test. Navigate each page, exercise editing/confirmation, and check the rendered
value at that sink. Enumerate relevant controls and verify full geometry,
keyboard traversal, focus restoration, and no action after cancellation.
Spend more cases on backend rejection, malformed output, stale revision,
operation conflict, disconnected/reconnected jobs, and mutation failure than
on repeated generic escaping of a single overview page.

## Existing tests worth preserving

- `tests/bats/nas-secret-transaction.bats`: real custom transaction functions,
  failed restart, signals, missing recovery tree/marker, unsafe topology, and
  premature commit, with surviving filesystem/service assertions.
- `tests/test_v2_generation_recovery.py`: calls real custom generation
  publication/cleanup and checks old/current links under injected failures.
- `tests/test_state.py`: archive tampering, unsafe members, restore rollback,
  digest mismatch, subprocess timeout/descendant cleanup, and quiesce stop
  failure. Extend export lifecycle coverage rather than replacing these.
- `tests/test_v2_identity_sync_coverage.py`: project retry policy, read/write
  distinction, non-convergent readback, malformed responses, and rejected paths.
- The installed OCI missing-image rollback drill at
  `tests/vm/guest-test.sh:1193-1208`: observes restored desired and live runtime
  state instead of simulating recovery in a local dictionary.

## Validation and limits

- Deterministic instrumented Python run: **1,496 passed, four skipped, 1,500
  ran across 147 files**. The command used the same eight exclusions as CI's
  fast unit stage: four maintainer/tooling files and four generated-property
  files. Combined coverage: 78.3%; actual branch coverage: 71.5% (3,495/4,888).
- The existing coverage checker passed that report, illustrating T8's mislabeled
  result. No claimed percentage includes shell, Nix, or browser execution.
- Focused existing tests for transaction faults, advertised E2E, non-V2
  functional coverage, and state authority: **44 passed**.
- Isolated oracle challenges reproduced T1/T3/T4/T5/T7/T8/T9/T11. They used
  temporary fixtures and in-memory patches; no product source changed.
- All seven code-defect reproductions from the project audit passed again on
  this baseline, alongside the green deterministic suite.
- Browser-only and installed-system findings above come from full source
  inspection of cited artifacts, not a new browser or VM run. No Nix, native
  QEMU, ZFS, hardware, or full generated-property qualification ran in this audit.
- The first preflight attempt stopped at repository structure because the
  instrumented run left its `.coverage` data file in the checkout. That file was
  removed after exporting the report; `.coveragerc` was preserved. This was audit
  residue, not a new product defect.
- Final preflight passed every executed check, including the deterministic
  Python suite, separate maintainer/tooling stages, 78 JavaScript tests,
  repository/data/documentation/manifest checks, Ruff, Pyright, and ShellCheck.
  It reports **partial** because Nix was explicitly skipped under the documented
  host-store restriction. Documentation links and diff whitespace also passed.

## Correction order

1. Replace false-positive tests/oracles: T1, T2, T3, T4, T8, T11.
2. Add failing regressions for all seven confirmed code defects: T10. Keep
   product remediation separate from this testing audit.
3. Tighten inventories and test scope: T5, T7, T9, T12. Remove independent
   upstream checks in T6 while preserving custom integration boundaries.

### Failure-path acceptance checklist

Use this to assess replacements; it is not a claim that every item is currently
missing. Keep the existing focused cases that already meet it.

- **Input rejection:** malformed, missing, wrong-type, boundary-length,
  case-equivalent, colliding, stale, or unauthorized input must fail before
  mutation. Include valid controls so an always-reject implementation fails too.
- **Dependency failure:** refused connection, timeout, nonzero exit, malformed
  response, lost acknowledgement, and incomplete readback must produce the
  project's intended error and must not commit false success.
- **Partial mutation:** inject failure after each project-owned write, stop,
  link switch, external mutation, and commit boundary. Observe the real files,
  service state, journal, and desired/applied revision before the test repairs
  anything. Include permission, disk-full, replace, and fsync failures where
  the custom code handles those operations.
- **Recovery failure:** fail the compensating write/start/readback as well.
  Require retained recovery material and an explicit manual-recovery outcome;
  never accept a success marker just because the first error was caught.
- **Interruption and contention:** exercise signal death, interrupted retry,
  competing operation ownership, changed authority during reads, and stale CAS.
  Verify lock/resource cleanup and that retry cannot repeat irreversible work.
- **Browser failures:** verify stale/rejected edits remain editable, failed
  operations do not produce success notices, cancellation sends no mutation,
  and reconnect/polling cannot launch duplicate work. Test these custom event
  bindings rather than native DOM or PatternFly behavior in isolation.

All twelve findings remain unremediated. No code/test behavior changed, so this
documentation-only audit needs no release version bump.
