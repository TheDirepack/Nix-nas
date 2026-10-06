# Project audit: 2026-10-03

## Result and scope

Historical snapshot. Source corrections and current qualification limits are in
[Audit remediation: 2026-10-04](audit-remediation-2026-10-04.md).

Eight findings remain open: one high, six medium, and one low. Seven have isolated
reproductions; the eighth is a documentation contradiction. No runtime code,
configuration, production state, or VM state changed during this audit.

Baseline: `c4628a95815b0f56522aba30abae5345b2c04962`.

This is a targeted source audit, not whole-project security certification.
Severity describes impact under the stated preconditions, not evidence of active
exploitation. The socket-collision security impact needs a live proxy/activation
test; the generated collision itself is confirmed.

## Project understanding

NixOS NAS combines ZFS, CopyParty, Authentik, Cockpit, and KeePassXC. NixOS owns
packages, units, listeners, and immutable defaults. Authentik owns people and
capability membership; CopyParty owns file policy. `nas-secrets` stages machine
credentials under `/run` after KeePassXC unlock and storage validation.

Managed Services V2 uses a V3 JSON Schema and one mutable `services.yaml` file.
The compiler normalizes and validates it, then generates native systemd/Quadlet,
Caddy, Authentik, firewall, and backup projections. Finite reconciliation and
Git-backed rollback replace a resident application supervisor. Cockpit calls
privileged commands; the setup wizard uses a permissioned Unix-socket API.

The recovery boundary is local console, SSH recovery access, or hardware KVM.
Authentik administration and Linux/PAM administration are separate authorities.
State bundles cover control configuration; ZFS/Restic/native backup cover other
failure domains.

Audit phases:

1. Read architecture, invariants, subsystem map, testing guide, and risk register.
2. Trace route authorization, activation naming, desired/effective status,
   native systemd reconciliation, setup API, and state export/restore.
3. Reproduce suspected defects without invoking host service management, run
   source/security tests and npm advisory checks, and record qualification gaps.

The deepest review covered `nas_v2_spec.py`, `nas_v2_caddy.py`,
`nas_v2_activation.py`, `nas_v2_apply.py`, `nas_v2_editor.py`,
`nas_v2_systemd_native.py`, `nas_v2_systemd_attachments.py`,
`nas_v2_systemd_reconcile.py`, `nas_v2_control.py`, `nas_cockpit_api.py`,
`nas_state.py`, and their intersecting Nix/frontend wiring and tests. Identity
sync internals, secret shell workflows, firewall packet behavior, backup
adapters, updates, GPU/VM adapters, and all frontend interactions did not receive
an exhaustive review. Passing tests in those areas are not audit clearance.

## Findings

| ID | Severity | Finding | Evidence |
|---|---|---|---|
| F1 | High | Distinct on-demand routes share an activation socket and proxy unit | Compiled projection reproduction |
| F2 | Medium | Valid Compose services appear unverified and unavailable | Status reproduction |
| F3 | Medium | State export ignores the configured empty quiesce list | Environment/projection reproduction |
| F4 | Medium | Database export preparation failure skips service recovery | Failure injection; database registry only |
| F5 | Medium | Header-name casing bypasses the static trusted-identity guard | Generated configuration reproduction |
| F6 | Medium | Failed active on-demand restart still commits reconcile state | Subprocess-boundary failure injection |
| F7 | Medium | Valid identifiers produce unusable Unix socket paths | Compiler plus Linux socket bind |
| F8 | Low | Public overview and security docs contradict current recovery/access rules | Source/document comparison |

### F1: activation names are ambiguous

Sources: `services/nas_v2_activation.py:25-38`,
`services/nas_v2_systemd_native.py:790-803`, and
`services/nas_v2_caddy.py:182-191`.

Both IDs permit hyphens. Joining service and route with a hyphen maps
`(a, b-c)` and `(a-b, c)` to the same
`nas-v2-activate-a-b-c.{socket,service}` and `a-b-c.sock`. The compiler accepts
these distinct routes. Native projection stores files in a dictionary, so the
later service overwrites the earlier proxy unit. Caddy points both routes at
the same socket.

Reproduction: configure identity-protected `/first` for service `a`, route `b-c`,
port 8001, and `/second` for service `a-b`, route `c`, port 8002. Use on-demand
daemon workloads with `idleSeconds: 60`, native systemd runtimes, and default
hidden portal entries. Compilation succeeds. Projection contains one activation
proxy targeting 8002, while both Caddy handlers use the shared socket.

Impact: a request authorized for the first service can reach the second
service's backend. Native backend authorization may limit damage; it does not
repair the edge's wrong destination. If both routes have visible portal entries,
the Authentik adapter can reject its own colliding application slug, so the
reproduced case deliberately uses the schema's hidden-portal default.

Remediation: use an injective, bounded canonical naming mechanism and reject
collisions across generated unit names before populating dictionaries. Test
multiple services/routes with hyphens, including differing capability grants,
then verify the authorized backend in a disposable installed VM.

### F2: Compose owner-unit mismatch breaks status

Sources: `services/nas_v2_spec.py:985-993` and
`services/nas_v2_editor.py:219-226,284-289`.

The compiler assigns Compose `nas-v2-<id>.target`; the editor expects
`nas-v2-<id>.service`. `_is_valid_effective_service` rejects a current, valid
effective document even when its provenance hash matches the desired bytes.

Reproduction: compile a minimal Compose daemon with source
`/var/lib/nas-control/apps/demo/compose.yaml`, save its effective JSON with the
correct `desiredSha256`, then call `editor.status`. The compiler's owner is
`nas-v2-demo.target`, but status returns `verified=false`,
`runtimeAvailable=false`, and no units. This reproduction does not require an
actual Compose source because it tests compilation/status, not native import.

Impact: Compose health/status is misleading; Compose jobs cannot satisfy
Cockpit's verified-job admission checks.

Remediation: share the compiler's canonical runtime-to-owner mapping. Add
status coverage for all runtime types, not only compiler/editor round trips.

### F3: small control-state exports stop the application stack

Sources: `services/nas_state.py:676-730,770-774` and
`modules/nas/internal/account-tools.nix:162-165,189`.

The installed wrapper specifies `NAS_STATE_QUIESCE_UNITS_JSON=[]`, explaining
that its small file authorities need no database/application shutdown. The
Python helper first reads effective state and returns a hard-coded identity,
PostgreSQL, Caddy, and managed-owner list. It consults the explicit policy only
when effective-state loading fails.

Reproduction: point `NAS_V2_EFFECTIVE` at
`{"services":{},"derived":{"runtime":{}}}` and set the quiesce policy to
`[]`. The result still contains six units, including Caddy and PostgreSQL.

Impact: ordinary configuration exports, including guarded-update snapshots,
can interrupt browser access and unrelated applications. The reproduction
verified the unit selection without stopping any real unit.

Remediation: honor the installed registry's explicit quiesce policy before
fallback discovery. Test both an empty policy and a nonempty generated policy
while valid effective state exists.

### F4: database preparation is outside export's recovery scope

Source: `services/nas_state.py:741-746,770-775,851-853`.

After stopping active units, export calls `prepare_database_export` before
entering the `try/finally` that restores the unit snapshot. An inactive prior
PostgreSQL state or a failed PostgreSQL start raises before that recovery runs.

Reproduction: inject a database authority and a snapshot with an active
application but inactive PostgreSQL. Export calls `stop_active_units`, raises
`PostgreSQL was not active before state export quiesce`, and never calls
`restore_unit_state`.

Impact: a failed export can leave applications stopped. The current installed
small registry contains no database authority, so this finding concerns the
supported database-registry/development path, not every production export.

Remediation: put post-snapshot preparation inside the recovery scope. Cover
inactive PostgreSQL, failed restart, and failed subsequent export separately.

### F5: identity-header validation is case-sensitive

Source: `services/nas_v2_caddy.py:47,163-165,222-223,250`.

HTTP header names are case-insensitive
([RFC 9110, section 5.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.1)),
but the forbidden static-header set uses exact spelling.
`requestHeaders: {Remote-User: admin}` fails; the equivalent
`requestHeaders: {remote-user: admin}` passes. The generated handler strips
`Remote-User`, then reintroduces `remote-user "admin"` before proxying.

Reproduction: compile a persistent public route with that lowercase static
header and generate its Caddyfile. Generation succeeds and includes the
identity assignment after stripping.

Impact: the configuration safety guard fails to enforce its trusted-identity
constraint. This requires an authorized desired-state edit; it is not evidence
that an unauthenticated HTTP client can forge identity. No live Caddy request
was exercised in this audit.

Remediation: compare normalized case-insensitive header names. Test mixed-case
variants of the full forbidden set and verify an upstream receives only the
intended authenticated identity in the installed proxy test.

### F6: active nonpersistent restart failures are ignored

Sources: `services/nas_v2_systemd_reconcile.py:488-511` and
`modules/nas/config/managed-services-transactions.nix:235-248`.

For changed owned units outside `startUnits`, the reconciler uses
`try-restart(..., check=False)` and ignores its return code. Active on-demand
owners fall into this branch. The reconciler persists new hashes/fingerprints
even if systemd reports restart failure; the outer transaction can then mark
the desired revision applied.

Reproduction: stage a changed owned service with no persistent start entry.
Mock `is-active` as active and `try-restart` as exit 1. Reconciliation returns
without error and writes its new state JSON.

Impact: failed application updates can appear applied without entering guarded
rollback. The application may be failed or retain old runtime semantics,
depending on the native restart failure. Those live outcomes were not measured.

Remediation: distinguish inactive no-op from an active restart failure, and
propagate the latter. Test both branches and confirm the outer rollback with a
running on-demand application in a disposable VM.

### F7: schema-valid IDs exceed Linux Unix-socket limits

Sources: `services/nas_v2_spec.py:32-33`,
`services/nas_v2_activation.py:15,37-38`, and
`services/nas_v2_systemd_native.py:470`.

A 64-character service ID and 64-character route ID generate a 160-byte socket
pathname. Linux pathname sockets have a 108-byte `sun_path` buffer, including
the terminating NUL. Neither semantic validation nor naming rejects this pair.

Reproduction: compile an on-demand daemon with service `"a" * 64` and route
`"b" * 64`. Compilation and Caddy generation succeed. Binding the generated
pathname using Python's `AF_UNIX` socket raises `AF_UNIX path too long` before
creating any filesystem entry.

Impact: a structurally valid service configuration cannot activate. This is
independent of F1's collision, but both need one bounded naming solution.

Remediation: derive socket names with a bounded collision-resistant encoding
and enforce platform path limits. Test maximum-length valid identifiers.

### F8: operator-facing overview retains obsolete guarantees

Sources: `README.md:10,13,29-30,51-53`, `SECURITY.md:24-30`,
`docs/development/invariants.md:18-26`, and
`services/nas_v2_caddy.py:130-143`.

The README promises cold-boot Cockpit/PAM browser recovery and fresh CLI setup.
Current invariants forbid browser management while locked, and the risk register
records that command-only fresh setup is unavailable. `SECURITY.md` still
describes `nas_allow_*`/`nas_deny_*` route policy and a removed AI integration;
the V2 route projector checks `application.<service>.<capability>` or `nas_admin`.
The invariants' authorization section also retains the old `nas_allow_*` rule.
The later locked-state section in the security document contradicts the
README's promise.

Impact: operators can prepare the wrong recovery access or follow obsolete
permission instructions. This finding does not establish a deny-group bypass
in a live Authentik installation; that would require auditing its full policy.

Remediation: align public setup/recovery/access instructions with the current
code and canonical invariants. Preserve out-of-band recovery requirements.

## Validation evidence

- Seven isolated reproduction checks completed with the outcomes above. Host
  service-management calls were mocked; F7 used a real Linux socket API.
- `node --test tests/js/*.test.mjs`: 78 passed after locked Cockpit dependencies
  were installed. The first attempt failed because esbuild was absent; this was
  an environment prerequisite, not a frontend defect.
- `./scripts/run-security-tests.py`: all four checks passed. Its browser check
  validates spec syntax, not a live browser or appliance.
- `./scripts/security-static-scan.py`: passed.
- Cockpit and first-run-wizard `npm audit --json`: zero reported advisories
  on 2026-10-03. This covers those npm lockfiles, not Nix closures or OCI images.
- Initial preflight's deterministic Python stage: 1,496 passed, 1,500 ran,
  four skipped across 147 files. Maintainer core and matrix also passed. The
  release fixture then failed while copying a changing `.hypothesis` cache
  produced by concurrent direct discovery. This run is not a preflight pass.
- Direct `unittest discover` was stopped to prevent that cache interference;
  it is not claimed as passing. Generated property suites are separate from
  the deterministic preflight suite.
- Final preflight with external Hypothesis storage and `NAS_PREFLIGHT_SKIP_NIX=1`:
  all executed checks passed; the script reports **partial**, not full, preflight
  because Nix evaluation was skipped. Deterministic Python: 1,496 passed and four
  skipped across 147 files. Separate maintainer core/matrix/release and tooling
  stages passed another 49 tests. JavaScript: 78 passed. Repository, documentation
  links, manifest generation/verification, static security, syntax, Ruff,
  formatting, Pyright, and ShellCheck checks passed.
- The all-files isolated Python run (`--timeout 60 --jobs 4`) was unsuccessful:
  1,543 tests passed and four skipped; `test_fuzz_custom_inputs.py`,
  `test_fuzz_boundaries.py`, and `test_maintainer_release.py` exceeded the imposed
  60-second per-file limit. This does not establish a product defect. The final
  preflight's separate release stage passed all 13 tests in 69.7 seconds under
  its larger budget. Generated-property qualification remains incomplete.

No Nix evaluation, closure build, installed QEMU qualification, browser-engine
test, ZFS operation, or hardware drill ran for this checkout. Another session
was using the shared VM cache/ports, and this audit did not interfere with it.
Do not use that session's results as evidence for this baseline. Host Nix was
not retried, following the repository's host-store restriction.

For native follow-up, use the documented QEMU wrapper with a dedicated cache,
state directory, and unused SSH/HTTPS ports. Run the installed suite and the
F1/F5 request tests before claiming security closure.

## Remaining work

All eight findings remain unremediated. Address F1 first, share its bounded
naming work with F7, then fix false-success/recovery behavior in F6/F3/F4.
Follow with F2, F5, and the operator documentation in F8. Add failing behavioral
tests before changing authorization or privileged behavior. No release/version
bump is needed for this documentation-only audit.
