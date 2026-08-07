# Coding-agent guide

Use this as the compact handoff for making changes. Current requirements live in code, tests, and the documents linked below; historical release notes do not define desired behavior.

## Read in this order

1. [`docs/development/README.md`](docs/development/README.md) — repository shape and workflow.
2. [`docs/development/invariants.md`](docs/development/invariants.md) — authority, security, storage, and recovery rules that must not drift.
3. [`docs/development/architecture.md`](docs/development/architecture.md) — control-plane boundaries and data flow.
4. [`docs/development/code-map.md`](docs/development/code-map.md) — where each subsystem lives.
5. The tests covering the subsystem you intend to change.
6. [`docs/development/known-risks.md`](docs/development/known-risks.md) when touching setup, identity, secrets, state restore, updates, or other multi-step privileged workflows.

Use `CHANGELOG.md` and `docs/development/history.md` only when historical context is actually needed.

## Quality gates

```bash
./scripts/preflight.sh
python3 -m unittest discover -s tests -p 'test_*.py'
node --test tests/js/*.test.mjs
nix develop .#qemu-test -c ./scripts/qemu-test.sh all
```

The QEMU command requires Linux, Nix, QEMU/KVM, and network access for the installer image.

## Change rules

- Preserve the authority boundaries in `docs/development/invariants.md`.
- Prefer an existing registry, schema, command, or upstream UI over creating another source of truth.
- Add behavioral coverage before changing authorization, storage, secrets, or root-privileged paths.
- Keep generated/runtime state, credentials, VM disks, and local installation configuration out of the repository.
- Put operator instructions in `docs/src/` and implementation guidance in `docs/development/`.
- Record stable external dependency constraints in `docs/development/dependencies.md`; do not add release-by-release prose beside executable code.
- Run `./scripts/preflight.sh` before packaging.

## Comment policy

Comments are for constraints that are not obvious from names, types, or control flow: security boundaries, concurrency rules, kernel behavior, upstream compatibility, or generated-file requirements. Keep them local and concise.

Do not use comments to narrate code, preserve review history, list rejected alternatives, or duplicate architecture documentation. Keep machine directives such as shebangs, `noqa`, schema hints, and Renovate annotations intact.

## Packaging

Release archives contain the source tree, `VERSION`, `CHANGELOG.md`, and a regenerated `MANIFEST.sha256`. Human-facing filenames follow [`docs/development/artifact-naming.md`](docs/development/artifact-naming.md); `VERSION` remains canonical. Documentation-only edits and rerunning unchanged packaging may keep the current version, but every code/Nix/script/UI/test/release-tooling behavior change requires the next version before publication. Normal development preflight does not require a current manifest; release validation uses:

```bash
NAS_PREFLIGHT_VERIFY_MANIFEST=1 ./scripts/preflight.sh
```

Install-ready packaging additionally requires the exact Cockpit lockfile and compiled distribution plus all qualification evidence in `docs/development/release-checklist.md`.
