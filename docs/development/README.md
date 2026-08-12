# Development guide

This directory documents how the appliance is built and validated. It is intentionally separate from `docs/src/`, which is written for the person operating an installed NAS.

## Start here

- [Architecture](architecture.md) — major components, trust boundaries, and data flow.
- [Non-negotiable invariants](invariants.md) — rules that code and configuration must preserve.
- [Code map](code-map.md) — where a change belongs.
- [Testing and validation](testing.md) — local, NixOS, VM, browser, and hardware validation.
- [Known risks](known-risks.md) — unresolved multi-step failure boundaries and recovery expectations.
- [Dependency policy](dependencies.md) — immutable-input and upstream-update constraints.
- [Release qualification checklist](release-checklist.md) — evidence required before an install-ready designation.

Historical context lives in [decision history](history.md). Release-specific implementation records are evidence, not design documents.

## Repository shape

```text
modules/       NixOS options, implementation fragments, internal registries
services/      privileged appliance commands and pure control-plane models
cockpit/       React/PatternFly Cockpit package (build via `npm --prefix cockpit ci && npm --prefix cockpit run build`)
schemas/       cross-process JSON schemas (V3 at `schemas/managed-services-v3.schema.json`)
scripts/       validation, packaging, update, and VM tooling
tests/         unit, contract, browser, NixOS, and guest tests
./tmp/         local packaging/VM artifacts (inside project, not /tmp; ignored)
docs/src/      deployed operator manual
docs/operator/ long-form recovery/operations runbooks
docs/development/ maintainer architecture and validation material
```

## Normal workflow

1. Identify the owning subsystem in [code-map.md](code-map.md).
2. Check [invariants.md](invariants.md) before changing an authority or privilege boundary.
3. Add the behavior/failure test that should protect the change.
4. Make the smallest coherent implementation change.
5. Update the operator manual when a user-visible workflow, default, or recovery path changes.
6. Run `./scripts/preflight.sh` and the focused tests.
7. Run the Nix/QEMU tiers required by [testing.md](testing.md).

## Documentation policy

Keep one current explanation of each concern:

- `README.md`: product overview and first-install entry point.
- `CONTRIBUTING.md`: contributor workflow and quality expectations.
- `AGENTS.md`: compact coding-agent handoff.
- `docs/src/`: installed operator/user manual.
- `docs/operator/`: detailed repository runbooks for recovery and command-oriented operation.
- `docs/development/`: architecture, risks, code map, dependency policy, validation, and release evidence.
- `CHANGELOG.md`: user-visible changes by release.

Do not keep raw audit transcripts, duplicated implementation plans, or stale review prose in active operator documentation.

## Comment policy

Executable comments explain only local constraints that would otherwise be easy to break: security, concurrency, kernel behavior, upstream compatibility, or generated-file semantics. Architecture and rationale belong here; user workflows belong in `docs/src/`.

Useful supporting records:

- [External validation](external-validation.md)
- [Privileged-service audit](root-service-audit.md)
- [Combined Alpha 18/20 remediation register](combined-review-remediation.md)
- [Alpha.24 implementation record](alpha24-implementation.md)
- [Alpha.2 audit remediation](alpha2-remediation.md)
- [Alpha.3 audit remediation](alpha3-remediation.md)
