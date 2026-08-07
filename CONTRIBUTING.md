# Contributing

Thank you for improving NixOS NAS. The project favors a small number of clear authorities, explicit recovery behavior, and tests that describe externally visible behavior.

## Before changing code

Read:

1. [`docs/development/invariants.md`](docs/development/invariants.md)
2. [`docs/development/architecture.md`](docs/development/architecture.md)
3. [`docs/development/code-map.md`](docs/development/code-map.md)

Then find the closest existing test and command surface. If a change appears to require a new database, daemon, identity model, share model, secret store, feature registry, or authorization layer, first verify that the existing authority cannot represent it safely.

## Versioning discipline

Documentation-only edits may remain on the current version. Repackaging unchanged source may also retain the current version. Any code-bearing change—including Nix module/configuration logic, Python/shell/JavaScript code, service definitions, tests that change executable qualification behavior, or release/packaging tooling—must increment `VERSION` and add a matching `CHANGELOG.md` entry before publication.

## Development workflow

1. Make the smallest coherent change.
2. Add or update behavior tests.
3. Update operator documentation when behavior or recovery changes.
4. Run `./scripts/preflight.sh`.
5. Run the focused unit/JS tests while iterating, then the full local suites.
6. Run the Nix/QEMU matrix when the change affects Nix evaluation, systemd, storage, networking, boot, installation, or service integration.

Useful commands:

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
node --test tests/js/*.test.mjs
./scripts/preflight.sh
nix develop .#qemu-test -c ./scripts/qemu-test.sh all
```

## Code style

- Python tooling is configured in `pyproject.toml`.
- Cockpit uses React, PatternFly, esbuild, and Sass; keep privileged decisions in `nas-cockpit-api`, not in the browser.
- Nix public options belong under `modules/nas/options/`; implementation belongs under `modules/nas/config/`; reusable private values belong under `modules/nas/internal/`.
- Prefer schemas and generated registries for cross-process contracts.
- Comments should explain non-obvious constraints, not restate the code.

## Documentation style

Write for the person performing a task. Lead with the safe/default path, then explain exceptions and recovery. Use the exact UI label or command name, keep authority ownership explicit, and avoid implementation history in operator pages.

## Security-sensitive changes

Authorization, secrets, storage destruction, restore, and update deployment changes require failure-path tests. Preserve default deny, explicit destructive confirmation, and the cold-boot Cockpit/PAM recovery path.

See [`SECURITY.md`](SECURITY.md) and [`docs/development/known-risks.md`](docs/development/known-risks.md).

## Release claims

Passing local tests is not enough to call a build install-ready. Use [`docs/development/release-checklist.md`](docs/development/release-checklist.md) and retain commit-bound evidence for the qualifying artifact.
