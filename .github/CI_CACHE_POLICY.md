# CI cache policy

CI caches reusable dependencies and outputs. It does not cache qualification pass markers.

## Qualification results are never pass-cached

Source/static/security/Caddy/archive/build/browser/QEMU/installer/fuzz qualification results are never pass-cached and execute on every applicable run. This includes unit and coverage checks, lint and type checks, local security scans, Caddy validation, source archive round-trips, NixOS builds, browser suites, virtual machine tests, installer checks, and fuzz shards.

The dependency audit also runs `npm audit` against the current vulnerability database on every applicable run. Cached dependencies may supply its inputs, but no cached result can replace the audit.

## Dependency caches

- `cockpit/node_modules` is keyed by `package-lock.json`, runner operating system, Node major, and `CI_CACHE_SCHEMA`.
- Playwright browser engines are keyed by `package-lock.json`, runner operating system, and `CI_CACHE_SCHEMA`.

Playwright operating-system packages installed by `playwright install-deps` are not cached. Each applicable browser job installs them on its runner.

## Cockpit distribution cache

`cockpit/dist` is keyed by the package lock, package metadata, build script, Cockpit source files, runner operating system, Node major, and `CI_CACHE_SCHEMA`. A hit can skip compilation, but it cannot skip qualification. The workflow always verifies `cockpit/dist` with `node cockpit/build.js --check` before uploading the artifact.

## Main coverage baseline data

Pull-request coverage comparison checks out the exact main-branch revision. Before measuring an uncached baseline, `scripts/prepare-coverage-baseline.py` targets exactly four known stale assertions or values in test-only fixtures. It alters no production source and ignores no test failures. The full fast baseline test run must pass before CI compares coverage.

CI caches `main-coverage.json` by that exact main revision, the baseline-preparation helper hash, runner operating system, and `CI_CACHE_SCHEMA`. The cache remains measurement data only. It does not replace current-branch tests, current coverage generation, or the per-file drift check.

## Immutable installer media

The installer media cache contains only:

- the downloaded NixOS ISO;
- the remote checksum file; and
- extracted ISO kernel, initrd, and boot options.

Its primary key includes the week, runner operating system, `qemu-test.sh`, the media release, and `CI_CACHE_SCHEMA`. Older weekly entries may restore as download candidates. `qemu-test.sh` fetches the current upstream checksum and removes stale or corrupt media before use.

Never cache mutable VM runtime state, including disks, overlays, PID files, logs used as inputs, temporary users, or credentials.

## Nix outputs

Nix derivation and virtual machine outputs use Nix content addressing and the incremental Magic Nix Cache. Jobs still request and verify their required derivations. Cached store paths reduce rebuild work; they do not represent qualification passes.

## Nix store bundles

The full QEMU VM system closure contains thousands of store paths; fetching them individually through the Magic Nix Cache trips GitHub's per-path cache rate limit and can force a from-source build of the entire system. The `build` job resolves bundle keys and restores the base NixOS core plus each top-level application before building the configuration. It imports those archives (`scripts/vm-bundles.sh import`) and then runs the ordinary NixOS closure builds, so unchanged package versions are already present when the configuration delta is assembled.

The producer restores only archives already in the cache and exports the missing archives once (`scripts/vm-bundles.sh save-missing`). It then uploads the exact complete bundle set used by that build as the short-lived `vm-bundle-handoff` artifact. Every integration VM downloads that handoff and re-imports the same files; it never re-exports or rebuilds a bundle for its matrix entry. A separate cache-persistence job saves only the archives that were cache misses, so the next workflow run can restore them without delaying the current VM matrix. Each non-core key also includes the exact core-root hash because application archives are stored as deltas against that base. The versioned package bundles are separate from the `vm-drivers` bundle, whose roots contain the config-sensitive NixOS test drivers. This means a config-only change can reuse the package archives and regenerate only the small system/driver delta. Bundles are immutable store closures only. They never stand in for a qualification pass, and the integration job always builds and runs both VM checks.

## Pipeline ordering

1. Pre-build source/static/security/Caddy/dependency/coverage qualification.
2. On one runner, the `build` job sequentially materializes and verifies Cockpit (compiling it on a cache miss), round-trips the source archive, builds the NixOS closures, and publishes one exact bundle handoff.
3. Downstream browser and KVM/QEMU integration jobs test the built artifacts; the independent cache-persistence job stores any newly created bundle archives for future runs.
4. Install/reboot the official ISO and run final-system deterministic browser/security checks.
5. Only after deterministic qualification passes, run slow source/property/browser and live ZAP fuzzing.

Slow browser qualification repeats the deterministic XSS/layout/formatting/accessibility corpus before hostile-input fuzzing. Final-VM fuzzing runs the full deterministic authenticated and unauthenticated Playwright suite before ZAP.
