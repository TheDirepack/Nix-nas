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

## Pipeline ordering

1. Pre-build source/static/security/Caddy/dependency/coverage qualification.
2. On one runner, the `build` job sequentially materializes and verifies Cockpit (compiling it on a cache miss), round-trips the source archive, and builds the NixOS closures.
3. Downstream browser and KVM/QEMU integration jobs test the built artifacts.
4. Install/reboot the official ISO and run final-system deterministic browser/security checks.
5. Only after deterministic qualification passes, run slow source/property/browser and live ZAP fuzzing.

Slow browser qualification repeats the deterministic XSS/layout/formatting/accessibility corpus before hostile-input fuzzing. Final-VM fuzzing runs the full deterministic authenticated and unauthenticated Playwright suite before ZAP.
