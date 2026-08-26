# CI cache policy

CI caches reusable dependencies and immutable build inputs. It does not cache qualification pass markers.

## Qualification results are never pass-cached

Pre-build source/static/security/Caddy/dependency/coverage checks, browser qualification, QEMU integration, installer checks, and fuzz/security workloads execute on every applicable run. A cache can supply dependencies or an immutable build product, but it cannot replace the check that consumes it.

The pre-build job deliberately keeps its independent sections running after a section fails. `scripts/ci-check-report.py` reports every failed section and the job fails once at the end. This is failure aggregation, not pass caching.

`npm audit` always queries the current vulnerability database on applicable runs. Cached dependencies may supply its inputs, but no cached result replaces the audit.

## Dependency caches

- `cockpit/node_modules` is keyed by `package-lock.json`, runner operating system, Node major, and `CI_CACHE_SCHEMA`.
- Playwright browser engines are keyed by `package-lock.json`, runner operating system, and `CI_CACHE_SCHEMA`.

Playwright operating-system packages installed by `playwright install-deps` are not cached. Each runner that needs real browser engines installs those host packages locally.

## Cockpit build handoff

The `prepare` stage builds and verifies the production Cockpit bundle once for the workflow run, then publishes `cockpit-bundle`. Browser, integration, installer, and installed-system jobs consume that reviewed artifact rather than compiling separate copies.

The artifact is not a pass marker. Every consumer still runs the checks appropriate to its layer, and the producer verifies the compiled bundle before publishing it.

## Verified source archive reuse

The prepare stage caches the source-only archive by the exact commit SHA after package assembly and manifest verification have passed. A later run for the same SHA still checks the restored ZIP before publishing source evidence. A different commit always misses and must execute the producer path.

This cache contains an immutable archive input, not a remembered qualification result.

## Main coverage baseline data

Pull-request coverage comparison checks out the exact main-branch revision. Before measuring an uncached baseline, `scripts/prepare-coverage-baseline.py` targets only the documented stale test-fixture assertions or values. It alters no production source and ignores no test failures.

CI caches `main-coverage.json` by the exact main revision, the baseline-preparation helper hash, runner operating system, and `CI_CACHE_SCHEMA`. On a cache hit the coverage-drift job does not install Nix merely to compare two JSON measurements. Current-branch tests and current coverage generation always run in the pre-build stage.

## Immutable installer media

The installer media cache contains only:

- the downloaded NixOS ISO;
- the remote checksum file; and
- extracted ISO kernel, initrd, and boot options.

Its primary key includes the week, runner operating system, `qemu-test.sh`, the media release, and `CI_CACHE_SCHEMA`. Older weekly entries may restore as download candidates. `qemu-test.sh` obtains the current upstream checksum and removes stale or corrupt media before use.

Never cache mutable VM runtime state, including disks, overlays, PID files, logs used as inputs, temporary users, or credentials.

## Nix outputs and per-run handoff

The full QEMU system closure contains thousands of store paths. Fetching those paths independently on every runner is both slow and capable of exhausting per-path cache traffic. CI therefore separates **cross-run acceleration** from the **authoritative per-run handoff**.

`.github/actions/prepare-vm-handoff/action.yml` is the only place that restores the six granular cross-run bundle caches:

- `core`;
- `identity`;
- `observability`;
- `storage`;
- `ai`; and
- `vm-drivers`.

The action imports restored fragments, builds and exports only missing roots with `scripts/vm-bundles.sh save-missing`, verifies the complete set, and builds the installable NixOS closures. It then saves only bundle-cache misses for future runs.

After that preparation, the action always publishes one complete verified `vm-bundle-handoff` artifact for the current workflow run. Downstream integration, installer, and installed-security runners download that artifact, run `scripts/vm-bundles.sh verify-handoff`, and import it. They do **not** independently restore the six bundle caches or rebuild the package set.

This keeps granular caches where they are useful across runs while making a single immutable artifact the source of truth inside one run. The artifact contains Nix store closures only; it does not contain mutable VM state and does not represent a passed test.

## Pipeline ordering

1. **Pre-build qualification** — one prepared runner executes repository contracts, static/configuration checks, unit/coverage and maintainer contracts, security/Caddy checks, Cockpit source/dependency checks, and unprivileged hermeticity. Independent sections continue after failure so the final report can show all discovered problems.
2. **PR coverage drift** — when applicable, compare current coverage with the exact main baseline even if another pre-build section failed. This lets one CI run expose both ordinary and coverage regressions.
3. **Prepare reusable build handoff** — build Cockpit once, restore/build the Nix package set once, publish the complete Cockpit/Nix handoffs, and produce source-archive evidence.
4. **Browser and QEMU qualification** — one browser runner executes the complete deterministic Playwright suite using Playwright's own internal workers; the two long QEMU integration legs remain separate so they can run in parallel. All three consume prepared products.
5. **Installer qualification** — install from official NixOS media, reboot, and run final-system deterministic browser/security checks while reusing the prepared Nix/Cockpit handoffs.
6. **Final generated/adversarial qualification** — `scripts/run-fuzz.py` owns source-fuzz parallelism inside one runner, while installed-command and ZAP workloads share one provisioned installed appliance and report their independent failures together.

The workflow intentionally keeps separate jobs only where isolation, event gating, or long-running parallelism provides a real benefit. It does not create separate runners merely to label individual lint rules, browser greps, or fuzz suites.
