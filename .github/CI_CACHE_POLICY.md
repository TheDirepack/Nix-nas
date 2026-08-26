# CI cache policy

CI caches reusable dependencies and immutable build inputs. It does not cache qualification pass markers.

## Qualification results are never pass-cached

Shared source/test contracts, static/configuration checks, unit/coverage checks, security/Caddy checks, unprivileged hermeticity, Cockpit qualification, browser qualification, QEMU integration, installer checks, and fuzz/security workloads execute on every applicable run. A cache can supply dependencies or an immutable build product, but it cannot replace the check that consumes it.

The qualification layer is split into one shared prerequisite job followed by independent parallel branches. Each branch uses `.github/ci-checks.sh` and `scripts/ci-check-report.py` to continue through its own subchecks, preserve complete logs, annotate exact failures, and fail once after reporting all failures found in that branch. The later qualification gate joins branch outcomes; it is not a cached pass marker.

`npm audit` always queries the current vulnerability database on applicable runs. Cached dependencies may supply its inputs, but no cached result replaces the audit.

## Shared Nix test-tool preparation

The shared prerequisite job installs Nix through `.github/actions/setup-nix-ci/action.yml`, enables the incremental Nix cache, and realizes `nix develop .#test -c true` before qualification fans out.

That realization is intentionally sequential because the static, unit, security, and nonroot branches all use the same pinned test-tool closure. The later runners still install Nix locally, but the expensive package realization is already available through the shared Nix cache instead of being independently resolved cold in every branch.

Branch-specific prerequisites remain branch-local. For example, Node dependencies are not restored by the shared job because only the Cockpit branch needs them at this stage.

## Dependency caches

- `cockpit/node_modules` is keyed by `package-lock.json`, runner operating system, Node major, and `CI_CACHE_SCHEMA`.
- Playwright browser engines are keyed by `package-lock.json`, runner operating system, and `CI_CACHE_SCHEMA`.

Playwright operating-system packages installed by `playwright install-deps` are not cached. Each runner that needs real browser engines installs those host packages locally.

## Cockpit build handoff

The parallel Cockpit qualification branch already owns the exact Node dependency environment needed to validate the UI. It therefore runs source validation, JavaScript tests, the live vulnerability audit, the production build, and `cockpit/build.js --check` in one runner. If that branch qualifies, it publishes `cockpit-bundle`.

The later `prepare` stage downloads that reviewed artifact instead of restoring Node dependencies and compiling Cockpit again. Browser, integration, installer, and installed-system jobs consume the same artifact.

The artifact is not a pass marker. The Cockpit producer runs its own source/tests/audit/build checks, and every downstream consumer still runs the checks appropriate to its layer.

## Verified source archive reuse

The prepare stage caches the source-only archive by the exact commit SHA after package assembly and manifest verification have passed. A later run for the same SHA still checks the restored ZIP before publishing source evidence. A different commit always misses and must execute the producer path.

`prepare` no longer restores `node_modules`, because the production Cockpit bundle arrives as an artifact. This keeps generated dependencies out of the packaging checkout by construction.

This cache contains an immutable archive input, not a remembered qualification result.

## Main coverage baseline data

The unit branch always produces current-branch coverage when its test runner reaches coverage generation. On pull requests targeting `main`, the coverage comparison job depends only on the unit branch, so it can start immediately without waiting for unrelated static, security, nonroot, or Cockpit work.

The comparison checks out the exact main-branch revision. Before measuring an uncached baseline, `scripts/prepare-coverage-baseline.py` targets only the documented stale test-fixture assertions or values. It alters no production source and ignores no test failures.

CI caches `main-coverage.json` by the exact main revision, the baseline-preparation helper hash, runner operating system, and `CI_CACHE_SCHEMA`. On a cache hit the coverage-drift job does not install Nix merely to compare two JSON measurements. Current-branch tests and current coverage generation always run in the unit qualification branch.

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

1. **Shared qualification prerequisites** — validate repository/test contracts and realize the pinned Nix test-tool closure once so later Nix qualification branches can reuse it through the shared cache.
2. **Parallel qualification fan-out** — static/configuration, unit/coverage, security/Caddy, unprivileged hermeticity, and Cockpit qualification run independently. Each branch owns only prerequisites that do not benefit the others and reports all of its subcheck failures before failing.
3. **PR coverage drift** — when applicable, start as soon as the unit branch finishes and compare current coverage with the exact main baseline without waiting for unrelated qualification branches.
4. **Qualification gate** — join the shared prerequisites and every parallel qualification result. Expensive product preparation starts only after the complete inexpensive qualification layer succeeds.
5. **Prepare reusable build handoff** — consume the already-reviewed Cockpit artifact, restore/build the Nix package set once, publish the complete Nix handoff, and produce source-archive evidence.
6. **Browser and QEMU qualification** — one browser runner executes the complete deterministic Playwright suite using Playwright's own internal workers; the two long QEMU integration legs remain separate so they can run in parallel. All three consume prepared products.
7. **Installer qualification** — install from official NixOS media, reboot, and run final-system deterministic browser/security checks while reusing the prepared Nix/Cockpit handoffs.
8. **Final generated/adversarial qualification** — `scripts/run-fuzz.py` owns source-fuzz parallelism inside one runner, while installed-command and ZAP workloads share one provisioned installed appliance and report their independent failures together.

The workflow intentionally splits jobs where parallel execution shortens the critical path or isolation matters, while keeping common prerequisites before the fan-out and branch-only preparation inside the branch that consumes it. It does not create separate runners merely to label individual lint rules, browser greps, or fuzz suites.
