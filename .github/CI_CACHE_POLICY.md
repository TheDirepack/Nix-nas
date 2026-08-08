# CI cache policy

The CI pipeline uses caches only when the cached bytes or pass result can be invalidated by every input that can change their correctness.

## Cache classes

### 1. Dependency caches

Safe to restore across jobs when their lockfile and runtime ABI are part of the key.

- `cockpit/node_modules`: keyed by `package-lock.json`, runner OS, Node major and `CI_CACHE_SCHEMA`.
- Playwright browser engines: keyed by `package-lock.json`, runner OS and `CI_CACHE_SCHEMA`.
- Nix store paths: handled by Magic Nix Cache/Nix content addressing. The cache is enabled only after a higher-level result cache misses.

Do not cache Playwright OS packages installed by `playwright install-deps`; those mutate the runner image and are cheap relative to browser downloads.

### 2. Immutable build-output caches

Safe when all source/build inputs are in the key.

- `cockpit/dist`: package lock/package metadata, build script and all Cockpit source files.
- Nix derivation outputs: content-addressed by Nix and transferred through the Nix cache.
- Source release archives: all release-packaged repository inputs plus manifest logic.

A build pass marker never substitutes arbitrary bytes. Downstream Nix jobs still request the required derivations from the content-addressed store/cache.

### 3. Deterministic qualification-result caches

These may be content-addressed without a time epoch when the check is fully deterministic and the toolchain is pinned by repository inputs.

- source/unit qualification
- Ruff/Pyright/ShellCheck/Prettier/Nix evaluation
- local Semgrep/Bandit/security regression rules
- generated Caddy adaptation/validation
- source archive round-trip
- NixOS closure build result

Every key includes `CI_CACHE_SCHEMA`. Increment it whenever the runner/runtime assumptions or the meaning of a qualification changes in a way not already represented by hashed inputs.

### 4. Runtime/browser/VM/fuzz result caches

These expire weekly in addition to hashing source/test inputs because they depend on runtime behavior, browser engines, virtualization, timing, external scanner behavior or intentionally long stochastic/property exploration.

- non-root hermeticity
- deterministic browser rendering/accessibility
- QEMU integration
- official installer/final-system qualification
- source/property fuzz shards
- slow browser fuzz

The installer/final-system key also includes `NAS_ZAP_IMAGE`, so changing the scanner image invalidates the pass marker.

### 5. Fresh checks that must not be pass-cached

Checks whose result can change without a repository change must query their upstream source each run.

- `npm audit` vulnerability database lookup

Dependencies used to perform the query may still be cached.

## VM and installer data

Never cache mutable VM runtime state:

- `state/*.qcow2`
- disposable overlays
- installed OS disks
- data disks
- VM PID/state files
- runtime logs as reusable inputs
- temporary test users or credentials

The installer media cache is intentionally limited to:

- downloaded NixOS ISO
- remote checksum file
- extracted ISO kernel/initrd/options

The media cache has a weekly key. `qemu-test.sh` re-fetches the current upstream checksum and rejects/removes a stale or corrupt ISO before use.

## Cache ordering

A higher-level qualification cache is always restored **before** installing Nix, enabling Magic Nix Cache, installing browser dependencies or performing expensive setup. On an exact pass-cache hit those setup actions are skipped entirely.

This is why a cached Caddy/security/build job should not show an incremental Nix-cache post hook: Magic Nix Cache was never started.

## Pipeline ordering

1. Pre-build source/static/security/Caddy/dependency/coverage qualification.
2. Build Cockpit, source-release and NixOS artifacts.
3. Test built artifacts with deterministic browsers and QEMU integration.
4. Install/reboot the official ISO and run final-system deterministic browser/security checks.
5. Only after deterministic qualification passes, run slow source/property/browser and live ZAP fuzzing.

Slow browser qualification repeats the deterministic XSS/layout/formatting/accessibility corpus before hostile-input fuzzing. Final-VM fuzzing likewise runs the full deterministic authenticated and unauthenticated Playwright suite before starting ZAP.
