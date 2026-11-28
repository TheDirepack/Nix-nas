# Port evaluation: KeePass secret system in Zig

This evaluates the Zig port of `nas-secrets`, `nas-unlock-api`, and the KeePass setup helper for comparison with the Go port. The current design and requirements are in [architecture.md](architecture.md) and [invariants.md](invariants.md).

The port uses Zig 0.17.1 and its standard library. [Zig release downloads](https://ziglang.org/download/)

## Type-system wins

| Requirement | Mechanism | Enforced by |
|---|---|---|
| Formatted output and JSON reject secrets | `Secret.format` and `Secret.jsonStringify` use `@compileError`. Generic `{any}` formatting can show the opaque pointer address. | `zig build compile-errors` (`secret_format`, `secret_json`) |
| Secrets never reach argv | `command.argv` inspects every tuple element at comptime and rejects any type that is, points to, or contains a `Secret` (including `StrongKeePassPassword`) | `secret_argv`, `password_argv` |
| sudo never consumes payload stdin | `Runner.privileged` has no payload parameter and always gives the child /dev/null | `privileged_payload` |
| Invalid transaction transitions | `Staged`, `Swapped`, `SwapFailed`, `Committed`, `RolledBack`, … are distinct types that expose only their legal methods | `staged_commit`, `committed_rollback` |
| Setup vs post-setup | `PostSetupSlot(.setup)` is `void`; link, outpost install and plaintext retirement take `PostSetup`, `Rotated` and `transaction.Committed` witnesses | `setup_mode_link` |
| Exhaustive outcomes | `Activation` is a tagged union, `Rejection` a closed error set; both map to HTTP through exhaustive `switch` | `outcome_exhaustive` |
| Feature gating | the host's options become a comptime ZON config; disabled services' staging code is not compiled, and relative paths or control characters fail the build | `config.zig` comptime block |
| Wiping | `ZeroingAllocator` is a distinct type, `secureZero`s on free/shrink and refuses `remap`, so moved buffers are wiped too | unit tests with `std.testing.allocator` (leak-checked) |

Explicit error sets are used throughout. The only `anyerror` is the signature that `std.testing.fuzz` imposes on fuzz callbacks.

## Limits

- **Field access.** Zig exposes struct fields. Constructor-only use of `AdminSession`, `UnlockRequest`, and other validated types relies on module conventions and source checks in `tests/test_secret_security.py`. A pointer cast can bypass the opacity of `Secret`.
- **Validation callbacks.** `Secret.satisfies*` lends a byte slice to a caller-supplied function. The compiler cannot prevent the function from retaining or copying it. Review callback call sites as part of the secret boundary.
- **Transaction ownership.** Zig permits copying transaction values. The runtime phase guard in `Context` rejects a second swap through a copied handle. Activation exit paths explicitly handle commit and rollback.
- **Lifetimes.** Black-box tests caught a `Payload` retaining a slice into an expired stack frame. Payload parts now have a comptime size bound and are stored by value.
- **Secret sinks.** Activation writes systemd environment files through `PrivateFile` in a verified 0700 directory. Existing `show-*` commands use explicit `RevealGrant` values for stdout, including ZFS key handoff.
- **Process memory.** The binaries disable core dumps with `PR_SET_DUMPABLE=0`. Secret buffers remain eligible for swap.
- **Coverage.** `tests/test_zig_contracts.py` checks the leak-tested module list, parser fuzz targets, and compile-error wiring. Zig execution is outside the Python branch-coverage report.
- **Fuzzing.** CI runs the seed corpus. `zig build test --fuzz` starts continuous fuzzing on a developer machine.
- **Behaviour changes.** A timed-out unlock sends SIGTERM to give `nas-secrets` time to roll back. KDBX move-aside uses the kernel's atomic `renameat2(RENAME_NOREPLACE)`. Rollback preserves its recovery tree if it cannot remove the live root.

## Version churn cost

0.16 replaced most of `std.posix` with `std.Io`, and 0.17 changed more. Items hit while writing this port, each a compile error rather than a silent change:

- `std.process.Init` "juicy main", `Io` threaded through spawn/sleep/random; `process.spawn` replaces `ChildProcess.init`; `File.MultiReader` for concurrent capture with timeouts.
- `@typeInfo(T).@"struct"` now has parallel `field_names`/`field_types` arrays (no `fields`); `std.meta.fields` is a compile error.
- Array repetition `**` was removed (use `@splat`).
- Optimize modes renamed to `.debug`/`.safe`/…; with a preferred mode the build exposes `-Drelease` rather than `-Doptimize`.
- `Allocator.dupeZ` became `dupeSentinel`; `std.os.linux.LOCK`/`ucred` are gone; most POSIX socket wrappers are gone, so `src/sys.zig` (≈250 lines) talks to `std.os.linux` with a closed error set.
- nixpkgs 26.05 only has Zig 0.16, so the compiler is pinned from the upstream tarball (`modules/nas/internal/zig-toolchain.nix`).
- Test discovery no longer reaches modules only referenced from `main`; `src/tests.zig` imports each module explicitly.

Expect a similar sweep on every minor release until 1.0. The black-box Python tests are the stable contract across those bumps.

## Size

Production Zig, excluding tests, blank lines and comments: about 3,800 lines. That includes a syscall layer, a minimal HTTP/1 server and a comptime Unicode case-folding table, which Python and bash supplied for free. It replaces 757 lines of shell-in-Nix, 407 lines of shell libraries, 324 code lines of Python (`nas_unlock_api.py`) and about 120 lines of KeePass code in `nas_setup.py`. `secret-tools.nix` is now about 120 lines of configuration rendering.

Release binaries (`-Drelease`, static, stripped, x86_64): `nas-secrets` about 660 KB, `nas-unlock-api` about 460 KB, `nas-keepass-setup` about 475 KB. The `nas-secrets` closure no longer needs bash, python3, jq, openssl, libargon2, apacheHttpd (htpasswd), findutils, grep, sed or util-linux. It still calls keepassxc-cli, coreutils, curl, sudo and systemctl.

The installed `nas-preflight` command also carries the pinned compiler to build
the black-box fixtures from the checked-out source. Activation and unlock use
only their compiled executables at runtime.

## Tests

- Black-box Python suites run against the real binaries: `test_nas_secrets.py` (activation, rotation, rollback, SIGTERM, setup mode, coordinator, no secret in any argv), `test_secret_transaction.py` (the 29 fault-injection scenarios of the former shell library, via a harness binary that exists only in `-Dtest-harness` builds), `test_unlock_api.py`, `test_keepass_setup.py` (byte-compatible with Python's scrypt/HMAC journal format) and `test_secret_security*.py`.
- Zig: `zig build test` runs 40+ unit and fuzz tests under `std.testing.allocator`; `zig build compile-errors` runs 9 must-not-compile snippets.
- Test hooks (relocatable paths, a non-root unlock API, a short activation timeout) are behind a comptime `test_harness` option; the production build is checked to ignore them.
