# Port evaluation: KeePass secret system in Zig

This records what the Zig port of the KeePass path (`nas-secrets`, `nas-unlock-api`, the KeePass part of setup) bought and cost, for comparison with the parallel Go port. It is evaluation material, not a design authority; [architecture.md](architecture.md) and [invariants.md](invariants.md) describe the current system.

Toolchain: Zig 0.17.1 (released 2026-11-02, the current release when the port was written), standard library only.

## Type-system wins

| Requirement | Mechanism | Enforced by |
|---|---|---|
| A secret cannot be printed or serialised | `Secret.format` and `Secret.jsonStringify` bodies are `@compileError`; the bytes sit behind `*anyopaque`, so `{any}` prints an address | `zig build compile-errors` (`secret_format`, `secret_json`) |
| Secrets never reach argv | `command.argv` inspects every tuple element at comptime and rejects any type that is, points to, or contains a `Secret` (including `StrongKeePassPassword`) | `secret_argv`, `password_argv` |
| sudo never consumes payload stdin | `Runner.privileged` has no payload parameter and always gives the child /dev/null | `privileged_payload` |
| Invalid transaction transitions | `Staged`, `Swapped`, `SwapFailed`, `Committed`, `RolledBack`, … are distinct types that expose only their legal methods | `staged_commit`, `committed_rollback` |
| Setup vs post-setup | `PostSetupSlot(.setup)` is `void`; link, outpost install and plaintext retirement take `PostSetup`, `Rotated` and `transaction.Committed` witnesses | `setup_mode_link` |
| Exhaustive outcomes | `Activation` is a tagged union, `Rejection` a closed error set; both map to HTTP through exhaustive `switch` | `outcome_exhaustive` |
| Feature gating | the host's options become a comptime ZON config; disabled services' staging code is not compiled, and relative paths or control characters fail the build | `config.zig` comptime block |
| Wiping | `ZeroingAllocator` is a distinct type, `secureZero`s on free/shrink and refuses `remap`, so moved buffers are wiped too | unit tests with `std.testing.allocator` (leak-checked) |

Explicit error sets are used throughout. The only `anyerror` is the signature that `std.testing.fuzz` imposes on fuzz callbacks.

## Gaps (honest)

- **No field privacy.** Zig has no private fields, so "only constructible after checks" for `AdminSession`, `UnlockRequest`, `UnitName` and similar types is a convention. `tests/test_secret_security.py` greps for struct-literal construction outside the owning module and for any touch of `Secret.handle`. A determined `@ptrCast` defeats the opaque pointer; the lint catches the obvious forms only.
- **No affine/linear types.** A copied `Staged` handle can be used twice. The runtime phase guard from the shell library remains in `Context` (tested: "double swap is rejected"). Leaving `main` while holding an uncommitted `Swapped` is not a compile error either; the activation code structures every exit explicitly.
- **No lifetime checking.** During the port a helper returned a `Payload` whose slice pointed into its own stack frame. Every KeePass call after the first failed, and the compiler said nothing; the black-box tests caught it. The fix stores parts by value with a comptime size bound, but the class of bug remains possible elsewhere.
- **Secrets also go to files and stdout.** The brief asked for stdin-only flow. Activation must write `EnvironmentFile`s, and `show-zfs-key-stdin` must print the key for `nas-zfs-unlock`. These are separate, enumerable sinks (`PrivateFile` in a verified 0700 directory, `revealToStdout` with a `RevealGrant` enum) rather than a general escape hatch.
- **No mlock.** Pages are not locked, so a secret can reach swap. Processes are marked non-dumpable (`PR_SET_DUMPABLE=0`) instead.
- **Coverage.** There is no Zig line-coverage tool in the toolchain. `coverage.py` floors cannot apply, so `tests/test_zig_contracts.py` gates structure instead: every module is in the leak-checked test root, parsers have fuzz targets, and every compile-fail snippet is wired into the build.
- **Fuzzing in CI** runs only the seed corpus (`zig build test`); continuous fuzzing needs `zig build test --fuzz` on a developer machine.
- **Behaviour changes, intended:** a timed-out unlock now sends SIGTERM so `nas-secrets` can roll back (Python sent SIGKILL); an existing KDBX is moved aside with `renameat2(RENAME_NOREPLACE)` instead of `mv --no-clobber`; failed rollback never attempts a move onto a live root that could not be removed.

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

## Tests

- Black-box Python suites run against the real binaries: `test_nas_secrets.py` (activation, rotation, rollback, SIGTERM, setup mode, coordinator, no secret in any argv), `test_secret_transaction.py` (the 29 fault-injection scenarios of the former shell library, via a harness binary that exists only in `-Dtest-harness` builds), `test_unlock_api.py`, `test_keepass_setup.py` (byte-compatible with Python's scrypt/HMAC journal format) and `test_secret_security*.py`.
- Zig: `zig build test` runs 40+ unit and fuzz tests under `std.testing.allocator`; `zig build compile-errors` runs 9 must-not-compile snippets.
- Test hooks (relocatable paths, a non-root unlock API, a short activation timeout) are behind a comptime `test_harness` option; the production build is checked to ignore them.
