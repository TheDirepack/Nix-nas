# Setup simplification

`nas_setup.py` currently mixes four separate jobs: first-start request handling, privileged orchestration, identity/bootstrap retirement, and steady-state recovery/status. The cleanup should reduce it to a thin command surface over smaller modules rather than growing more setup-specific helpers in the same file.

The secret-runtime extraction is complete: `secret-tools.nix` sources the immutable `nas-secret-runtime.sh` library for validation and private-file installation. The validators retain their existing call sites and diagnostics; private installation rejects missing, non-regular, and symlink sources. There is no duplicate implementation in the Nix string. The setup-module and npm cleanup below remain separate follow-up changes, not part of this extraction.

## Target split

- `nas_setup.py`: argument parsing and command dispatch only.
- `nas_setup_config.py`: setup document and secret-input validation; keep this side-effect free.
- `nas_setup_first_start.py`: first-start request/result files, plan confirmation, and systemd job handoff.
- `nas_setup_apply.py`: finite first-run orchestration and rollback/journal integration.
- `nas_setup_recovery.py`: status and explicit recovery/reconciliation commands.
- `scripts/lib/nas-secret-runtime.sh`: shared shell validation and private-file installation helpers used by secret activation code.

Do not add a setup daemon, a second mutable desired-state store, or another lock database. Long-running work remains systemd-owned and privileged mutation coordination remains the shared operation lock.

## Cleanup order

1. Move pure first-start request parsing and validation out of `nas_setup.py`, preserving focused tests.
2. Move systemd job/result-file handling next so the Cockpit API and CLI share one request contract.
3. Move secret validation/install shell helpers out of the Nix string and source the standalone runtime library.
4. Keep the Cockpit npm manifest limited to direct imports; transitive PatternFly packages stay lockfile-owned instead of being declared as direct dependencies.
5. Remove obsolete setup compatibility paths rather than carrying migrations for behavior that is no longer supported.

Each extraction should leave the public command surface smaller and should delete the old implementation in the same change once its replacement is wired.
