# Setup simplification

`nas_setup.py` currently mixes four separate jobs: first-start request handling, privileged orchestration, identity/bootstrap retirement, and steady-state recovery/status. The cleanup should reduce it to a thin command surface over smaller modules rather than growing more setup-specific helpers in the same file.

The secret runtime is the Zig `nas-secrets` binary (`zig/`); `secret-tools.nix` only renders its compile-time configuration. KeePass database creation, the KeePass password floor and the resumable-journal verifier run in `nas-keepass-setup`, which `nas_setup.py` and `nas_setup_config.py` call with secrets on stdin. The setup-module and npm cleanup below remain separate follow-up changes.

## Target split

- `nas_setup.py`: argument parsing and command dispatch only.
- `nas_setup_config.py`: setup document and secret-input validation; keep this side-effect free.
- `nas_setup_first_start.py`: first-start request/result files, plan confirmation, and systemd job handoff.
- `nas_setup_apply.py`: finite first-run orchestration and rollback/journal integration.
- `nas_setup_recovery.py`: status and explicit recovery/reconciliation commands.
- `zig/src/keepass_setup.zig`: KeePass-specific setup checks; keep them out of the Python modules.

Do not add a setup daemon, a second mutable desired-state store, or another lock database. Long-running work remains systemd-owned and privileged mutation coordination remains the shared operation lock.

## Cleanup order

1. Move pure first-start request parsing and validation out of `nas_setup.py`, preserving focused tests. **Implemented:** `nas_setup_first_start.py` now owns both JSON request and secret-payload contracts; filesystem permission checks and secret-file deletion remain in the privileged runner.
2. Move systemd job/result-file handling next so the Cockpit API and CLI share one request contract.
3. Move secret validation/install shell helpers out of the Nix string and source the standalone runtime library.
4. Keep the Cockpit npm manifest limited to direct imports; transitive PatternFly packages stay lockfile-owned instead of being declared as direct dependencies.
5. Remove obsolete setup compatibility paths rather than carrying migrations for behavior that is no longer supported.

Each extraction should leave the public command surface smaller and should delete the old implementation in the same change once its replacement is wired.

## Current first-start boundary

Cockpit links to the canonical standalone wizard. The API and detached worker
share administrator/secret validation in `nas_setup_first_start.py`; the
`nas-setup first-run --secret-payload-stdin` integration uses it too. The GUI
collects input and displays outcomes; all authorization, plan/device validation,
locking and recovery remain in the installed commands.
