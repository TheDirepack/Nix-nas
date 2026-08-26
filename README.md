# NixOS NAS 0.1.0

A NixOS-based NAS appliance that keeps storage, identity, secrets, applications, and recovery paths explicit and independently understandable.

The core stack is ZFS + CopyParty + Authentik + Cockpit + KeePassXC-backed secrets, with optional Syncthing, Vaultwarden, virtualization, local AI, and a lightweight VictoriaMetrics/Telegraf observability stack.

> **Release status:** 0.1.0 is a source-only development artifact until its exact Cockpit frontend, Nix closures, VM tests, installer path, and hardware recovery drills are qualified. Do not treat a source-only archive as an install-ready appliance image.

Every successfully qualified pull-request merge to `main` produces a separate, tagged source-only GitHub Release. The release workflow starts only after the full main-branch CI run succeeds, requires the CI source to be the pull request's exact recorded merge result, and preserves main's first-parent release order before publication; direct pushes are not automatically published. The development tree keeps the fixed `akadmin / nas-admin-first-boot` credential for repeatable testing, while the tagged release commit receives a five-word Diceware bootstrap password whose matching username/password are published in that release's notes. The generated release commit is never pushed back onto `main`, CI does not trigger on release tags, and the release workflow does not trigger on push/tag events, so publication cannot recurse into another release cycle. See [`docs/development/automated-releases.md`](docs/development/automated-releases.md) for the exact qualification, versioning, credential, retry, ordering, and publication behavior.

## First installation

1. Replace `hardware-configuration.nix` with reviewed output from the target machine.
2. Review `local.nix` and complete the installation checklist in [`docs/src/admin/configuration.md`](docs/src/admin/configuration.md).
