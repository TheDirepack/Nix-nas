# Manually triggered source releases

A release is published **only when an operator explicitly runs** the **Merge build and release** workflow using **Actions → Merge build and release → Run workflow** on `main`. Merging a PR or completing CI never starts a release. The workflow does not accept release triggers from a push, tag, or another workflow.

## Qualification and publication

1. The operator selects `main` and starts the workflow. The dispatch commit (`github.sha`) is the release source; releases from other refs are refused.
2. The eligibility job verifies that this exact commit is the recorded merge result of a pull request merged into `main`, then finds a successful push-triggered **CI** run for that same SHA. It fails closed if either condition is missing. The CI run ID is retained for later artifact retrieval.
3. The build job downloads and verifies that run's exact `vm-bundle-handoff` artifact and NixOS closures. It uses the Nixpkgs-provided Diceware tool to generate a five-word release-specific bootstrap credential and stamps a separate release-only commit without pushing that commit to `main`.
4. Release-specific Cockpit and wizard bundles, Nix closures, tests, and source package are rebuilt or validated. A candidate Git bundle and publication metadata are uploaded as an immutable workflow artifact.
5. A separate publication job, the only job with repository write access, verifies the candidate commit's parent and version, pushes an annotated tag, and creates or repairs the GitHub Release.

The workflow has a single `manual-release-main` concurrency group with `cancel-in-progress: false`; do not queue multiple source versions concurrently. Because releases are manual, a qualified merge does **not** automatically consume a patch number or require a release. Version allocation follows existing published release tags, not commit distance.

## Versioning and retries

`VERSION` and `.github/release-version-epoch.json` identify the development series. Preparation starts from the series anchor in Git first-parent history and allocates the next patch after validated existing generated tags. A later manual release may cover several main merges; it creates one release. Gaps or contradictory tagged release history fail closed.

For a rerun of an already tagged source, preparation recovers the exact version and bootstrap password from the existing tagged release commit, and publication repairs the release rather than inventing a new identity. The same-commit rerun remains possible even after a later source has been released.

Only the release-only commit replaces the fixed development bootstrap credential in `modules/nas/internal/base.nix`. The canonical bootstrap value feeds Linux, Authentik, and KeePass setup. The five-word Diceware password is published in the matching release notes and must be retired during initial setup; it is not a persistent application secret.

## Security and release status

Source compilation and tests run with read-only repository credentials. The publication job does not invoke Nix, npm, or project test/build scripts. CI and release triggers remain loop-free, and a release tag cannot trigger CI or another release.

Releases are **source-only development artifacts** until native VM, installation, and applicable live hardware recovery evidence satisfy [release-checklist.md](release-checklist.md). A successful manual run does not by itself qualify an install-ready appliance.
