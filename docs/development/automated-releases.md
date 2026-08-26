# Automated merge releases

A release is created only after the repository's `CI` workflow has completed successfully for a `push` to `main`. `.github/workflows/release.yml` listens to that successful `workflow_run`, then verifies that the qualified source SHA is the associated pull request's recorded `merge_commit_sha` after a merge into `main`. GitHub defines that field as the resulting base-branch commit for merge commits, squash merges, and rebase merges. Merely being associated with a pull request is not enough, so a direct or indirect push cannot become release-eligible just because GitHub marks a related pull request as merged.

This trigger graph is intentionally loop-free. CI does not listen to release tags, and the release workflow does not listen to repository push or tag events at all. Publishing `v<version>` therefore cannot start another CI or release workflow, even if the publication token or GitHub's token-trigger behavior changes in the future.

The development tree remains development-friendly: it keeps the fixed `akadmin` bootstrap password `nas-admin-first-boot`, so VM, browser, and first-run tests do not need to discover a changing credential. Automated release stamping happens only in a separate release commit created by the workflow; that commit is tagged and packaged but is never pushed back onto `main`.

## Qualification and publication flow

The workflow:

1. accepts only a successful main-branch `CI` run whose source SHA exactly equals the recorded merge result of a merged pull request targeting `main`;
2. downloads the exact `vm-bundle-handoff` produced by that CI run and verifies/imports both the reusable package bundles and exact `nas-ci-ready`/`nas-qemu` system-closure handoff;
3. uses the maintained `diceware` package from the repository's pinned Nixpkgs test environment to generate a five-word passphrase with the long EFF English wordlist (`en_eff`), explicitly selects the `system` cryptographic random source, enables capitalization, and uses `-` as the delimiter;
4. calculates the release patch deterministically from the source commit's first-parent distance from the checked-in release-version epoch for the current `VERSION` series;
5. updates `VERSION`, README/flake/Cockpit version metadata, and the changelog in the release-only checkout;
6. replaces the fixed development bootstrap password only in the two explicit runtime authorities: `modules/nas/internal/secret-tools.nix` and `modules/nas/config/application-services.nix`. Tests and explanatory documentation are not rewritten, so they remain independent validation rather than changing their expectations with production code;
7. rebuilds and validates the release-specific Cockpit bundle and configuration-dependent NixOS closures after stamping;
8. commits the exact stamped release inputs locally and creates a source-only package with manifest, checksum, and provenance metadata;
9. packages the release candidate commit, release notes, metadata, and release assets into an immutable workflow artifact; and
10. passes that artifact to a separate publication job that alone has `contents: write`, verifies the candidate's source parent/version, pushes only the annotated `v<version>` tag, and creates or repairs the GitHub Release.

The build job has only read access and checks out with `persist-credentials: false`. Repository build/test code therefore never executes with a repository-write credential. The publication job does not run Nix/npm/project build code; it only verifies and publishes the already-built immutable candidate.

## Version allocation and reruns

`.github/release-version-epoch.json` names only the current development `VERSION` series; it deliberately contains no commit SHA. Git history supplies the anchor: release preparation finds the first-parent commit that introduced or last changed the epoch file and uses that commit's first parent as distance zero. The release patch is the development patch plus the qualified source merge's first-parent distance from that anchor. The first qualified merge in a series therefore receives the next patch, and each later qualified main commit has a deterministic version independent of Actions run numbers, retries, queue order, or overlapping CI execution.

This avoids self-referential release metadata. When a new development `VERSION` series is deliberately established, change `VERSION` and the epoch file's `version` field together. No commit hash needs to be predicted or written into its own commit. Release preparation fails closed if the epoch version and `VERSION` disagree.

The release workflow itself deliberately uses one `main-release-publication` concurrency group with `queue: max`. This serialization is not needed to make version numbers unique; the first-parent mapping already does that. It exists so each generated release sees the previously published tag history before constructing its cumulative generated changelog. `queue: max` preserves up to 100 pending release runs instead of replacing the previous pending run, so a burst of qualified merges is processed in order rather than silently dropping intermediate release opportunities.

Generated release commits are intentionally not merged back to `main`. To keep release changelogs cumulative anyway, release preparation reads the newest earlier generated release tag in the same version series and carries its generated release sections forward before the development baseline section. Serializing release workflows ensures that earlier qualified merges have finished publishing their tags before the next candidate reads that history.

If publication is interrupted after the tag exists, a rerun finds the tag associated with the original source merge, recovers the exact release version and passphrase from that tagged release commit, and repairs or completes the GitHub Release instead of generating a different release identity.

## Bootstrap credential policy

`main` and ordinary development branches keep `nas-admin-first-boot`. Only the release-only commit's explicit runtime bootstrap authorities receive the generated passphrase. Operator documentation tells release users to obtain the generated value from the matching GitHub Release notes rather than assuming the development password is valid for a tagged release.

The release passphrase is generated by the existing `diceware` implementation packaged by Nixpkgs, not by NAS-owned random-word code. The workflow explicitly selects Diceware's `system` random source (Python `SystemRandom`) and the `en_eff` EFF long wordlist with 7,776 entries. Five independently selected words provide about 64.6 bits of selection entropy. Capitalization is only formatting and does not add entropy. The credential is intentionally published in that release's notes because it is a first-run bootstrap credential, not a long-lived secret.

The setup workflow retires the bootstrap identity after the configured administrator has been established. Do not reuse the bootstrap credential for normal administration. Existing installations keep their own KeePassXC state; a new release only changes the seed used by fresh first-run initialization from that release artifact.

## Repository policy

Protecting `main` with a repository ruleset that requires pull requests and the stable CI summary remains recommended defense in depth. Automated release eligibility does not rely on that setting: the workflow independently verifies the exact merged-PR result and refuses to publish direct or indirectly associated pushes.

## Release status

Automated releases remain **source-only development artifacts** until the project's install-ready qualification requirements are satisfied. The main source commit completes the full CI pipeline before release preparation begins. Release preparation then validates the release-specific stamped source and configuration-dependent build delta. This does not substitute for the hardware recovery and destructive-boundary evidence required by the release qualification checklist.
