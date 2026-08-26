# Automated merge releases

Every non-skipped push to `main` starts `.github/workflows/release.yml`. In the normal pull-request flow, that means every merge gets its own build and GitHub Release.

The release is stamped from the merge commit rather than from a mutable shared build directory. The workflow:

1. fetches existing release tags and calculates a monotonically increasing patch version;
2. generates a new 32-byte URL-safe Authentik bootstrap password;
3. updates `VERSION`, README/flake/Cockpit version metadata, and the changelog;
4. replaces the previous bootstrap password in every tracked reference so runtime configuration, tests, development tooling, and documentation all use the same release-specific value;
5. rebuilds and validates the production Cockpit bundle;
6. evaluates the configuration matrix and builds the CI-ready and QEMU NixOS closures;
7. commits the exact stamped release inputs and creates a source-only package with manifest, checksum, and provenance metadata;
8. publishes a `v<version>` tag and GitHub Release whose notes contain the first-boot Authentik username (`akadmin`) and generated password; and
9. fast-forwards the release metadata commit onto `main` only when that merge is still the current tip.

If another merge lands while an older release is building, the older release is still published from its own merge commit. It does not rewrite the newer `main`. The newer merge's release carries the version sequence forward. The workflow run number is included as a lower bound for the patch number so concurrently started merge releases do not select the same version; existing tags are also treated as authoritative when choosing the next patch.

Release commits use `[skip ci]`. GitHub's workflow token normally does not recursively start workflows for its own pushes, and the skip marker is an additional recursion guard.

## Bootstrap credential policy

The release-specific `akadmin` password is intentionally public because it is a first-run bootstrap credential, not a long-lived secret. It is generated independently for each release, embedded into both Authentik first-boot paths, and published in that release's notes. The setup workflow retires the bootstrap identity after the configured administrator has been established.

Do not reuse the bootstrap credential for normal administration. Existing installations keep their own KeePassXC state; a new release only changes the seed used by fresh first-run initialization.

## Release status

Automated releases remain **source-only development artifacts** until the project's install-ready qualification requirements are satisfied. The automation proves that the release-specific source, frontend bundle, and NixOS closures build, but it does not substitute for the hardware recovery and destructive-boundary evidence required by the release qualification checklist.
