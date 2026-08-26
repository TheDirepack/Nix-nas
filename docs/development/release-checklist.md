# Release qualification checklist

Use this checklist for an **install-ready** release. A source archive may be useful for development without satisfying these gates, but it must remain clearly labeled source-only/unverified.

The automated merge-release workflow described in [`automated-releases.md`](automated-releases.md) deliberately publishes **source-only development releases** before the install-ready qualification below is complete. Publication is eligible only after the complete `CI` workflow succeeds for a `main` push and the source commit is independently verified as belonging to a merged pull request. The release workflow creates a release-only commit, assigns its deterministic patch version there, validates the stamped release delta, and publishes the tagged source artifact without modifying `main`. Passing that workflow is useful build evidence, but it does not by itself satisfy this checklist.

## 1. Freeze the source and frontend artifact

- Record the qualifying commit and `flake.lock` digest.
- Retain the exact `cockpit/package-lock.json`.
- Build Cockpit with the locked dependency graph (`npm ci`, then project checks/build).
- Retain the exact compiled `cockpit/dist/` bytes and build metadata.
- Make Nix evaluation, VM tests, installer tests, and release packaging consume that same frontend artifact.

For an automated merge release, the main source commit first completes the full CI pipeline and produces the verified Cockpit/Nix handoffs. The published artifact is then built from a generated release-only commit whose first parent is that qualified `main` source commit. Version metadata and the release-specific bootstrap credential must be read from the tagged release commit, not reconstructed from the current `main` tree.

## 2. Run source validation

```bash
./scripts/test-matrix.py fast --require-all --report test-evidence/fast.json
./scripts/run-unit-tests.py --jobs 4
./scripts/run-security-tests.py
node --test tests/js/*.test.mjs
```

Also run the unprivileged/hermetic test job used by CI.

## 3. Prove Nix evaluation and closures

Retain results for:

```bash
./scripts/nix-config-matrix.sh
```

This must evaluate the appliance/reusable-profile matrix and prove every intentionally invalid fixture fails for its expected assertion. Then build the CI-ready and QEMU closures and run all native `runNixOSTest` checks.

Record Nix version, runner architecture, result paths, and check names with the source/frontend digests. The CI producer exports the exact `nas-ci-ready` and `nas-qemu` system closures into the per-run handoff; later runners must verify/import that artifact rather than independently reconstructing the full closure cold.

## 4. Run installation tests

Run the deterministic official-ISO installation harness through fresh install, repeated declarative installation, first boot, security/browser checks, dry-activate/test/switch, rejected bad candidate, explicit rollback, return to the reviewed generation, and a second reboot. Then require the independently provisioned installed-command and active-ZAP fuzz workloads. Confirm each installed generation uses the same reviewed source and Cockpit artifact and that unrelated persistence survives every deterministic stage.

## 5. Exercise recovery and destructive boundaries

Retain evidence for:

- locked boot and KeePass activation;
- initial static setup guidance, followed by Authentik-authorized browser access after activation;
- absence of direct Cockpit or local-PAM browser login on every network interface;
- firewall access from an independent client;
- ZFS import, encryption, snapshot, replication, and restore;
- Restic restore to independent storage;
- failed deployment rollback including mutable-state recovery;
- successful update promotion and post-promotion manageability;
- out-of-band recovery through NanoKVM or equivalent hardware access.

## 6. Package and verify

- Enforce the version discipline before packaging:
  - documentation-only edits may keep the current development `VERSION`;
  - rebuilding/renaming an artifact from otherwise unchanged source may keep the current `VERSION`;
  - **every code/config/script/UI/test/release-tooling publication requires a distinct release version**;
  - for automated merge releases, `scripts/prepare_release.py` derives the release patch deterministically from the qualified source commit's first-parent position relative to `.github/release-version-epoch.json`, then synchronizes that version only in the release commit;
  - when intentionally establishing a new development `VERSION` series, update the release-version epoch with it;
  - changing the packaging or release tooling itself still causes the next qualified merged source to receive its distinct deterministic version.
- Require `python3 scripts/check-version.py` to pass on the exact release checkout after stamping, including README status, both Cockpit lockfile version fields, flake description, and changelog heading.
- Use the artifact filename convention in [`artifact-naming.md`](artifact-naming.md).
- Regenerate `MANIFEST.sha256`.
- Package from a clean, reviewed tree.
- Run release preflight with manifest verification:

  ```bash
  NAS_PREFLIGHT_VERIFY_MANIFEST=1 ./scripts/preflight.sh
  ```

- Produce and retain the archive SHA-256 and provenance record.
- Confirm the archive contains no private or long-lived credentials, local configuration, caches, VM disks, installer ISOs, or unrelated build output.
- Automated merge releases intentionally contain one public first-boot credential: `akadmin` plus the release-specific five-word Diceware password embedded in the tagged release source. Verify that credential matches the GitHub Release notes exactly and that the development-only `nas-admin-first-boot` password is not the bootstrap password in the published release commit.
- Verify only the two explicit runtime bootstrap authorities were credential-stamped; tests and documentation must remain independent and retain their development expectations.
- Verify the generated release commit was not pushed back onto `main`; the fixed development bootstrap credential must remain in the development tree for repeatable tests.
- Verify the release trigger graph remains loop-free: CI must not trigger on `v*` tags, and the release workflow must be triggered only by successful `CI` `workflow_run` completion rather than push/tag events.
- Verify repository-write permission exists only in the small publication job; release build/test jobs must use read-only contents access and checkout with persisted credentials disabled.

## Evidence rule

A release claim is bound to one source/frontend artifact pair. Evidence from a different commit, lockfile, compiled distribution, flake lock, or upstream CI run does not qualify the current release. For an interrupted automated publication, rerun/repair must reuse the existing tag's exact release commit, version, and bootstrap credential rather than minting a second identity for the same source commit.