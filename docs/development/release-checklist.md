# Release qualification checklist

Use this checklist for an **install-ready** release. A source archive may be useful for development without satisfying these gates, but it must remain clearly labeled source-only/unverified.

No checklist item may be satisfied with evidence from a different commit. If code, configuration, generated frontend bytes, lockfiles, or release tooling changes, rerun the affected qualification gates.

## 1. Freeze the source and frontend artifact

- Record the qualifying commit and `flake.lock` digest.
- Retain the exact `cockpit/package-lock.json`.
- Build Cockpit with the locked dependency graph (`npm ci`, then project checks/build).
- Retain the exact compiled `cockpit/dist/` bytes and build metadata.
- Make Nix evaluation, VM tests, installer tests, and release packaging consume that same frontend artifact.
- Run `python3 scripts/check-version.py` and require `VERSION`, the README heading, `flake.nix`, `CHANGELOG.md`, Cockpit/package metadata, and generated release metadata to agree before publication.

## 2. Run source validation

```bash
./scripts/test-matrix.py fast --require-all --report test-evidence/fast.json
./scripts/run-unit-tests.py --jobs 4
./scripts/run-security-tests.py
node --test tests/js/*.test.mjs
```

Also run the unprivileged/hermetic test job used by CI. Static analysis, dependency/vulnerability auditing, secret scanning, and security/injection tests are release-blocking: do not convert a genuine finding into an allowed failure merely to publish an artifact.

## 3. Prove Nix evaluation and closures

Retain results for:

```bash
./scripts/nix-config-matrix.sh
```

This must evaluate the appliance/reusable-profile matrix and prove every intentionally invalid fixture fails for its expected assertion. Then build the CI-ready and QEMU closures and run all native `runNixOSTest` checks.

Record Nix version, runner architecture, result paths, and check names with the source/frontend digests.

Before install-ready qualification, prove the target configuration itself evaluates with `nas.installationReady = true`. That evaluation must use the target's reviewed/generated `hardware-configuration.nix`, a unique non-placeholder `networking.hostId`, non-empty reviewed `nas.trustedInterfaces`, and either a configured administrator SSH key or an explicitly verified console/hardware-KVM recovery path. If ZFS encryption is disabled, retain the operator's explicit unencrypted-storage acknowledgement.

## 4. Run installation tests

Run the deterministic official-ISO installation harness through fresh install, repeated declarative installation, first boot, security/browser checks, dry-activate/test/switch, rejected bad candidate, explicit rollback, return to the reviewed generation, and a second reboot. Then require the independently provisioned installed-command and active-ZAP fuzz workloads. Confirm each installed generation uses the same reviewed source and Cockpit artifact and that unrelated persistence survives every deterministic stage.

The full QEMU/integration and installer matrix is release-blocking. A skipped heavyweight job is not passing evidence unless the release process explicitly runs the equivalent gate on a qualified builder and attaches that evidence to the same commit.

## 5. Exercise recovery and destructive boundaries

Retain evidence for:

- locked boot and KeePass activation;
- validation of required bootstrap/secret input files, ownership, and permissions before protected-service activation;
- initial static setup guidance, followed by Authentik-authorized browser access after activation;
- absence of direct Cockpit or local-PAM browser login on every network interface;
- firewall access from an independent client;
- ZFS import, encryption, snapshot, replication, and restore;
- Restic restore to independent storage;
- failed deployment rollback including mutable-state recovery;
- successful update promotion and post-promotion manageability;
- out-of-band recovery through NanoKVM or equivalent hardware access.

Do not remove the source-only/development warning or publish an install-ready release until the physical recovery and failure drills above have been performed on representative hardware.

## 6. Prove update provenance and dependency maintenance

- Exercise the guarded update flow against an exact reviewed commit and verify its provenance checks reject an unexpected checkout/artifact.
- Exercise both scheduled check/build mode (`nas.autoUpdate.enable = true`, `nas.autoUpdate.apply = false`) and an explicitly authorized promotion/rollback path.
- Confirm Renovate is enabled for the repository, its Dependency Dashboard is current, and dependency PR creation has been observed recently. A committed `renovate.json` alone is not evidence that the GitHub app/service is running.
- Review outstanding dependency/security update failures before release; unresolved security failures remain release-blocking where applicable.

## 7. Package and verify

- Enforce the version discipline before packaging:
  - documentation-only edits may keep the current `VERSION`;
  - rebuilding/renaming an artifact from otherwise unchanged source may keep the current `VERSION`;
  - **every code/config/script/UI/test/release-tooling change requires a new `VERSION`** and matching `CHANGELOG.md` entry before publication;
  - changing the packaging script itself counts as code and therefore requires a version bump.
- Use the artifact filename convention in [`artifact-naming.md`](artifact-naming.md).
- Regenerate `MANIFEST.sha256`.
- Package from a clean, reviewed tree.
- Run release preflight with manifest verification:

  ```bash
  NAS_PREFLIGHT_VERIFY_MANIFEST=1 ./scripts/preflight.sh
  ```

- Produce and retain the archive SHA-256 and provenance record.
- Confirm the archive contains no credentials, local configuration, caches, VM disks, installer ISOs, or unrelated build output.
- Publish a GitHub Release only after the installable artifact, checksums/signatures, provenance, changelog, and same-commit qualification evidence are complete. Until then, source archives remain development artifacts rather than installable releases.

## Evidence rule

A release claim is bound to one source/frontend artifact pair. Evidence from a different commit, lockfile, compiled distribution, or flake lock does not qualify the current release.
