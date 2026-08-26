# Release artifact naming

`VERSION` is the canonical software version. Artifact filenames are intentionally shorter and are not a second version source of truth.

## Source archives

Use this human-facing filename format:

```text
Nix OS NAS <display-version> source.zip
```

For the current version:

```text
VERSION:                         0.1.0
source archive filename:        Nix OS NAS 0.1.0 source.zip
```

For prereleases matching `MAJOR.MINOR.0-alpha.N`, the display version is `MAJOR.MINOR.N`. For stable SemVer versions, the display version equals `VERSION`.

The ZIP keeps a canonical internal root directory containing the full repository version and qualification state, for example:

```text
nixos-nas-0.1.0-source-only-unverified/
```

That internal name, `VERSION`, `README.md`, `CHANGELOG.md`, and the provenance JSON remain authoritative when exact release identity matters.

## Qualified release archives

Use:

```text
Nix OS NAS <display-version> release.zip
```

The word `source` means the artifact is a source package, not an install-ready appliance image. Source-only qualification state must remain explicit inside the archive and provenance even though the filename no longer carries the verbose `source-only-unverified` suffix.

## Companion files

Use the same basename for checksum, manifest, provenance, and signatures:

```text
Nix OS NAS 2.2.14 source.zip
Nix OS NAS 2.2.14 source.zip.sha256
Nix OS NAS 2.2.6 source.MANIFEST.sha256
Nix OS NAS 2.2.6 source.provenance.json
```

## Version bump policy

`VERSION` changes are tied to source behavior, not to the act of rebuilding an archive.

- **Documentation-only changes do not require a version bump.** This includes prose, diagrams, comments, and other documentation that do not change generated/runtime behavior.
- **Repackaging unchanged source does not require a version bump.** Renaming or regenerating an artifact from byte-for-byte equivalent source is not a software revision.
- **Every code change requires a new version number.** Any change to executable code, Nix configuration/module logic, scripts, service definitions, UI code, tests that alter executable qualification behavior, release tooling, generated-runtime configuration, or other non-documentation source must bump `VERSION` before it is published.
- A packaging-script change is a code change and therefore requires a version bump; only rerunning the unchanged packaging code does not.

For the `0.1.0` baseline, increment the patch or minor component (`0.1.0` -> `0.1.1` or `0.2.0`) for the next code-bearing revision; prereleases may use `0.1.1-alpha.1` style suffixes. Keep `CHANGELOG.md`, Cockpit package metadata, flake-visible version text, provenance, and the human-facing display version mapping synchronized with `VERSION`. The previous `2.2.0-alpha.x` line used `alpha.N` increments.
