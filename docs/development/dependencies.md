# Dependency policy

## CopyParty

The CopyParty flake is consumed as one reviewed upstream input and follows this repository's nixpkgs input. Nested lock nodes are not edited independently. A CopyParty update must include flake evaluation, closure builds, and the QEMU matrix.

## HuggingFaceModelDownloader

The model-downloader service remains an optional digest-pinned OCI workload until a native Nix package can be created with verified source and Go dependency hashes. Unverified hashes and failing placeholder derivations are forbidden. The service stays disabled in the VM matrix until an immutable platform artifact is available.

This is an explicit supply-chain boundary rather than an open implementation note: dependency changes require verifiable immutable inputs and a successful Nix build.

## Python runtime validation

The privileged control plane uses the Python standard library, immutable dataclasses at internal boundaries, and committed closed JSON Schemas for external payloads. A runtime framework such as Pydantic is not required for the current recovery plane and would add a new boot-critical dependency. Reconsider only when schema generation or cross-process model reuse clearly exceeds the existing validators.

## Cockpit frontend

The Cockpit UI uses the same React 18, PatternFly 6, esbuild, and Sass model as Cockpit Starter Kit. Direct dependency versions are exact in `cockpit/package.json`; an installable release must also contain the generated `cockpit/package-lock.json`, the compiled `cockpit/dist/` payload, and matching source-hash metadata. Nix installs only that verified payload and refuses a source-only placeholder. `nas-cockpit-api` remains the single privileged boundary, and backend response schemas and pure view-model tests remain mandatory.

## Open WebUI

Open WebUI is the only non-GPU package admitted by the Nix unfree-package predicate. Keep the exception exact to the `open-webui` package name; broader unfree enablement would bypass the appliance dependency review boundary.
