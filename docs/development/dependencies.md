# Dependency policy

## CopyParty

The CopyParty flake is consumed as one reviewed upstream input and follows this repository's nixpkgs input. Nested lock nodes are not edited independently. A CopyParty update must include flake evaluation, closure builds, and the QEMU matrix.

## HuggingFaceModelDownloader

The model-downloader service remains an optional digest-pinned OCI workload until a native Nix package can be created with verified source and Go dependency hashes. Unverified hashes and failing placeholder derivations are forbidden. The service stays disabled in the VM matrix until an immutable platform artifact is available.

This is an explicit supply-chain boundary rather than an open implementation note: dependency changes require verifiable immutable inputs and a successful Nix build.

## Python runtime validation

The privileged control plane uses the Python standard library, immutable dataclasses at internal boundaries, and committed closed JSON Schemas for external payloads. A runtime framework such as Pydantic is not required for the current recovery plane and would add a new boot-critical dependency. Reconsider only when schema generation or cross-process model reuse clearly exceeds the existing validators.

## Test-only property and fuzz engines

Structured Python fuzz/property testing uses **Hypothesis** from the pinned Nix test shell. Hypothesis is test-only and must not enter appliance runtime closures. Project-local RNG mutation engines are forbidden: tests define strategies and invariants while Hypothesis owns generation, shrinking, replay, and state-machine sequences.

JavaScript property testing uses **fast-check 4.9.0** in the isolated `tests/js-fuzz/` npm workspace. Its lockfile is intentionally separate from `cockpit/package-lock.json`, so adding or updating a fuzzing tool cannot change the production Cockpit dependency graph or source hash. Use fast-check directly for frontend value-space properties that do not require a browser; it may also drive browser-backed cases when the invariant genuinely depends on browser semantics.

Byte-level coverage-guided fuzzing may use Atheris/libFuzzer only for a target that actually consumes opaque or binary input. Do not add it merely to fuzz structured JSON, identifiers, paths, or configuration objects that property strategies can model more efficiently.

## Browser and HTTP test tools

Playwright is the browser-behavior layer for checks that require a browser engine: DOM execution/XSS regressions, layout, interaction, accessibility, and real login flows. Browser engines are allowed for generated tests when those semantics matter. Request/response-level behavior that only needs HTTP status, headers, paths, redirects, or authorization responses should use curl or a protocol-aware scanner instead, because launching and rendering a browser adds cost without increasing fidelity for those invariants. Installed web active scanning remains ZAP's responsibility.

## Cockpit frontend

The Cockpit UI uses the same React 18, PatternFly 6, esbuild, and Sass model as Cockpit Starter Kit. Direct dependency versions are exact in `cockpit/package.json`; an installable release must also contain the generated `cockpit/package-lock.json`, the compiled `cockpit/dist/` payload, and matching source-hash metadata. Nix installs only that verified payload and refuses a source-only placeholder. `nas-cockpit-api` remains the single privileged boundary, and backend response schemas and pure view-model tests remain mandatory.

## Open WebUI

Open WebUI is the only non-GPU package admitted by the Nix unfree-package predicate. Keep the exception exact to the `open-webui` package name; broader unfree enablement would bypass the appliance dependency review boundary.
