# Dependency policy

## CopyParty

The CopyParty flake is consumed as one reviewed upstream input and follows this repository's nixpkgs input. Nested lock nodes are not edited independently. A CopyParty update must include flake evaluation, closure builds, and the QEMU matrix.

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

## Unfree packages

The unfree-package predicate in `modules/nas/config/host-platform.nix` admits only NVIDIA/CUDA/CUDNN/Libcu/NCCL package names, and only when `nas.hardware.gpuVendors` declares `nvidia`. Keep that exception exact to those package-name prefixes; broader unfree enablement would bypass the appliance dependency review boundary.

## Upgrade qualification pin

The official-ISO upgrade rehearsal pins nixpkgs revision
`36f2e6c0b6b6de4e7269e8996cf2dbb9cb5a29ac` (NixOS 26.05, June 30,
2026). It provides Syncthing 2.0.15, older than the reviewed lock's package.
Keep the revision immutable so CI exercises the same old-to-new transition.
