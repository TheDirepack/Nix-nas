# Dependency policy

## Release inventory

Release automation publishes `dependencies-nas-ci-ready.json` and
`dependencies-nas-qemu.json` beside the source archive. Each records the stamped
release commit, exact system store path, recursive Nix closure, and repository
OCI pins. OCI entries describe source declarations, not proof that an image was
installed. Empty digest slots remain visible. This inventory is informational;
it is not a vulnerability scan or an install-ready qualification claim.

For an already built system, run:

```bash
python3 scripts/release-inventory.py --system /nix/store/EXACT-SYSTEM \
  --revision "$(git rev-parse HEAD)" --output /tmp/dependencies.json
```

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

CI defaults to the immutable upstream ZAP image declared in `.github/workflows/ci.yml`. The optional `NAS_ZAP_IMAGE` repository variable may override it with another reviewed digest; an absent variable must not prevent qualification. Both scanner wrappers reject floating tags.

`scripts/lib/zap-addons.lock.json` pins the native add-on inventory for packaged
and Automation Framework scans, including release and beta active/passive rules
and browser dependencies. The wrappers build one derived scanner image through
`scripts/lib/zap.Dockerfile`. The build verifies the upstream core JAR and add-on
archives, downloads five SHA256-locked Java sources at exact upstream revisions,
and applies `zap-cookie-probes.patch`. The pinned image's JDK compiles those
sources; the build replaces only their existing class entries and checks all
three rebuilt archive hashes. Other classes, rule metadata and dependencies stay
unchanged. A source, patch or output mismatch fails the build.

The shared entrypoint checks the rebuilt core and all add-on hashes, prepares a
private home, then asks ZAP to load its own dependencies. It rejects a missing,
extra or different runnable add-on before scanning. Scans use `-silent` with
that verified home to prevent live updates and run from it so the packaged
scanner can write its relative `zap.out` as the caller's UID. Each `.addons.json` report records
the base image digest, derived image ID, lock digest, source-build recipe and
complete runnable inventory.

For an image or add-on update, capture the native resolved inventory for baseline,
full, and browser automation modes, compare rule/dependency coverage, and refresh
the lock from the captured archive hashes. Run `tests/test_zap_addons.py`,
`tests/test_zap_source_build.py` and the scanner wrapper contracts. Run the native
transport and hardened/vulnerable authentication controls with
`NAS_ZAP_NATIVE_TEST=1 NAS_ZAP_IMAGE=<reviewed-digest> python3 -m unittest tests.slow_zap_native -v`,
then qualify installed scans and browsers on the combined revision. CI retains
the native-control and installed-scanner evidence on success and failure.
Disabling add-on updates without supplying the locked beta rules would remove
security coverage.

Authenticated active scans retain their configured user. ZAP's session layer
can overwrite deliberate cookie mutations before sending requests, as recorded
in [upstream issue 6506](https://github.com/zaproxy/zaproxy/issues/6506).
Native fixture wire traces reproduce this with both autodetected and explicit
cookie sessions: rule `90027` receives HTTP 200 because ZAP reinserted the removed
session cookie. The source repair adds an explicit per-request session-management
option and uses it only for that rule's cookie-removal probes. Those probes retain
the requesting user, scanner hooks, anti-CSRF handling and listeners, but cannot
inherit or update a shared cookie jar or trigger authentication retries. Normal
requests retain session refresh and response-cookie updates. Rule `90027` remains
fatal; a deliberately vulnerable session fixture must still trigger it. Removing
the active-scan user or suppressing the rule cannot qualify a scanner.

## Cockpit frontend

The Cockpit UI uses the same React 18, PatternFly 6, esbuild, and Sass model as Cockpit Starter Kit. Direct dependency versions are exact in `cockpit/package.json`. Nix builds Cockpit and the first-run wizard from their reviewed npm lockfiles with `importNpmLock` and `buildNpmPackage`, then verifies their output with the existing build-integrity checks. Local `node_modules` and generated `dist` trees are excluded from derivation inputs. Release archives retain the compiled payload and source-hash metadata for browser qualification and source consumers; they are not the inputs to the installed frontend build. `nas-cockpit-api` remains the single privileged boundary, and backend response schemas and pure view-model tests remain mandatory.

The running Cockpit bridge applies `cockpit-frame-ancestors.patch` to the native
package policy generator. Its default HTML policy adds `frame-ancestors 'self'`
without replacing package-specific directives, nonces or WebSocket origins.
Explicit stricter package policies still win. This does not repair upstream HTML
error responses without CSP. Retain the patch until the pinned upstream provides
an equivalent default; source fixtures alone do not establish installed browser
compatibility or finding-policy clearance.

Cockpit menu paths are package-qualified components, not paths relative to the
declaring manifest. The shell normalizes a trailing `/index`, so NAS Help targets
the existing `nas/docs/admin/installation.html` chapter rather than a nested index
page. Keep that target in the book summary and qualify real shell navigation
after package/router changes. Direct documentation links still use the packaged
`nas/docs/index.html` home page.

## Unfree packages

The unfree-package predicate in `modules/nas/config/host-platform.nix` admits only NVIDIA/CUDA/CUDNN/Libcu/NCCL package names, and only when `nas.hardware.gpuVendors` declares `nvidia`. Keep that exception exact to those package-name prefixes; broader unfree enablement would bypass the appliance dependency review boundary.

## Firewalld readiness

The upstream unit may use implicit `Type=simple`, which does not guarantee that
`firewall-cmd` can connect when dependent units start. The NAS unit uses native
`Type=dbus` readiness with `BusName=org.fedoraproject.FirewallD1`. Firewalld
acquires that name after initializing firewall state; the baseline and guards
must remain ordered after this readiness boundary.

## Authentik login accessibility

`authentikPackage` in `modules/nas/internal/account-tools.nix` applies
`authentik/patches/authentik-accessibility.patch` to the upstream source before
Nix builds its frontend and server. It removes invalid required-state ARIA from
labels, keeps password-manager helper controls out of accessibility/tab order,
and gives light footer/locale text a solid dark background. All native server,
worker, migration, and blueprint commands consume this one package. Dependency
updates must either retain an applicable source patch or remove it after the
unchanged installed-login accessibility test passes without it.

The same source package applies `authentik-known-device-cookie.patch` so the
remembered-device cookie is HttpOnly and uses the request's secure transport
flag. It also makes the native session middleware honor Django's
`SESSION_COOKIE_SAMESITE` (`Lax` by default) for creation, renewal and deletion
instead of forcing `None` over TLS. NAS browser applications share an origin;
retain native session signing, expiry, binding and transport security. Keep
this patch until upstream provides equivalent protection. Do not make the CSRF
cookie HttpOnly: the native interface reads it to construct its CSRF request
header. Dependency updates require installed login, logout and CSRF/session
qualification, not just source-patch checks.

`authentik-blueprint-apply-failure.patch` makes the native `ak apply_blueprint`
command exit nonzero when the importer's atomic apply returns false. Validation
and apply are separate transactions; successful validation does not guarantee
successful apply. Keep this patch until upstream propagates apply failures, so
the V2 reconciler cannot commit its object manifest after a rolled-back import.
The behavioral fixture in `test_authentik_blueprint_patch.py` covers the command
from upstream Authentik 2025.12.6; dependency updates must preserve this contract.

Authentik's [documented CSP](https://docs.goauthentik.io/security/security-hardening/#content-security-policy-csp)
uses inline scripts and styles. `authentik-csp.patch` replaces that requirement
with django-csp 4 per-response nonces in the canonical source package. Server
templates nonce inline scripts/styles and set `window.litNonce` before loading
Lit, including its stylesheet fallback. Dynamic frontend styles use CSSOM
property bindings instead of CSP-blocked style attributes. The locked Web
Components 2.8.0 bundle injects one fixed unresolved-element stylesheet without
nonce support; `style-src` authorizes only its exact SHA256, tested against the
complete upstream source fixture. Dependency changes must requalify that hash;
style attributes and `unsafe-hashes` remain forbidden. The upstream build's
style loader converts the locked PatternFly tooltip's two `styleMap` bindings
to CSSOM property bindings, including its floating-position custom property;
unrecognized dependency styling fails the build rather than silently weakening
CSP. The proxy preserves
upstream response policies, including stricter uploaded-file CSP, and supplies
a same-origin fallback only when no policy exists.

Keep script/style `unsafe-inline` and `unsafe-eval` disabled. Both public proxy
configurations enforce COEP `require-corp`, COOP `same-origin` and CORP
`same-origin`; the installed avatar default uses local initials. Dependency
updates must retain these boundaries and pass installed login, private API,
CSRF/session, accessibility and native/fallback stylesheet checks in every
browser engine. Source patch applicability and fixture checks alone do not
qualify installed compatibility or clean ZAP scans.

## Upgrade qualification pin

The official-ISO upgrade rehearsal pins nixpkgs revision
`36f2e6c0b6b6de4e7269e8996cf2dbb9cb5a29ac` (NixOS 26.05, June 30,
2026). It provides Syncthing 2.0.15, older than the reviewed lock's package.
Keep the revision immutable so CI exercises the same old-to-new transition.
The shared test declaration lives in `tests/vm/package-upgrade-baseline.sh`.
Install and initialize that baseline before promoting to the reviewed lock;
downgrading an already-migrated native database is not an upgrade rehearsal.
