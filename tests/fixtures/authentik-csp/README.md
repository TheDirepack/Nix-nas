# Authentik CSP fixtures

Unmodified Authentik 2025.12.6 templates and selected settings sections from
upstream revision `e1c90f3fae9d86d6a7a4f36018dafa9a1554f670` (MIT license).
The `.txt` suffix prevents repository Python validation from importing upstream
settings. Tests apply the production source patch before rendering templates
with Django and django-csp. Full patch applicability is also checked against the
complete pinned upstream source during qualification.

`lit-html/` contains the complete unmodified browser renderer, directive base,
styleMap module and BSD-3-Clause license from the npm dependency locked by that
same Authentik revision. `lit-html.json` records the upstream lockfile SHA256,
package URL/SHA512 integrity and each fixture's SHA256. Refresh these from the
locked tarball, verifying its integrity before extracting; never reconstruct the
runtime from a mock or substitute a different Lit version.

The Node fixture helper materializes these files in an isolated temporary tree,
applies the production build-loader patch and imports that loader unchanged.
Only logging and package-location dependencies are stubbed. The Playwright
regression in `cockpit/e2e/authentik-csp.spec.mjs` bundles the real renderer and
directive through that plugin and executes them under an HTTP CSP, alongside
unpatched-Lit and hostile-attribute controls. Run it with the deterministic
browser suite in each configured engine; source-only Python checks do not
replace that browser qualification.
