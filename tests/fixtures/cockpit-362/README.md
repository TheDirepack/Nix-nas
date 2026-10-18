# Cockpit 362 behavior fixtures

The upstream source is `cockpit-project/cockpit` commit
`ca0d360e3a858a7eb189edde15cf7b976018404b` (tag `362`), selected by the
repository's locked nixpkgs package.

- `packages.py.txt` contains the unchanged `Document` declaration and
  `Package.get_content_security_policy` / `load_file` methods from
  `src/cockpit/packages.py`, with standard-library imports and a minimal class
  wrapper. Full upstream file SHA256:
  `f95afb2b3d2305a9b1b2eadc55a7a1247d3473b434e2262044b96b107162b107`.
- `manifest-routing.ts.txt` contains unchanged lines 71–241 from
  `pkg/shell/util.tsx`, with its copyright notice and runtime Cockpit import.
  Full upstream file SHA256:
  `0c77e95e0fb85ccd86ade6b1a428451330b05fbf0d0a7be1c639c44c15aca15d`.

Tests execute the upstream policy/file-serving and menu/frame-routing code, not
an independently implemented policy or route resolver. The JavaScript fixture
needs only an inert `gettext`; TypeScript-only imports are omitted. Fixtures do
not enter runtime packages. An upstream package update must recheck these code
paths and the source patch against the new pinned source, then qualify installed
browser behavior and security again.
