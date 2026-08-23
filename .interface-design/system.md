# Design System — Nix-nas Cockpit UI

## Direction
Personality: Utility & Function
Foundation: PatternFly 6 defaults (no custom tokens, no custom theme)
Depth: Stock PatternFly card borders and shadows only

## Authority
- `@patternfly/react-core` 6.1 IS the design system. This repo adds zero design
  tokens of its own; all colors, spacing, radii, and typography come from
  PatternFly global CSS variables (`--pf-t--global--*`).
- Cockpit shell integration follows the current upstream starter kit
  (verified 2026): React 18.3.1 + PF 6.1 + esbuild/esbuild-sass-plugin.
- Shared imports to adopt from Cockpit `pkg/lib`: `cockpit-dark-theme`
  (dark-mode sync) and `patternfly/patternfly-6-cockpit.scss`
  (Cockpit-tuned PF base) in place of raw `patternfly.css`.
- Navigation is a single-page app with the stock PatternFly `<Nav>`.
  Deliberately NOT manifest multi-entry: sections share one overview
  payload and busy/error context; menu-entry iframes would refetch per click.

## Tokens
### Spacing / Color / Type
PatternFly global CSS vars only. No bespoke hex or px values.

## Component rules
- Forms: react-core `FormSelect`, `TextInput`, `Checkbox`, `TextArea` only;
  raw `<select>` / `<input>` are forbidden (already enforced for
  schema-editor.jsx by tests/js/react-patternfly-source.test.mjs).
- Card grids: `Gallery`/`GalleryItem`, not bespoke grid classes.
- Key-value facts: `DescriptionList`, not raw `<dl>` classes.
- Destructive/privileged confirmations: `Modal` variant="danger"
  (explicit verb button), never inline cards or window.confirm.
- JSON/output dumps: single `<pre className="nas-pre">` via OutputBlock.
- Status: `Label` color green/orange via shared StatusLabel.

## Patterns
- Page header pattern: `Title h2` + muted hint line + action row
  (shared SectionHeader).
- Page registry: adding a section = one file in src/pages/ plus one entry
  in the PAGES array in app.jsx. Nothing else changes.

## Build/deps constraints
- Exact-pinned dependencies with reviewed lockfile; no new runtime deps
  (@patternfly/react-templates is beta — do not adopt).
- dist/ is generated output only; never hand-edit.
