# Cockpit NAS package

The NAS interface is a Cockpit Starter Kit-style React application built with PatternFly 6. Keep the browser as a presentation layer: every privileged decision and action remains in the fixed `nas-cockpit-api` backend boundary.

## Layout

- `src/app.jsx` — single-page shell: section registry, PatternFly nav, alerts, secrets unlock.
- `src/pages/` — one module per section; add a section with one file plus one registry entry.
- `src/components/` — shared presentation components (status labels, output blocks, cards).
- `src/hooks/` — overview fetch and mutation (busy/error/notice) state hooks.
- `src/schema-editor.jsx` + `src/schema-model.js` — form generated from the canonical JSON Schema.
- `src/view-model.js` — pure labels, filtering, and display-state helpers.
- `src/api.js` — the narrow Cockpit process bridge.
- `src/cockpit-dark-theme.js` — vendored Cockpit shell dark-mode sync (`pf-v6-theme-dark`).
- `src/app.scss` — NAS-specific layout only; PatternFly supplies the design system.
- `build.js` — esbuild/Sass compilation into the self-contained `dist/` payload.

Destructive operations confirm through a danger PatternFly modal; form controls are
PatternFly components only (no raw `select`/`input` elements).

Passwords are cleared from React state after submission and sent only over process standard input. Destructive and privileged operations require explicit confirmation.

## Build and test

With the reviewed lockfile present:

```sh
npm ci --no-audit --no-fund
npm run check
npm test
npm run build
```

An installable release must retain the exact `package-lock.json` together with the generated `dist/index.js`, `dist/index.css`, `dist/index.html`, `dist/manifest.json`, and `dist/build-meta.json`. The Nix package intentionally rejects a source-only placeholder.

If a development archive does not contain the lockfile, restore/generate it on a controlled network-enabled builder before attempting release qualification; do not silently substitute `npm install` in the release path.
