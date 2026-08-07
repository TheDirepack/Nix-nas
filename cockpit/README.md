# Cockpit NAS package

The NAS interface is a Cockpit Starter Kit-style React application built with PatternFly 6. Keep the browser as a presentation layer: every privileged decision and action remains in the fixed `nas-cockpit-api` backend boundary.

## Layout

- `src/app.jsx` — page composition and operator interactions.
- `src/view-model.js` — pure labels, filtering, and display-state helpers.
- `src/api.js` — the narrow Cockpit process bridge.
- `src/app.scss` — NAS-specific layout only; PatternFly supplies the design system.
- `build.js` — esbuild/Sass compilation into the self-contained `dist/` payload.

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
