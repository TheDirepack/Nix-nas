# Source-only Cockpit placeholder

This development archive intentionally does not contain the compiled browser bundle or npm lockfile. Restore or generate the reviewed `package-lock.json` on a controlled network-enabled builder, run `npm ci --no-audit --no-fund`, then run the Cockpit checks/build and complete release preflight.

Nix packaging refuses to install this placeholder until the verified `index.js`, `index.css`, `index.html`, `manifest.json`, and `build-meta.json` payload is present.
