# Cockpit distribution

This directory contains the verified React/PatternFly build output (`index.js`, `index.css`, `index.html`, `manifest.json`, `build-meta.json`, `assets/`) generated via `npm ci && npm run build` inside the VM harness. The previous source-only placeholder has been replaced by a reproducible build that is Nix-verified via `build-meta.json`.

For source-only archives, this file would be the sole placeholder and Nix packaging would refuse to install it until a proper build is present.
