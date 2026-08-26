/**
 * first-run-wizard build script
 * Bundles the React/PatternFly wizard into dist/ for Nix packaging.
 * The Nix derivation (nasInternal firstRunWizardStatic) verifies and
 * installs these assets; nothing is written outside this directory.
 */

const esbuild = require('esbuild');
const fs = require('fs');
const path = require('path');

const SRC = path.resolve(__dirname, 'src');
const ENTRY = path.resolve(SRC, 'index.jsx');
const OUTDIR = path.resolve(__dirname, 'dist');

async function build() {
  try {
    await esbuild.build({
      entryPoints: [ENTRY],
      bundle: true,
      minify: true,
      platform: 'browser',
      target: 'es2020',
      outdir: OUTDIR,
      entryNames: 'first-run-wizard',
      assetNames: 'assets/[name]-[hash]',
      loader: {
        '.jsx': 'jsx',
        '.woff': 'file', '.woff2': 'file', '.svg': 'file',
        '.png': 'file', '.jpg': 'file', '.jpeg': 'file',
      },
      jsx: 'automatic',
      logLevel: 'info',
    });
    fs.copyFileSync(path.resolve(__dirname, 'index.html'), path.join(OUTDIR, 'index.html'));
  } catch (err) {
    console.error('first-run-wizard: build failed', err);
    process.exit(1);
  }
}

build();
