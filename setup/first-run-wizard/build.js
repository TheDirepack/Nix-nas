/**
 * first-run-wizard build script.
 * Bundles the React/PatternFly wizard into dist/ for Nix packaging.
 * The Nix derivation (nasInternal firstRunWizardStatic) verifies and
 * installs these assets; nothing is written outside this directory.
 *
 * Source-bound reproducible contract shared with Cockpit through
 * scripts/frontend-build-integrity.cjs: `node build.js` rebuilds dist/
 * with fresh build-meta.json, while `node build.js --check` verifies the
 * committed output without writing anything. A source change without a
 * rebuild, or missing/stale/tampered output, fails check mode.
 */

const fs = require('fs');
const path = require('path');

const ROOT = __dirname;
const SRC = path.resolve(ROOT, 'src');
const ENTRY = path.resolve(SRC, 'index.jsx');
const INDEX_HTML = path.resolve(ROOT, 'index.html');
const OUTDIR = path.resolve(ROOT, 'dist');
// The Nix sandbox overrides the helper location because only selected
// paths enter the store. Otherwise the helper is located by walking up
// toward the repository root so staged copies keep working.
function resolveHelper() {
  if (process.env.NAS_FRONTEND_INTEGRITY_HELPER) return process.env.NAS_FRONTEND_INTEGRITY_HELPER;
  let dir = ROOT;
  for (let depth = 0; depth < 5; depth++) {
    const candidate = path.join(dir, 'scripts', 'frontend-build-integrity.cjs');
    if (fs.existsSync(candidate)) return candidate;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return path.resolve(ROOT, '..', '..', 'scripts', 'frontend-build-integrity.cjs');
}
const integrity = require(resolveHelper());

const MODE = process.argv[2] || 'build';
const VALID_MODES = new Set(['build', 'watch', '--watch', 'check', '--check', 'check-source', '--check-source']);
if (!VALID_MODES.has(MODE) || process.argv.length > 3) {
  console.error('Usage: node build.js [build|--watch|--check|--check-source]');
  process.exit(2);
}

function inputPaths() {
  const inputs = [...integrity.listFiles(SRC), INDEX_HTML, path.join(ROOT, 'package.json'), path.join(ROOT, 'build.js')];
  const lock = path.join(ROOT, 'package-lock.json');
  if (fs.existsSync(lock)) inputs.push(lock);
  return inputs;
}

function sourceHash() {
  return integrity.sourceHash(ROOT, inputPaths());
}

function sourceCheck() {
  const packageJson = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  const required = {
    '@patternfly/patternfly': '6.1.0',
    '@patternfly/react-core': '6.1.0',
    react: '18.3.1',
    'react-dom': '18.3.1',
  };
  for (const [name, version] of Object.entries(required)) {
    if (packageJson.dependencies?.[name] !== version) throw new Error(`${name} must be pinned to ${version}`);
  }
  const index = fs.readFileSync(path.join(SRC, 'index.jsx'), 'utf8');
  if (!index.includes('createRoot') || !index.includes('@patternfly/patternfly/patternfly.css')) {
    throw new Error('Wizard entry point is not a React/PatternFly entry point');
  }
  // @patternfly/react-core 6.1.0 builds wizard steps exclusively from
  // WizardStep children; the steps-array prop arrived in a later 6.x.
  if (index.includes('steps={[')) throw new Error('Wizard entry point uses the unsupported steps-array prop');
  if (!index.includes('<WizardStep')) throw new Error('Wizard entry point does not declare WizardStep children');
}

function esbuildOptions(metafile) {
  return {
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
    metafile,
  };
}

function loadEsbuild() {
  try {
    return require('esbuild');
  } catch (error) {
    throw new Error(`Wizard build dependencies are unavailable. Run npm ci before building. ${error.message}`);
  }
}

function copyAssets() {
  fs.mkdirSync(OUTDIR, { recursive: true });
  fs.copyFileSync(INDEX_HTML, path.join(OUTDIR, 'index.html'));
}

async function build() {
  sourceCheck();
  if (!fs.existsSync(path.join(ROOT, 'package-lock.json'))) {
    throw new Error('setup/first-run-wizard/package-lock.json is missing. Run npm ci before building an installable bundle.');
  }
  const esbuild = loadEsbuild();
  fs.rmSync(OUTDIR, { recursive: true, force: true });
  fs.mkdirSync(OUTDIR, { recursive: true });
  if (MODE === 'watch' || MODE === '--watch') {
    const context = await esbuild.context(esbuildOptions(false));
    await context.watch();
    copyAssets();
    console.log('Watching setup/first-run-wizard/src and rebuilding dist/');
    await new Promise(() => {});
    return;
  }
  const result = await esbuild.build(esbuildOptions(true));
  copyAssets();
  integrity.writeBuildMeta({
    outputDir: OUTDIR,
    schemaVersion: 2,
    sourceSha256: sourceHash(),
    inputs: Object.keys(result.metafile.inputs).sort(),
    outputFiles: integrity.outputRecords(OUTDIR),
  });
}

function check() {
  sourceCheck();
  if (!fs.existsSync(path.join(ROOT, 'package-lock.json'))) {
    throw new Error('setup/first-run-wizard/package-lock.json is required for a complete bundle check');
  }
  integrity.checkBundle({
    label: 'setup/first-run-wizard',
    sourceSha256: sourceHash(),
    outputDir: OUTDIR,
    schemaVersion: 2,
    requiredAssets: ['index.html', 'first-run-wizard.js', 'first-run-wizard.css', 'build-meta.json'],
    missingHint: 'run npm ci and node build.js in setup/first-run-wizard/',
    staleHint: 'rebuild the wizard bundle with node build.js in setup/first-run-wizard/',
    extraVerify: (outputDir) => {
      const html = fs.readFileSync(path.join(outputDir, 'index.html'), 'utf8');
      if (!html.includes('src="./first-run-wizard.js"') || !html.includes('href="./first-run-wizard.css"')) {
        throw new Error('Wizard distribution entry point is invalid');
      }
    },
  });
}

async function main() {
  try {
    if (MODE === 'check-source' || MODE === '--check-source') sourceCheck();
    else if (MODE === 'check' || MODE === '--check') check();
    else await build();
  } catch (err) {
    console.error(`first-run-wizard: ${err.message}`);
    process.exit(1);
  }
}

main();
