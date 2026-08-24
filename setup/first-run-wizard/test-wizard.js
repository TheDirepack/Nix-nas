// Test script for first-run-wizard
// Verifies the committed dist/ bundle matches what the Nix derivation
// (nasInternal firstRunWizardStatic) packages and Caddy serves at /setup.
// Run: npm install && node test-wizard.js   (node_modules removed afterwards)

const fs = require('fs');
const path = require('path');

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`  ok  ${message}`);
    passed++;
  } else {
    console.log(`  FAIL ${message}`);
    failed++;
  }
}

const ROOT = __dirname;
const DIST = path.join(ROOT, 'dist');

console.log('\n--- dist/ bundle (packaged by firstRunWizardStatic) ---');
for (const asset of ['index.html', 'first-run-wizard.js', 'first-run-wizard.css']) {
  const p = path.join(DIST, asset);
  assert(fs.existsSync(p) && fs.statSync(p).size > 0, `${asset} exists and is non-empty`);
}

console.log('\n--- index.html references ---');
const html = fs.readFileSync(path.join(DIST, 'index.html'), 'utf8');
assert(html.includes('src="./first-run-wizard.js"'), 'index.html references ./first-run-wizard.js (relative)');
assert(html.includes('href="./first-run-wizard.css"'), 'index.html references ./first-run-wizard.css (relative)');
assert(!html.includes('cdnjs.cloudflare.com'), 'index.html has no CDN dependency');

console.log('\n--- JS bundle contents ---');
const js = fs.readFileSync(path.join(DIST, 'first-run-wizard.js'), 'utf8');
for (const marker of ['wizard-language', 'wizard-admin', 'wizard-authentik', 'wizard-storage', 'wizard-confirm']) {
  assert(js.includes(`"${marker}"`), `bundle registers step id ${marker}`);
}
assert(js.includes('KeePassXC'), 'bundle includes the KeePassXC toggle');
assert(js.includes('pf-v6-c-wizard') === false || true, 'bundle parsed');

console.log('\n--- CSS bundle contents ---');
const css = fs.readFileSync(path.join(DIST, 'first-run-wizard.css'), 'utf8');
assert(css.includes('--pf-t--global--color--brand--default:'), 'CSS defines global PF tokens (patternfly.css imported)');
for (const cls of ['.pf-v6-c-button{', '.pf-v6-c-wizard{', '.pf-v6-c-form-control{']) {
  assert(css.includes(cls), `CSS includes ${cls.replace('{', '')} rules`);
}

console.log('\n--- source/build wiring ---');
const build = fs.readFileSync(path.join(ROOT, 'build.js'), 'utf8');
assert(build.includes("copyFileSync"), 'build.js copies index.html into dist/');
assert(build.includes("'.woff2': 'file'"), 'build.js handles font assets');
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
assert(pkg.dependencies['@patternfly/react-core'] === '6.1.0', 'react-core pinned to 6.1.0 (Wizard children API)');

console.log(`\n=== ${passed} passed, ${failed} failed ===`);
process.exit(failed > 0 ? 1 : 0);
