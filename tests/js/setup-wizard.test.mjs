import test from "node:test";
import assert from "node:assert/strict";
import {readFile, stat} from "node:fs/promises";
import {fileURLToPath} from "node:url";

const wizard = async (name) =>
  readFile(new URL(`../../setup/first-run-wizard/${name}`, import.meta.url), "utf8");
const exists = async (name) => {
  try {
    await stat(new URL(`../../setup/first-run-wizard/${name}`, import.meta.url));
    return true;
  } catch {
    return false;
  }
};

const STEPS = [
  "wizard-language",
  "wizard-admin",
  "wizard-storage",
  "wizard-confirm",
];

test("wizard entry mounts React and imports PatternFly global styles", async () => {
  const index = await wizard("src/index.jsx");
  assert.match(index, /createRoot/);
  assert.match(index, /@patternfly\/patternfly\/patternfly\.css/);
  assert.match(index, /nas-setup-shell/);
  assert.match(index, /pf-v6-theme-dark/);
  assert.match(index, /Browser setting/);
  assert.match(index, /prefers-color-scheme/);
});

test("wizard builds steps from WizardStep children with explicit ids", async () => {
  const index = await wizard("src/index.jsx");
  // @patternfly/react-core 6.1.0 ignores the steps-array prop; without an id
  // on every step, activeStep?.id === step.id is undefined === undefined and
  // every pane renders into the body at once.
  assert.doesNotMatch(index, /steps\s*=\s*\{?\s*\[/);
  for (const id of STEPS) {
    assert.match(index, new RegExp(`<WizardStep[^>]*id="${id}"`), `missing WizardStep id ${id}`);
  }
  assert.equal(
    (index.match(/<WizardStep /g) ?? []).length,
    STEPS.length,
    "unexpected extra wizard steps",
  );
});

test("wizard step components use exports that exist in react-core 6.1.0", async () => {
  for (const step of ["LanguageStep", "AdminStep", "StorageStep", "ConfirmStep"]) {
    const text = await wizard(`src/steps/${step}.jsx`);
    assert.match(
      text,
      /from ['"]@patternfly\/react-core['"]/,
      `${step} must use PatternFly components`,
    );
    assert.match(text, /export default/, `${step} must default-export its component`);
    assert.doesNotMatch(
      text,
      /[^a-zA-Z]Input[,}]/,
      `${step} imports removed v6 "Input"; use TextInput`,
    );
    assert.doesNotMatch(
      text,
      /innerHTML|querySelector|document\.createElement/,
      `${step} uses legacy DOM APIs`,
    );
  }
});

test("admin step gates the KeePassXC database password behind the shared-password toggle", async () => {
  const admin = await wizard("src/steps/AdminStep.jsx");
  assert.match(admin, /KeePassXC/);
  assert.match(admin, /useSamePassword/);
  assert.match(admin, /wizard-keepass-password/);
  assert.match(
    admin,
    /wizard-admin-password-confirm/,
    "administrator password needs a confirm field",
  );
});

test("administrator username starts blank and has no schema default", async () => {
  const index = await wizard("src/index.jsx");
  const api = await wizard("src/api.js");
  const schema = JSON.parse(await wizard("src/forms/schema.json"));
  assert.match(index, /emptyAdministrator = \{ username: ''/);
  assert.doesNotMatch(
    api,
    /adminUsername: schema\.properties\.adminUsername\.default \|\| 'admin'/,
  );
  assert.equal(schema.properties.adminUsername.default, undefined);
});

test("setup uses searchable locale controls and keeps storage configuration actionable", async () => {
  const language = await wizard("src/steps/LanguageStep.jsx");
  const storage = await wizard("src/steps/StorageStep.jsx");
  assert.match(language, /Select/);
  assert.match(language, /typeahead/);
  assert.match(language, /Search languages/);
  assert.match(language, /Search cities or regions/);
  assert.match(language, /Intl\.supportedValuesOf/);
  assert.match(language, /Current browser time zone/);
  assert.match(language, /nas-searchable-select-toggle/);
  assert.match(storage, /\/console\/storage/);
  assert.match(storage, /\/console\/system\/terminal/);
  assert.match(storage, /Refresh plan/);
  assert.doesNotMatch(
    await wizard("src/index.jsx"),
    /AuthentikStep|wizard-authentik|Authentik Integration/,
  );
  assert.equal(
    await exists("src/steps/AuthentikStep.jsx"),
    false,
    "the removed Authentik step must not remain as dead UI",
  );
});

test("setup stylesheet provides a full-height responsive shell and dark-mode tokens", async () => {
  const css = await wizard("src/wizard.css");
  assert.match(css, /min-height: 100dvh/);
  assert.match(css, /height: 100dvh/);
  assert.match(css, /--pf-v6-c-wizard--Height: 100%/);
  assert.match(css, /pf-v6-c-wizard__outer-wrap/);
  assert.match(css, /@media \(prefers-color-scheme: dark\)/);
  assert.match(css, /\.pf-v6-theme-dark/);
  assert.match(css, /@media \(max-width: 40rem\)/);
  assert.match(css, /nas-searchable-select-toggle/);
  assert.match(css, /--nas-setup-control-border/);
  assert.match(css, /width: min\(100%, 52rem\)/);
});

test("wizard shell references only relative, locally served assets", async () => {
  const html = await wizard("index.html");
  assert.match(html, /src="\.\/first-run-wizard\.js"/);
  assert.match(html, /href="\.\/first-run-wizard\.css"/);
  assert.doesNotMatch(html, /https?:\/\//, "wizard shell must not depend on CDN assets");
});

test("build script emits the reviewed dist layout the Nix derivation packages", async () => {
  const build = await wizard("build.js");
  assert.match(build, /outdir:\s*OUTDIR/);
  assert.match(build, /copyFileSync/, "build.js must copy index.html into dist/");
  assert.match(build, /['"]\.woff2['"]:\s*['"]file['"]/, "build.js must emit font assets");
  for (const asset of ["index.html", "first-run-wizard.js", "first-run-wizard.css"]) {
    assert.ok(await exists(`dist/${asset}`), `dist/${asset} must be committed`);
  }
  assert.ok(await exists("dist/assets"), "dist font assets must be committed");
});

test("committed bundle registers every step and the storage setup links", async () => {
  const js = await wizard("dist/first-run-wizard.js");
  for (const id of STEPS) {
    assert.ok(js.includes(`"${id}"`), `bundle is missing step id ${id}`);
  }
  assert.ok(js.includes("KeePassXC"), "bundle is missing the KeePassXC toggle");
  assert.ok(js.includes("Browser setting"), "bundle is missing the browser theme option");
  assert.ok(js.includes("Open Storage"), "bundle is missing the storage console link");
  assert.ok(!js.includes("wizard-authentik"), "bundle still contains the removed Authentik step");
});

test("committed stylesheet carries the global tokens and core component rules", async () => {
  const css = await wizard("dist/first-run-wizard.css");
  assert.ok(
    css.includes("--pf-t--global--color--brand--default:"),
    "patternfly.css tokens are missing",
  );
  for (const rule of [".pf-v6-c-button{", ".pf-v6-c-wizard{", ".pf-v6-c-form-control{"]) {
    assert.ok(css.includes(rule), `stylesheet is missing ${rule}`);
  }
  assert.ok(css.includes(".nas-setup-shell{"), "stylesheet is missing the full-height setup shell");
  assert.ok(css.includes(".pf-v6-theme-dark"), "stylesheet is missing dark-mode overrides");
  assert.ok(
    css.includes(".nas-searchable-select-toggle{"),
    "stylesheet is missing visible locale control chrome",
  );
});

test("dist index.html matches the reviewed source shell", async () => {
  const [source, dist] = await Promise.all([wizard("index.html"), wizard("dist/index.html")]);
  assert.equal(
    dist,
    source,
    "dist/index.html is stale; run node build.js in setup/first-run-wizard/",
  );
});

test("wizard pins the same PatternFly generation as the cockpit plugin", async () => {
  const [wizardPkg, cockpitPkg] = await Promise.all([
    wizard("package.json").then(JSON.parse),
    readFile(new URL("../../cockpit/package.json", import.meta.url), "utf8").then(JSON.parse),
  ]);
  for (const dep of ["@patternfly/patternfly", "@patternfly/react-core", "react", "react-dom"]) {
    assert.equal(
      wizardPkg.dependencies[dep],
      cockpitPkg.dependencies[dep],
      `${dep} diverges from cockpit`,
    );
  }
  assert.ok(await exists("package-lock.json"), "a reviewed lockfile must be committed");
});
