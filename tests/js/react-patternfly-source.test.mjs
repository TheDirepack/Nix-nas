import test from "node:test";
import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import {spawnSync} from "node:child_process";
import {fileURLToPath} from "node:url";

const source = async (name) => readFile(new URL(`../../cockpit/${name}`, import.meta.url), "utf8");

const APP_SHELL = "src/app.jsx";
const PAGES = [
  "src/pages/overview-page.jsx",
  "src/pages/services-page.jsx",
  "src/pages/applications-page.jsx",
  "src/pages/operations-page.jsx",
  "src/pages/ai-page.jsx",
  "src/pages/source-page.jsx",
  "src/pages/setup-page.jsx",
];
const COMPONENTS = [
  "src/components/status-label.jsx",
  "src/components/output-block.jsx",
  "src/components/section-header.jsx",
  "src/components/link-card.jsx",
  "src/components/service-card.jsx",
];
const ALL_JSX = [APP_SHELL, ...PAGES, ...COMPONENTS, "src/schema-editor.jsx"];

test("Cockpit entry point mounts React 18 and loads PatternFly 6 styles", async () => {
  const index = await source("src/index.jsx");
  assert.match(index, /createRoot/);
  assert.match(index, /@patternfly\/patternfly\/patternfly\.css/);
  assert.match(index, /<React\.StrictMode>/);
});

test("application shell uses PatternFly page components instead of legacy DOM rendering", async () => {
  const app = await source(APP_SHELL);
  assert.match(app, /from "@patternfly\/react-core"/);
  for (const component of ["<Page", "<PageSection", "<Nav", "<NavItem", "<Button", "<Title"]) {
    assert.ok(app.includes(component), `missing ${component}`);
  }
  const everything = (await Promise.all(ALL_JSX.map(source))).join("\n");
  for (const component of ["<Card", "<Form", "<Checkbox", "<Alert", "<Label"]) {
    assert.ok(everything.includes(component), `missing ${component}`);
  }
  for (const name of ALL_JSX) {
    const text = await source(name);
    for (const legacy of ["innerHTML", "querySelector", "createElement", "window.confirm"]) {
      assert.equal(text.includes(legacy), false, `${name} uses legacy renderer API: ${legacy}`);
    }
    for (const raw of ["<select", "<option", "<input"]) {
      assert.equal(text.includes(raw), false, `${name} uses a raw form control: ${raw}`);
    }
  }
});

test("destructive operations confirm through a danger dialog, not inline cards", async () => {
  const operations = await source("src/pages/operations-page.jsx");
  assert.match(operations, /<Modal\b/);
  assert.match(operations, /titleIconVariant="warning"/);
  assert.match(operations, /variant="danger"/);
  const shell = await source(APP_SHELL);
  assert.equal(shell.includes("window.confirm"), false);
});

test("pages are registered modules behind the single-page navigation shell", async () => {
  const app = await source(APP_SHELL);
  assert.match(app, /const PAGES = \[/);
  assert.match(
    app,
    /href=\{`#\/\$\{id\}`\}/,
    "nav items must be hash links for keyboard reachability",
  );
  assert.match(app, /hashchange/, "the shell must follow browser history navigation");
  for (const page of PAGES) {
    const text = await source(page);
    assert.match(text, /export function /, `${page} must export its page component`);
    assert.ok(
      app.includes(`from "./pages/${page.split("/").pop()}"`),
      `${page} must be registered in the shell`,
    );
  }
});

test("managed services editor is generated from the canonical schema with YAML as advanced mode", async () => {
  const services = await source("src/pages/services-page.jsx");
  const schemaEditor = await source("src/schema-editor.jsx");
  const schemaModel = await source("src/schema-model.js");
  assert.match(services, /<SchemaEditor schema=\{document\.schema\} value=\{formValue\}/);
  assert.match(services, /replaceManagedServicesJsonDocument/);
  assert.match(services, /Advanced YAML/);
  assert.match(schemaEditor, /additionalProperties/);
  assert.match(schemaEditor, /variantOptions/);
  assert.match(schemaModel, /resolved\.oneOf/);
  for (const component of ["<FormSelect", "<Checkbox", "<TextInput"]) {
    assert.ok(schemaEditor.includes(component), `schema editor must use ${component}`);
  }
  assert.equal(schemaEditor.includes("<select"), false, "schema editor uses a raw select");
  assert.equal(schemaEditor.includes("<input"), false, "schema editor uses a raw input");
  for (const application of [
    "copyparty",
    "syncthing",
    "grafana",
    "ai-runtime",
    "ai-workspace",
    "ntfy",
  ]) {
    assert.equal(
      schemaEditor.includes(application),
      false,
      `${application} must not be special-cased in schema UI`,
    );
    assert.equal(
      schemaModel.includes(application),
      false,
      `${application} must not be special-cased in schema model`,
    );
  }
});

test("build follows the Starter Kit esbuild and Sass source-to-dist pattern", async () => {
  const build = await source("build.js");
  const packageJson = JSON.parse(await source("package.json"));
  assert.match(build, /import\("esbuild"\)/);
  assert.match(build, /import\("esbuild-sass-plugin"\)/);
  assert.match(build, /sourceSha256/);
  assert.equal(packageJson.dependencies.react, "18.3.1");
  assert.equal(packageJson.dependencies["@patternfly/react-core"], "6.1.0");
  const buildScript = fileURLToPath(new URL("../../cockpit/build.js", import.meta.url));
  const result = spawnSync(process.execPath, [buildScript, "--check-source"], {
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);
});

test("manifest does not weaken Cockpit content security policy", async () => {
  const manifest = JSON.parse(await source("src/manifest.json"));
  assert.equal(manifest["content-security-policy"].includes("unsafe-inline"), false);
  assert.equal(manifest.requires.cockpit, "300");
});
