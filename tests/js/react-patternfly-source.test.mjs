import test from "node:test";
import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import {spawnSync} from "node:child_process";
import {fileURLToPath} from "node:url";

const source = async (name) => readFile(new URL(`../../cockpit/${name}`, import.meta.url), "utf8");

test("Cockpit entry point mounts React 18 and loads PatternFly 6 styles", async () => {
  const index = await source("src/index.jsx");
  assert.match(index, /createRoot/);
  assert.match(index, /@patternfly\/patternfly\/patternfly\.css/);
  assert.match(index, /<React\.StrictMode>/);
});

test("application uses PatternFly components instead of legacy DOM rendering", async () => {
  const app = await source("src/app.jsx");
  assert.match(app, /from "@patternfly\/react-core"/);
  for (const component of ["<Card", "<Form", "<Alert", "<Label", "<Button", "<Title"]) {
    assert.ok(app.includes(component), `missing ${component}`);
  }
  for (const legacy of ["innerHTML", "querySelector", "createElement", "window.confirm"]) {
    assert.equal(app.includes(legacy), false, `legacy renderer API remains: ${legacy}`);
  }
});

test("managed services editor is generated from the canonical schema with YAML as advanced mode", async () => {
  const app = await source("src/app.jsx");
  const schemaEditor = await source("src/schema-editor.jsx");
  const schemaModel = await source("src/schema-model.js");
  assert.match(app, /<SchemaEditor schema=\{document\.schema\} value=\{formValue\}/);
  assert.match(app, /replaceManagedServicesJsonDocument/);
  assert.match(app, /Advanced YAML/);
  assert.match(schemaEditor, /additionalProperties/);
  assert.match(schemaEditor, /variantOptions/);
  assert.match(schemaModel, /resolved\.oneOf/);
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
