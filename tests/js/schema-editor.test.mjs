import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {createRequire} from "node:module";
import {fileURLToPath} from "node:url";

const cockpitRoot = fileURLToPath(new URL("../../cockpit/", import.meta.url));
const cockpitRequire = createRequire(path.join(cockpitRoot, "package.json"));

const esbuildPath = cockpitRequire.resolve("esbuild");
const {build} = (await import(esbuildPath)).default ?? (await import(esbuildPath));

const schema = JSON.parse(
  fs.readFileSync(new URL("../../schemas/managed-services-v3.schema.json", import.meta.url)),
);

const editorPath = path.join(cockpitRoot, "src", "schema-editor.jsx");

async function renderEditor(value) {
  const entry = `
    import {renderToString} from "react-dom/server";
    import {SchemaEditor} from ${JSON.stringify(editorPath)};
    globalThis.__NAS_EDITOR_HTML__ = renderToString(
      <SchemaEditor schema={window.__SCHEMA__} value={window.__VALUE__} onChange={() => {}} />,
    );
  `;
  const result = await build({
    stdin: {contents: entry, loader: "jsx", resolveDir: path.join(cockpitRoot, "src")},
    jsx: "automatic",
    jsxImportSource: "react",
    bundle: true,
    format: "cjs",
    platform: "node",
    write: false,
    logLevel: "silent",
    // SSR only needs the DOM markup, not PatternFly stylesheet side-effects.
    loader: {".css": "empty"},
    define: {"process.env.NODE_ENV": '"production"'},
  });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nas-schema-editor-"));
  const file = path.join(dir, "bundle.cjs");
  fs.writeFileSync(file, result.outputFiles[0].text);
  delete globalThis.__NAS_EDITOR_HTML__;
  globalThis.window = {__SCHEMA__: schema, __VALUE__: value};
  try {
    cockpitRequire(file);
  } finally {
    delete globalThis.window;
    fs.rmSync(dir, {recursive: true, force: true});
  }
  return globalThis.__NAS_EDITOR_HTML__;
}

test("schema editor renders PatternFly form controls from the canonical V3 schema", async () => {
  const html = await renderEditor({});
  assert.ok(html.length > 500, "editor rendered non-trivial markup");
  assert.match(html, /pf-v6-c-form/, "uses stock PatternFly form components");
  assert.match(html, /<(input|textarea|select)\b/, "renders editable controls");
});

test("schema editor keeps hostile values inert", async () => {
  const html = await renderEditor({"<script>alert(1)</script>": {"x": "</textarea><img src=x onerror=alert(2)>"}});
  assert.doesNotMatch(html, /<script>alert\(1\)<\/script>/, "hostile key must be entity-escaped");
  assert.doesNotMatch(html, /<\/textarea><img/, "hostile value must not break out of its field");
  assert.match(html, /&lt;script&gt;/, "escaped representation is present instead");
});

test("schema editor reflects provided values back into controlled fields", async () => {
  const html = await renderEditor({"demo": {}});
  assert.match(html, /Key for demo/, "renders a keyed entry for the provided map key");
  assert.match(html, /value="demo"/, "controlled input carries the provided key");
});
