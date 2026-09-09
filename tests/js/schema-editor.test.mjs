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

async function renderEditor(value, customSchema) {
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
    nodePaths: (process.env.NODE_PATH ?? "").split(path.delimiter).filter(Boolean),
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
  const warnings = [];
  const originalError = console.error;
  const originalWarn = console.warn;
  console.error = (...args) => {
    warnings.push(args.join(" "));
  };
  console.warn = (...args) => {
    warnings.push(args.join(" "));
  };
  globalThis.window = {__SCHEMA__: customSchema ?? schema, __VALUE__: value};
  try {
    cockpitRequire(file);
  } finally {
    delete globalThis.window;
    console.error = originalError;
    console.warn = originalWarn;
    fs.rmSync(dir, {recursive: true, force: true});
  }
  return {html: globalThis.__NAS_EDITOR_HTML__, warnings};
}

function optionalPickerLabels(html) {
  return [...html.matchAll(/aria-label="([^"]*Add optional field[^"]*)"/g)].map((match) => match[1]);
}

// A small schema with an optional leaf and a nested object that also has an
// absent optional, so root and nested pickers render side by side.
const NESTED_SCHEMA = {
  type: "object",
  properties: {
    child: {
      type: "object",
      properties: {req: {type: "string"}, optA: {type: "string"}},
      required: ["req"],
    },
    optB: {type: "string"},
  },
  required: [],
};

test("schema editor renders PatternFly form controls from the canonical V3 schema", async () => {
  const {html} = await renderEditor({});
  assert.ok(html.length > 500, "editor rendered non-trivial markup");
  assert.match(html, /pf-v6-c-form/, "uses stock PatternFly form components");
  assert.match(html, /<(input|textarea|select)\b/, "renders editable controls");
});

test("schema editor keeps hostile values inert", async () => {
  const {html} = await renderEditor({
    "<script>alert(1)</script>": {x: "</textarea><img src=x onerror=alert(2)>"},
  });
  assert.doesNotMatch(html, /<script>alert\(1\)<\/script>/, "hostile key must be entity-escaped");
  assert.doesNotMatch(html, /<\/textarea><img/, "hostile value must not break out of its field");
  assert.match(html, /&lt;script&gt;/, "escaped representation is present instead");
});

test("schema editor reflects provided values back into controlled fields", async () => {
  const {html} = await renderEditor({demo: {}});
  assert.match(html, /Key for demo/, "renders a keyed entry for the provided map key");
  assert.match(html, /value="demo"/, "controlled input carries the provided key");
});

test("server rendering emits no accessible-name warning for the optional-field picker", async () => {
  for (const value of [{}, {child: {req: "x"}}]) {
    const {warnings} = await renderEditor(value);
    assert.deepEqual(
      warnings.filter((message) => message.includes("requires either an id or aria-label")),
      [],
      `PatternFly accessible-name warning must fail the suite: ${warnings.join("; ")}`,
    );
  }
  const {warnings} = await renderEditor({}, NESTED_SCHEMA);
  assert.deepEqual(
    warnings.filter((message) => message.includes("requires either an id or aria-label")),
    [],
    `PatternFly accessible-name warning must fail the suite: ${warnings.join("; ")}`,
  );
});

test("root and nested optional-field pickers expose unique path-derived names", async () => {
  const {html} = await renderEditor({child: {req: "x"}}, NESTED_SCHEMA);
  const labels = optionalPickerLabels(html);
  assert.ok(labels.length >= 2, `expected root and nested pickers, found: ${labels.join(", ")}`);
  assert.equal(new Set(labels).size, labels.length, `picker names must be distinct: ${labels.join(", ")}`);
  for (const label of labels) {
    assert.match(label, /^Add optional field at \S+/, `picker name must derive from its schema path: ${label}`);
  }
  assert.ok(
    labels.some((label) => label === "Add optional field at root"),
    `root picker must be named for its schema path: ${labels.join(", ")}`,
  );
  assert.ok(
    labels.some((label) => label === "Add optional field at root.child"),
    `nested picker must be named for its schema path: ${labels.join(", ")}`,
  );
  const ids = [...html.matchAll(/id="(nas-schema-add-[^"]*)"/g)].map((match) => match[1]);
  assert.equal(new Set(ids).size, ids.length, `picker ids must be distinct: ${ids.join(", ")}`);
});

test("canonical schema pickers carry stable accessible names", async () => {
  const {html} = await renderEditor({});
  const labels = optionalPickerLabels(html);
  assert.ok(labels.length >= 1, "canonical schema must render at least one optional-field picker");
  assert.equal(new Set(labels).size, labels.length, `picker names must be distinct: ${labels.join(", ")}`);
});

test("optional-field picker markup stays keyboard operable", async () => {
  const {html} = await renderEditor({child: {req: "x"}}, NESTED_SCHEMA);
  const selects = [...html.matchAll(/<select\b[^>]*aria-label="([^"]*Add optional field[^"]*)"[^>]*>/g)];
  assert.ok(selects.length >= 2, "root and nested pickers must render as labelled selects");
  for (const [tag] of selects) {
    assert.doesNotMatch(tag, /\bdisabled\b/, "picker must be focusable, not disabled");
    assert.doesNotMatch(tag, /tabindex="-1"/, "picker must stay in the tab order");
  }
  assert.match(html, /<option[^>]*value="optA"/, "nested picker must offer its absent optional field");
  assert.match(html, /<option[^>]*value="optB"/, "root picker must offer its absent optional field");
  assert.match(html, />Add field<\/span><\/button>/, "adding the focused field must stay a button away");
});
