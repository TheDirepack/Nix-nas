import {test, expect} from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import {createRequire} from "node:module";
import {fileURLToPath} from "node:url";
import path from "node:path";

const cockpitRoot = fileURLToPath(new URL("../", import.meta.url));
const cockpitRequire = createRequire(path.join(cockpitRoot, "package.json"));
const esbuildPath = cockpitRequire.resolve("esbuild");
const {build} = (await import(esbuildPath)).default ?? (await import(esbuildPath));

// A small schema with an optional leaf and a nested object that also has an
// absent optional, so root and nested pickers render side by side. The editor
// under test is bundled straight from source; backend schema semantics are
// untouched.
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

async function openEditor(page, value) {
  const entry = `
    import React, {useState} from "react";
    import {createRoot} from "react-dom/client";
    import {SchemaEditor} from "./schema-editor.jsx";
    function Harness() {
      const [value, setValue] = useState(window.__VALUE__);
      return <SchemaEditor schema={window.__SCHEMA__} value={value} onChange={setValue} />;
    }
    createRoot(document.getElementById("root")).render(<Harness />);
  `;
  const result = await build({
    stdin: {contents: entry, loader: "jsx", resolveDir: path.join(cockpitRoot, "src")},
    jsx: "automatic",
    jsxImportSource: "react",
    bundle: true,
    format: "iife",
    platform: "browser",
    write: false,
    logLevel: "silent",
    loader: {".css": "empty"},
    define: {"process.env.NODE_ENV": '"production"'},
  });
  const pageErrors = [];
  const consoleErrors = [];
  page.on("pageerror", (error) => pageErrors.push(String(error)));
  page.on("console", (message) => {
    if (message.type() === "error") consoleErrors.push(message.text());
  });
  await page.setContent(
    `<!doctype html><html lang="en"><head><title>Schema editor accessibility fixture</title></head><body><div id="root"></div><script>window.__SCHEMA__=${JSON.stringify(NESTED_SCHEMA)};window.__VALUE__=${JSON.stringify(value)};</script><script>${result.outputFiles[0].text}</script></body></html>`,
  );
  await expect(page.locator(".nas-schema-editor")).toBeVisible();
  return {pageErrors, consoleErrors};
}

test("optional-field pickers expose distinct accessible names and stay operable by keyboard", async ({
  page,
}) => {
  const {pageErrors, consoleErrors} = await openEditor(page, {child: {req: "x"}});
  const rootPicker = page.getByRole("combobox", {name: "Add optional field at root", exact: true});
  const nestedPicker = page.getByRole("combobox", {name: "Add optional field at root.child"});
  await expect(rootPicker).toBeVisible();
  await expect(nestedPicker).toBeVisible();

  // Keyboard only: tab to the nested picker and choose optA. ArrowDown alone
  // changes a collapsed native select; Enter would open its dropdown popup.
  await nestedPicker.focus();
  await expect(nestedPicker).toBeFocused();
  await page.keyboard.press("ArrowDown");
  await expect(nestedPicker).toHaveValue("optA");

  // Tab on to its Add field button and activate it without a pointer. The
  // enabled wait flushes the select's React state before the button is used.
  const addRow = page.locator(".nas-schema-add-row", {has: nestedPicker});
  const addButton = addRow.getByRole("button", {name: "Add field"});
  await expect(addButton).toBeEnabled();
  await page.keyboard.press("Tab");
  await expect(addButton).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(addRow.getByRole("combobox", {name: "Add optional field at root.child"})).toHaveCount(0);
  await expect(addRow).toHaveCount(0);
  await expect(page.locator("legend", {hasText: "optA"}).first()).toBeVisible();

  expect(pageErrors).toEqual([]);
  expect(
    consoleErrors.filter((message) => message.includes("requires either an id or aria-label")),
  ).toEqual([]);
});

test("optional-field add flow reports no serious or critical axe violations", async ({page}) => {
  await openEditor(page, {child: {req: "x"}});
  // Focused on the affected flow: both optional-field add rows. Broader
  // editor labeling (e.g. scalar inputs under fieldset legends) is unchanged
  // by this fix and stays out of scope.
  const result = await new AxeBuilder({page})
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .include(".nas-schema-add-row")
    .analyze();
  const blocking = result.violations.filter((item) =>
    ["serious", "critical"].includes(item.impact),
  );
  expect(blocking).toEqual([]);
});
