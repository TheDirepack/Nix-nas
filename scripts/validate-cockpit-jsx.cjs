#!/usr/bin/env node
const fs = require("node:fs");
const path = require("node:path");
const {createRequire} = require("node:module");

const root = path.resolve(__dirname, "..");
let ts;
try {
  ts = createRequire(path.join(root, "cockpit/package.json"))("typescript");
} catch {
  ts = require("typescript");
}

const sources = ["cockpit/src/index.jsx", "cockpit/src/app.jsx"];
let failed = false;
for (const relative of sources) {
  const filename = path.join(root, relative);
  const source = fs.readFileSync(filename, "utf8");
  const result = ts.transpileModule(source, {
    fileName: filename,
    compilerOptions: {
      jsx: ts.JsxEmit.ReactJSX,
      module: ts.ModuleKind.ESNext,
      target: ts.ScriptTarget.ES2020,
    },
    reportDiagnostics: true,
  });
  const diagnostics = result.diagnostics || [];
  for (const diagnostic of diagnostics) {
    failed = true;
    const message = ts.flattenDiagnosticMessageText(diagnostic.messageText, "\n");
    if (diagnostic.file && diagnostic.start !== undefined) {
      const position = diagnostic.file.getLineAndCharacterOfPosition(diagnostic.start);
      console.error(`${relative}:${position.line + 1}:${position.character + 1}: ${message}`);
    } else {
      console.error(`${relative}: ${message}`);
    }
  }
}
if (failed) process.exit(1);
console.log("Cockpit JSX syntax ok");
