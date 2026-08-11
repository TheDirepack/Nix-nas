import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import {fileURLToPath} from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

function text(name) {
  return fs.readFileSync(path.join(root, name), "utf8");
}

test("browser sources avoid direct HTML/code injection sinks", () => {
  const sources = [
    "cockpit/src/app.jsx",
    "cockpit/src/api.js",
    "cockpit/src/view-model.js",
    "web/portal/index.html",
  ]
    .map(text)
    .join("\n");
  for (const sink of [
    "dangerouslySetInnerHTML",
    "document.write(",
    "insertAdjacentHTML(",
    "eval(",
    "new Function(",
    "javascript:",
  ]) {
    assert.equal(sources.includes(sink), false, sink);
  }
});

test("external-target links keep opener isolation", () => {
  const app = text("cockpit/src/app.jsx");
  const externalAnchors = [
    ...app.matchAll(/<Button[^>]+component="a"[^>]+target="_blank"[^>]*>/g),
  ].map((match) => match[0]);
  assert.ok(externalAnchors.length > 0);
  for (const anchor of externalAnchors) assert.match(anchor, /rel="noopener noreferrer"/);
});

test("Caddy portal escapes identity fields at output contexts", () => {
  const portal = text("web/portal/index.html");
  assert.match(portal, /Remote-Name" \| html/);
  assert.match(portal, /Remote-User" \| urlquery/);
});

import {
  inactiveServiceCount,
  managedApplicationLinks,
  managedServiceMap,
  managedServiceOperationsBusy,
  managedServiceRows,
  managedServiceRuntimeText,
  managedServiceUnitState,
  mib,
  operationBusy,
  revisionModel,
  safeInternalPath,
  setupModel,
  staticLinks,
  visibleOperations,
} from "../../cockpit/src/view-model.js";
import {parseJsonOutput} from "../../cockpit/src/api.js";

function seeded(seed) {
  let state = seed >>> 0;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return (state >>> 0) / 0x100000000;
  };
}

function fuzzValue(random, depth = 0) {
  const hostile = [
    null,
    true,
    false,
    0,
    -1,
    2 ** 31 - 1,
    "",
    "../",
    "' OR 1=1 --",
    '<img src=x onerror="globalThis.__nas_xss=1">',
    "\r\nX-Injected: yes",
    "A".repeat(2048),
  ];
  if (depth >= 3 || random() < 0.55) return hostile[Math.floor(random() * hostile.length)];
  if (random() < 0.5)
    return Array.from({length: Math.floor(random() * 6)}, () => fuzzValue(random, depth + 1));
  const result = {};
  for (let i = 0; i < Math.floor(random() * 6); i += 1)
    result[`k${Math.floor(random() * 20)}`] = fuzzValue(random, depth + 1);
  return result;
}

test("V2 view-model helpers stay total over malformed JSON-shaped backend data", () => {
  const random = seeded(0x4e415332);
  const functions = [
    (value) => managedServiceMap(value),
    (value) => managedServiceRows(value),
    (value) => inactiveServiceCount(value),
    (value) => revisionModel(value),
    (value) => staticLinks(value),
    (value) => managedApplicationLinks(value),
    (value) => safeInternalPath(value),
    (value) => setupModel(value),
    (value) => managedServiceUnitState(value),
    (value) => managedServiceRuntimeText(value),
    (value) => operationBusy(value, "health"),
    (value) => managedServiceOperationsBusy(value),
    (value) => visibleOperations(value),
    (value) => mib(value),
  ];
  for (let i = 0; i < 2000; i += 1) {
    const value = fuzzValue(random);
    for (const fn of functions) assert.doesNotThrow(() => fn(value));
  }
});

test("V2 link helpers fail closed on external and control-character paths", () => {
  for (const value of [
    "//evil.invalid/",
    "https://evil.invalid/",
    "javascript:alert(1)",
    "/ok\r\nX-Injected: yes",
  ]) {
    assert.equal(safeInternalPath(value), null);
  }
  assert.deepEqual(
    managedApplicationLinks({
      managedServiceLinks: [
        {id: "bad", label: "bad", url: "//evil.invalid/"},
        {id: "good", label: "good", url: "/shares/"},
      ],
    }).map((entry) => entry.id),
    ["good"],
  );
});

test("JSON output parser accepts JSON only and never evaluates injected code", () => {
  globalThis.__nas_xss = 0;
  const payload = JSON.stringify({
    value: "<script>globalThis.__nas_xss=1</script>",
    nested: {constructor: {prototype: {polluted: true}}},
  });
  const parsed = parseJsonOutput(payload);
  assert.equal(parsed.value.includes("<script>"), true);
  assert.equal(globalThis.__nas_xss, 0);
  assert.equal({}.polluted, undefined);
  for (const invalid of [
    "",
    "{",
    "undefined",
    "(()=>{globalThis.__nas_xss=1})()",
    "<script>alert(1)</script>",
  ]) {
    assert.throws(() => parseJsonOutput(invalid));
  }
  assert.equal(globalThis.__nas_xss, 0);
});
