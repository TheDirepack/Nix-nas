import test from "node:test";
import assert from "node:assert/strict";
import * as apiModule from "../../cockpit/src/api.js";
import {
  activateSecrets,
  api,
  apiInput,
  managedServicesDocument,
  managedServicesStatus,
  parseJsonOutput,
  replaceManagedServicesDocument,
  replaceManagedServicesJsonDocument,
  setManagedServiceMode,
} from "../../cockpit/src/api.js";

test("api uses only the fixed privileged Cockpit backend", async () => {
  const calls = [];
  const spawn = (command, options) => {
    calls.push({command, options});
    return Promise.resolve('{"ok":true}');
  };
  assert.deepEqual(await api(["overview"], spawn), {ok: true});
  assert.deepEqual(calls, [
    {
      command: ["nas-cockpit-api", "overview"],
      options: {superuser: "require", err: "message"},
    },
  ]);
});

test("Cockpit does not expose a first-run credential submission helper", () => {
  assert.equal("startFirstRun" in apiModule, false);
});

test("structured API mutations send JSON only over stdin", async () => {
  const calls = [];
  const spawn = (command, options) => {
    const process = Promise.resolve('{"ok":true}');
    process.input = (value) => calls.push(["input", value]);
    calls.push(["spawn", command, options]);
    return process;
  };
  assert.deepEqual(
    await apiInput(["ai-provider-set"], {id: "openrouter", apiKey: "secret"}, spawn),
    {ok: true},
  );
  assert.deepEqual(calls, [
    ["spawn", ["nas-cockpit-api", "ai-provider-set"], {superuser: "require", err: "message"}],
    ["input", JSON.stringify({id: "openrouter", apiKey: "secret"})],
  ]);
  assert.equal(calls[0][1].includes("secret"), false);
});

test("managed services status and document use the canonical V2 control CLI", async () => {
  const calls = [];
  const spawn = (command, options) => {
    calls.push({command, options});
    return Promise.resolve('{"ok":true,"services":[]}');
  };
  await managedServicesStatus(spawn);
  await managedServicesDocument(spawn);
  assert.deepEqual(calls, [
    {
      command: ["nas-managed-services-control", "status"],
      options: {superuser: "require", err: "message"},
    },
    {
      command: ["nas-managed-services-control", "document"],
      options: {superuser: "require", err: "message"},
    },
  ]);
});

test("managed services document replacement sends YAML only over stdin", async () => {
  const calls = [];
  const spawn = (command, options) => {
    const process = Promise.resolve('{"ok":true}');
    process.input = (value) => calls.push(["input", value]);
    calls.push(["spawn", command, options]);
    return process;
  };
  const yaml = "schemaVersion: 3\nservices: {}\n";
  assert.deepEqual(await replaceManagedServicesDocument(yaml, spawn), {ok: true});
  assert.deepEqual(calls, [
    [
      "spawn",
      ["nas-managed-services-control", "replace-document", "-"],
      {superuser: "require", err: "message"},
    ],
    ["input", yaml],
  ]);
  assert.throws(() => replaceManagedServicesDocument("", spawn), /must not be empty/);
});

test("schema editor replacement sends only the JSON document over stdin", async () => {
  const calls = [];
  const spawn = (command, options) => {
    const process = Promise.resolve('{"ok":true}');
    process.input = (value) => calls.push(["input", value]);
    calls.push(["spawn", command, options]);
    return process;
  };
  const document = {schemaVersion: 3, services: {}};
  assert.deepEqual(await replaceManagedServicesJsonDocument(document, spawn), {ok: true});
  assert.deepEqual(calls, [
    [
      "spawn",
      ["nas-managed-services-control", "replace-json-document", "-"],
      {superuser: "require", err: "message"},
    ],
    ["input", JSON.stringify(document)],
  ]);
  assert.throws(() => replaceManagedServicesJsonDocument([], spawn), /must be an object/);
});

test("managed service mode validates identifiers and fixed modes before spawning", async () => {
  const calls = [];
  const spawn = (command, options) => {
    calls.push({command, options});
    return Promise.resolve('{"ok":true}');
  };
  await setManagedServiceMode("ai-runtime", "on-demand", spawn);
  assert.deepEqual(calls[0], {
    command: ["nas-managed-services-control", "set", "ai-runtime", "on-demand"],
    options: {superuser: "require", err: "message"},
  });
  assert.throws(() => setManagedServiceMode("../escape", "always", spawn), /Invalid Managed Services/);
  assert.throws(() => setManagedServiceMode("ai-runtime", "secret", spawn), /Invalid Managed Services/);
});

test("hostile structured values never become Cockpit command arguments", async () => {
  const calls = [];
  const spawn = (command, options) => {
    const process = Promise.resolve('{"ok":true}');
    process.input = (value) => calls.push({kind: "input", value});
    calls.push({kind: "spawn", command, options});
    return process;
  };
  const payload = {
    id: "'\";$(touch /tmp/nas-api-pwned);\\\n",
    url: "javascript:alert(1)",
    models: ["<img src=x onerror=alert(1)>", "$(id)"],
    filters: {setParams: {__proto__: "polluted"}},
  };
  await apiInput(["ai-provider-set"], payload, spawn);
  assert.deepEqual(calls[0].command, ["nas-cockpit-api", "ai-provider-set"]);
  assert.equal(calls[0].command.some((value) => value.includes("pwned")), false);
  assert.equal(calls[1].value, JSON.stringify(payload));
  assert.equal({}.polluted, undefined);
});

test("backend JSON parsing fails closed", () => {
  assert.deepEqual(parseJsonOutput('{"ok":true}'), {ok: true});
  assert.throws(() => parseJsonOutput("not-json"), SyntaxError);
});

test("unlock sends the password only over stdin", () => {
  const calls = [];
  const process = {
    input(value) {
      calls.push(["input", value]);
    },
  };
  const spawn = (command, options) => {
    calls.push(["spawn", command, options]);
    return process;
  };
  assert.equal(activateSecrets("correct horse", spawn), process);
  assert.deepEqual(calls, [
    ["spawn", ["nas-secrets", "activate-stdin"], {superuser: "require", err: "message"}],
    ["input", "correct horse\n"],
  ]);
});

test("unlock rejects empty and multiline passwords before spawning", () => {
  const fail = () => assert.fail("spawn should not run");
  assert.throws(() => activateSecrets("", fail), /Enter/);
  assert.throws(() => activateSecrets("bad\nvalue", fail), /single line/);
});

test("unlock preserves hostile single-line values only on stdin", () => {
  const inputs = [];
  const spawn = (command) => {
    const process = {
      input(value) {
        inputs.push({command, value});
      },
    };
    return process;
  };
  const password = "'\"\\$`;&|<> password";
  activateSecrets(password, spawn);
  assert.deepEqual(inputs.map(({command}) => command), [["nas-secrets", "activate-stdin"]]);
  assert.equal(inputs[0].value, `${password}\n`);
  assert.equal(inputs.some(({command}) => command.some((arg) => arg.includes(password))), false);
});
