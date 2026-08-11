import test from "node:test";
import assert from "node:assert/strict";
import {
  activateSecrets,
  api,
  apiInput,
  managedServicesDocument,
  managedServicesStatus,
  parseJsonOutput,
  replaceManagedServicesDocument,
  setManagedServiceMode,
  startFirstRun,
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
  assert.throws(
    () => setManagedServiceMode("../escape", "always", spawn),
    /Invalid Managed Services/,
  );
  assert.throws(
    () => setManagedServiceMode("ai-runtime", "secret", spawn),
    /Invalid Managed Services/,
  );
});

test("backend JSON parsing fails closed", () => {
  assert.deepEqual(parseJsonOutput('{"ok":true}'), {ok: true});
  assert.throws(() => parseJsonOutput("not-json"), SyntaxError);
});

test("first-run sends password and safety choices only in a JSON stdin request", async () => {
  const calls = [];
  const spawn = (command, options) => {
    const process = Promise.resolve('{"schemaVersion":1,"jobId":"abc","status":"submitted"}');
    process.input = (value) => calls.push(["input", value]);
    calls.push(["spawn", command, options]);
    return process;
  };
  const result = await startFirstRun(
    "correct horse battery staple",
    {
      allowDestructiveStorage: true,
      planDigest: "a".repeat(64),
      confirmPasswordReapply: true,
      devices: ["/dev/disk/by-id/disk-one"],
    },
    spawn,
  );
  assert.equal(result.status, "submitted");
  assert.deepEqual(calls[0], [
    "spawn",
    ["nas-cockpit-api", "first-run"],
    {superuser: "require", err: "message"},
  ]);
  const request = JSON.parse(calls[1][1]);
  assert.deepEqual(request, {
    password: "correct horse battery staple",
    planDigest: "a".repeat(64),
    devices: ["/dev/disk/by-id/disk-one"],
    allowDestructiveStorage: true,
    confirmPasswordReapply: true,
  });
  assert.equal(calls[0][1].includes("correct horse battery staple"), false);
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

test("secret transports reject empty and multiline passwords before spawning", () => {
  const fail = () => assert.fail("spawn should not run");
  assert.throws(() => activateSecrets("", fail), /Enter/);
  assert.throws(() => activateSecrets("bad\nvalue", fail), /single line/);
  assert.throws(
    () => startFirstRun("bad\rvalue", {planDigest: "a".repeat(64)}, fail),
    /single line/,
  );
});
