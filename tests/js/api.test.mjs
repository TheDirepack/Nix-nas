import test from "node:test";
import assert from "node:assert/strict";
import {
  activateSecrets,
  api,
  apiInput,
  parseJsonOutput,
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

test("backend JSON parsing fails closed", () => {
  assert.deepEqual(parseJsonOutput('{"ok":true}'), {ok: true});
  assert.throws(() => parseJsonOutput("not-json"), SyntaxError);
});

test("first-run sends passwords only through stdin and safety flags as fixed arguments", async () => {
  const inputs = [];
  const invocations = [];
  const spawn = (command, options) => {
    invocations.push({command, options});
    const process = Promise.resolve('{"ok":true,"status":"complete"}');
    process.input = (value) => inputs.push(value);
    return process;
  };
  assert.deepEqual(
    await startFirstRun(
      "correct horse battery staple",
      {
        allowDestructiveStorage: true,
        planDigest: "a".repeat(64),
        confirmPasswordReapply: true,
      },
      spawn,
    ),
    {ok: true, status: "complete"},
  );
  assert.deepEqual(invocations, [
    {
      command: [
        "nas-cockpit-api",
        "first-run",
        "--plan-digest",
        "a".repeat(64),
        "--allow-destructive-storage",
        "--confirm-password-reapply",
      ],
      options: {superuser: "require", err: "message"},
    },
  ]);
  assert.deepEqual(inputs, ["correct horse battery staple\n"]);
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
