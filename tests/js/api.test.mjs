import test from "node:test";
import assert from "node:assert/strict";
import * as apiModule from "../../cockpit/src/api.js";
import {
  api,
  apiInput,
  managedServicesDocument,
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

test("structured API mutations send JSON only over stdin", async () => {
  const calls = [];
  const spawn = (command, options) => {
    const process = Promise.resolve('{"ok":true}');
    process.input = (value) => calls.push(["input", value]);
    calls.push(["spawn", command, options]);
    return process;
  };
  assert.deepEqual(await apiInput(["source-control"], {action: "status"}, spawn), {ok: true});
  assert.deepEqual(calls, [
    ["spawn", ["nas-cockpit-api", "source-control"], {superuser: "require", err: "message"}],
    ["input", JSON.stringify({action: "status"})],
  ]);
  assert.equal(calls[0][1].includes("secret"), false);
});

test("managed services document uses the canonical V2 control CLI", async () => {
  const calls = [];
  const spawn = (command, options) => {
    calls.push({command, options});
    return Promise.resolve('{"ok":true,"services":[]}');
  };
  await managedServicesDocument(spawn);
  assert.deepEqual(calls, [
    {
      command: ["nas-managed-services-control", "document"],
      options: {superuser: "require", err: "message"},
    },
  ]);
});

test("managed services document replacement sends YAML only over stdin with revision CAS", async () => {
  const calls = [];
  const spawn = (command, options) => {
    const process = Promise.resolve('{"ok":true}');
    process.input = (value) => calls.push(["input", value]);
    calls.push(["spawn", command, options]);
    return process;
  };
  const yaml = "schemaVersion: 3\nservices: {}\n";
  assert.deepEqual(await replaceManagedServicesDocument(yaml, "a".repeat(64), spawn), {ok: true});
  assert.deepEqual(calls, [
    [
      "spawn",
      ["nas-managed-services-control", "replace-document", "-", "a".repeat(64)],
      {superuser: "require", err: "message"},
    ],
    ["input", yaml],
  ]);
  assert.throws(
    () => replaceManagedServicesDocument("", "a".repeat(64), spawn),
    /must not be empty/,
  );
});

test("schema editor replacement sends only the JSON document over stdin with revision CAS", async () => {
  const calls = [];
  const spawn = (command, options) => {
    const process = Promise.resolve('{"ok":true}');
    process.input = (value) => calls.push(["input", value]);
    calls.push(["spawn", command, options]);
    return process;
  };
  const document = {schemaVersion: 3, services: {}};
  assert.deepEqual(await replaceManagedServicesJsonDocument(document, "b".repeat(64), spawn), {
    ok: true,
  });
  assert.deepEqual(calls, [
    [
      "spawn",
      ["nas-managed-services-control", "replace-json-document", "-", "b".repeat(64)],
      {superuser: "require", err: "message"},
    ],
    ["input", JSON.stringify(document)],
  ]);
  assert.throws(
    () => replaceManagedServicesJsonDocument([], "b".repeat(64), spawn),
    /must be an object/,
  );
});

test("managed service mode validates identifiers and fixed modes before spawning", async () => {
  const calls = [];
  const spawn = (command, options) => {
    calls.push({command, options});
    return Promise.resolve('{"ok":true}');
  };
  await setManagedServiceMode("grafana", "on-demand", spawn);
  assert.deepEqual(calls[0], {
    command: ["nas-managed-services-control", "set", "grafana", "on-demand"],
    options: {superuser: "require", err: "message"},
  });
  assert.throws(
    () => setManagedServiceMode("../escape", "always", spawn),
    /Invalid Managed Services/,
  );
  assert.throws(
    () => setManagedServiceMode("grafana", "secret", spawn),
    /Invalid Managed Services/,
  );
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
    path: ["<img src=x onerror=alert(1)>", "$(id)"],
    query: {setParams: {__proto__: "polluted"}},
  };
  await apiInput(["source-control"], payload, spawn);
  assert.deepEqual(calls[0].command, ["nas-cockpit-api", "source-control"]);
  assert.equal(
    calls[0].command.some((value) => value.includes("pwned")),
    false,
  );
  assert.equal(calls[1].value, JSON.stringify(payload));
  assert.equal({}.polluted, undefined);
});

test("backend JSON parsing fails closed", () => {
  assert.deepEqual(parseJsonOutput('{"ok":true}'), {ok: true});
  assert.throws(() => parseJsonOutput("not-json"), SyntaxError);
});

const jsonRequests = [
  ["overview", (spawn) => api(["overview"], spawn)],
  ["structured mutation", (spawn) => apiInput(["source-control"], {action: "status"}, spawn)],
  ["managed document", (spawn) => managedServicesDocument(spawn)],
  [
    "YAML replacement",
    (spawn) =>
      replaceManagedServicesDocument("schemaVersion: 3\nservices: {}\n", "a".repeat(64), spawn),
  ],
  [
    "JSON replacement",
    (spawn) =>
      replaceManagedServicesJsonDocument({schemaVersion: 3, services: {}}, "b".repeat(64), spawn),
  ],
  ["service mode", (spawn) => setManagedServiceMode("grafana", "on-demand", spawn)],
];

for (const [name, request] of jsonRequests) {
  for (const output of ["", "not-json", '{"ok":', '{"ok":true}']) {
    test(`${name} parses thenable output inside a native promise: ${JSON.stringify(output)}`, async () => {
      const process = {
        input() {},
        then(fulfilled) {
          return fulfilled(output);
        },
      };
      let result;
      assert.doesNotThrow(() => {
        result = request(() => process);
      }, "JSON decoding must reject the returned promise, not escape a Cockpit callback");
      assert.equal(result instanceof Promise, true);
      if (output === '{"ok":true}') {
        assert.deepEqual(await result, {ok: true});
      } else {
        await assert.rejects(result, SyntaxError);
      }
    });
  }

  test(`${name} preserves the original thenable rejection`, async () => {
    const reason = new Error("privileged process failed");
    const process = {
      input() {},
      then(_fulfilled, rejected) {
        return rejected(reason);
      },
    };
    let result;
    assert.doesNotThrow(() => {
      result = request(() => process);
    });
    assert.equal(result instanceof Promise, true);
    await assert.rejects(result, (error) => error === reason);
  });
}

test("JSON transport still rejects an unavailable Cockpit process API before spawning", () => {
  assert.throws(() => api(["overview"], null), /Cockpit process API is unavailable/);
});

test("Cockpit exposes no KeePassXC password transport", () => {
  assert.equal("activateSecrets" in apiModule, false);
});
