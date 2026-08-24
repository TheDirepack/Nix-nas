import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {resolve} from "node:path";
import {registerHooks} from "node:module";
import {pathToFileURL} from "node:url";

const source = readFileSync(resolve(import.meta.dirname, "../../cockpit/src/systemd.js"), "utf8");

test("systemd status uses Cockpit system D-Bus directly", () => {
  assert.match(source, /cockpit\.dbus\(SYSTEMD_NAME, \{bus: "system"\}\)/);
  assert.match(source, /ListUnitsByNames/);
  assert.match(source, /ListUnitsByPatterns/);
  assert.match(source, /MemoryCurrent/);
  assert.doesNotMatch(source, /nas-cockpit-api/);
  assert.doesNotMatch(source, /systemctl/);
  assert.doesNotMatch(source, /superuser/);
});

test("systemd D-Bus client is always closed", () => {
  assert.match(source, /finally\s*\{\s*client\.close\(\);\s*\}/s);
});

test("systemd snapshot merges live state without changing desired policy", () => {
  assert.match(source, /managedServices\.services\.map/);
  assert.match(source, /effectiveMode/);
  assert.match(source, /running/);
  assert.match(source, /healthState/);
  assert.doesNotMatch(source, /setManagedServiceMode/);
});

// cockpit/src/systemd.js imports the "cockpit" browser host object. Stub it
// with a recorded fake D-Bus client so the module is testable under node:test.
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === "cockpit") {
      return {
        shortCircuit: true,
        url: pathToFileURL(new URL("./systemd-cockpit-stub.mjs", import.meta.url).pathname).href,
      };
    }
    return nextResolve(specifier, context);
  },
});

const {managedServiceUnitNames, mergeSystemdState, readSystemdState} =
  await import("../../cockpit/src/systemd.js");

const unitRow = (unit, activeState = "active", subState = "running", loadState = "loaded") => [
  unit,
  `${unit} description`,
  loadState,
  activeState,
  subState,
  0,
  `/org/freedesktop/systemd1/unit/${unit.replaceAll("-", "_2d").replaceAll(".", "_2e")}`,
];

test("managedServiceUnitNames collects unique unit names from the managed document", () => {
  const data = {
    managedServices: {
      services: [
        {units: [{unit: "a.service"}, {unit: "b.service"}, {}]},
        {units: [{unit: "a.service"}]},
        {units: "not-an-array"},
        {},
      ],
    },
  };
  assert.deepEqual(managedServiceUnitNames(data), ["a.service", "b.service"]);
  assert.deepEqual(managedServiceUnitNames({}), []);
  assert.deepEqual(managedServiceUnitNames({managedServices: {services: "junk"}}), []);
});

test("readSystemdState hydrates named units and failed units over D-Bus", async () => {
  const calls = [];
  const client = {
    call(path, iface, method, args) {
      calls.push({path, iface, method, args});
      if (method === "ListUnitsByNames") {
        return Promise.resolve([[unitRow("nas-ai.service"), [undefined], null]]);
      }
      if (method === "ListUnitsByPatterns") {
        return Promise.resolve([[unitRow("broken.service", "failed", "failed", "failed")]]);
      }
      if (method === "Get") {
        return Promise.resolve([{t: "u", v: 2048}]);
      }
      return Promise.reject(new Error(`unexpected call ${method}`));
    },
    close() {
      calls.push({closed: true});
    },
  };
  globalThis.systemdTestClient = client;
  try {
    const state = await readSystemdState(["nas-ai.service", 42, ""]);
    const byName = (method) => calls.find((call) => call.method === method);
    assert.ok(byName("ListUnitsByNames"), "named unit query missing");
    assert.deepEqual(byName("ListUnitsByNames").args, [["nas-ai.service"]]);
    assert.ok(byName("ListUnitsByPatterns"), "failed unit query missing");
    assert.deepEqual(byName("ListUnitsByPatterns").args, [["failed"], []]);
    assert.ok(
      calls.some((call) => call.closed),
      "client must be closed",
    );
    assert.deepEqual(state.failedUnits, [
      "broken.service failed failed failed broken.service description",
    ]);
    const unit = state.units["nas-ai.service"];
    assert.equal(unit.active, true);
    assert.equal(unit.memoryBytes, 2048);
  } finally {
    delete globalThis.systemdTestClient;
  }
});

test("readSystemdState reports null memory when the property is unavailable", async () => {
  globalThis.systemdTestClient = {
    call(_path, _iface, method) {
      if (method === "Get") return Promise.reject(new Error("unknown property"));
      if (method === "ListUnitsByNames") return Promise.resolve([[unitRow("x.service")]]);
      return Promise.resolve([[]]);
    },
    close() {},
  };
  try {
    const state = await readSystemdState(["x.service"]);
    assert.equal(state.units["x.service"].memoryBytes, null);
  } finally {
    delete globalThis.systemdTestClient;
  }
});

test("mergeSystemdState projects unit state into service health", () => {
  const data = {
    failedUnits: ["stale.service"],
    managedServices: {
      services: [
        {name: "always-on", effective: true, effectiveMode: "always", units: [{unit: "a.service"}]},
        {
          name: "on-demand",
          effective: true,
          effectiveMode: "on-demand",
          units: [{unit: "b.service"}],
        },
        {name: "broken", effective: false, effectiveMode: "always", units: []},
      ],
    },
  };
  const snapshot = {
    units: {"a.service": {active: true, activeState: "active"}},
    failedUnits: ["failed.service"],
  };
  const merged = mergeSystemdState(data, snapshot);
  assert.deepEqual(merged.failedUnits, ["failed.service"], "snapshot failures replace stale ones");
  const [alwaysOn, onDemand, broken] = merged.managedServices.services;
  assert.equal(alwaysOn.running, true);
  assert.equal(alwaysOn.resident, true);
  assert.equal(alwaysOn.healthy, true);
  assert.deepEqual(alwaysOn.units[0], {unit: "a.service", active: true, activeState: "active"});
  assert.equal(onDemand.running, false);
  assert.equal(onDemand.resident, false);
  assert.equal(onDemand.healthy, false);
  assert.equal(broken.healthy, false);
  assert.ok(merged.services["a.service"], "unit lookup map must be exposed");
});
