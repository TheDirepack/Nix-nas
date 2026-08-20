import test from "node:test";
import assert from "node:assert/strict";
import {
  inactiveServiceCount,
  managedApplicationLinks,
  managedServiceMap,
  managedServiceOperationsBusy,
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

test("managed service and application link models follow V2 state", () => {
  const data = {
    managedServices: {
      services: [
        {id: "syncthing", available: true, effectiveMode: "always"},
        {id: "vaultwarden", available: true, effectiveMode: "off"},
      ],
    },
    managedServiceLinks: [
      {id: "syncthing.web", label: "Syncthing", url: "/syncthing/", category: "Files", order: 20},
      {id: "files.web", label: "Files", url: "/shares/", category: "Files", order: 10},
    ],
    links: {accountSettings: "/settings/", identity: "/identity/if/user/"},
  };
  assert.equal(managedServiceMap(data).syncthing.effectiveMode, "always");
  assert.deepEqual(
    managedApplicationLinks(data).map((entry) => entry.id),
    ["files.web", "syncthing.web"],
  );
  assert.deepEqual(
    staticLinks(data)
      .map((entry) => entry.key)
      .sort(),
    ["accountSettings", "identity"],
  );
  assert.equal(
    visibleOperations(data).some(([id]) => id === "syncthing-sync"),
    true,
  );
});

test("service runtime and memory formatting are deterministic", () => {
  assert.equal(
    inactiveServiceCount({
      "a.service": {activeState: "inactive"},
      "b.service": {activeState: "active"},
    }),
    1,
  );
  assert.equal(managedServiceUnitState({managed: false, units: []}), "Platform service");
  assert.equal(
    managedServiceUnitState({units: [{active: true}, {active: false}], effectiveMode: "always"}),
    "Partially running",
  );
  assert.match(
    managedServiceRuntimeText({effectiveMode: "on-demand", running: false, idleSeconds: 600}),
    /authorized access/,
  );
  assert.equal(mib(10 * 1048576), "10.0");
  assert.equal(mib(Number.NaN), "—");
});

test("setup and revision models retain recovery distinctions", () => {
  assert.deepEqual(
    setupModel({
      setup: {
        firstStart: {
          status: "ready",
          message: "ready",
          requiresDestructiveConfirmation: true,
          accountCount: 3,
          serviceCount: 8,
        },
      },
    }),
    {
      complete: false,
      verified: false,
      pending: true,
      ready: true,
      status: "ready",
      message: "ready",
      configPath: "",
      planDigest: "",
      storage: {},
      accountCount: 3,
      serviceCount: 8,
      destructiveRequired: true,
      journal: null,
      authorityHealth: null,
    },
  );
  assert.equal(revisionModel({dirty: true}).checkout, "dirty");
  assert.equal(revisionModel({dirty: null}).checkout, "unknown");
  assert.deepEqual(revisionModel({ok: false, error: "unsafe tree"}), {
    kind: "error",
    error: "unsafe tree",
  });
});

test("operation conflicts disable V2 lifecycle controls while privileged work is active", () => {
  const data = {
    operations: {
      busyClasses: ["storage"],
      managedServicesConflicts: ["runtime", "appliance", "first-start"],
    },
  };
  assert.equal(operationBusy(data, "zfs-scrub"), true);
  assert.equal(managedServiceOperationsBusy(data), false);
  data.operations.busyClasses.push("runtime");
  assert.equal(managedServiceOperationsBusy(data), true);
});

test("backend link destinations remain same-origin root-relative paths", () => {
  assert.equal(safeInternalPath("/identity/"), "/identity/");
  assert.equal(safeInternalPath("/docs/?q=test#section"), "/docs/?q=test#section");
  for (const value of [
    null,
    1,
    "",
    "//evil.invalid/",
    "https://evil.invalid/",
    "javascript:alert(1)",
    "/\\evil.example/",
    "/ok\r\nX-Test: bad",
  ]) {
    assert.equal(safeInternalPath(value), null, String(value));
  }
});
