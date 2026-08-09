import test from "node:test";
import assert from "node:assert/strict";
import {
  enabledLinkKeys,
  featureMap,
  featureRuntimeText,
  featureUnitState,
  inactiveServiceCount,
  featureOperationsBusy,
  mib,
  operationBusy,
  revisionModel,
  safeInternalPath,
  setupModel,
  visibleOperations,
} from "../../cockpit/src/view-model.js";

test("feature and link models follow effective runtime state", () => {
  const data = {
    featureControl: {
      features: [
        {id: "syncthing", effective: true, available: true},
        {id: "vaultwarden", effective: false},
        {id: "backups", available: false},
      ],
    },
    links: {settings: "/settings/", syncthing: "/syncthing/", vaultwarden: "/vault/"},
  };
  assert.equal(featureMap(data).syncthing.effective, true);
  assert.deepEqual(enabledLinkKeys(data), ["settings", "syncthing"]);
  assert.equal(
    visibleOperations(data).some(([id]) => id === "syncthing-reconcile"),
    true,
  );
  assert.equal(
    visibleOperations(data).some(([id]) => id === "backup"),
    false,
  );
});

test("service, feature runtime, and memory formatting are deterministic", () => {
  assert.equal(
    inactiveServiceCount([
      {unit: "a.service", active: "inactive"},
      {unit: "a.timer", active: "inactive"},
      {unit: "b.service", active: "active"},
    ]),
    1,
  );
  assert.equal(featureUnitState({units: []}), "Logical group");
  assert.equal(featureUnitState({units: [{active: true}, {active: false}]}), "Partially running");
  assert.match(
    featureRuntimeText({effectiveMode: "on-demand", running: false}),
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
      featureCount: 0,
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

test("operation conflicts disable only incompatible controls", () => {
  const data = {
    operationState: {
      busyClasses: ["storage"],
      featureConflicts: ["runtime"],
      conflictsByAction: {scrub: ["storage"], "identity-sync": ["identity"]},
    },
  };
  assert.equal(operationBusy(data, "scrub"), true);
  assert.equal(operationBusy(data, "identity-sync"), false);
  assert.equal(featureOperationsBusy(data), false);
  data.operationState.busyClasses.push("runtime");
  assert.equal(featureOperationsBusy(data), true);
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
    "/ok\r\nX-Test: bad",
  ]) {
    assert.equal(safeInternalPath(value), null, String(value));
  }
});
