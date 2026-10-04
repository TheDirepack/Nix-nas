import assert from "node:assert/strict";
import test from "node:test";
import * as api from "../../cockpit/src/api.js";
import * as model from "../../cockpit/src/view-model.js";
import * as schema from "../../cockpit/src/schema-model.js";

test("unused frontend entry points are not maintained as a second API", () => {
  for (const name of ["managedServicesStatus", "sourceControl", "updateControl"])
    assert.equal(Object.hasOwn(api, name), false, name);
  for (const name of ["inactiveServiceCount", "operationBusy"])
    assert.equal(Object.hasOwn(model, name), false, name);
  assert.equal(Object.hasOwn(schema, "propertySchema"), false);
});
