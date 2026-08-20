import test from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";

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

const jsonScalar = fc.oneof(
  fc.constant(null),
  fc.boolean(),
  fc.integer(),
  fc.double({noNaN: true, noDefaultInfinity: true}),
  fc.string({maxLength: 256}),
);

const shallowJson = fc.oneof(
  jsonScalar,
  fc.array(jsonScalar, {maxLength: 24}),
  fc.dictionary(fc.string({maxLength: 48}), jsonScalar, {maxKeys: 24}),
);

test("safeInternalPath accepts only same-origin root-relative control-free strings", () => {
  fc.assert(
    fc.property(
      fc.oneof(
        fc.string({maxLength: 4096}),
        fc.integer(),
        fc.boolean(),
        fc.constant(null),
        fc.array(fc.integer(), {maxLength: 8}),
      ),
      (value) => {
        const accepted = safeInternalPath(value);
        if (accepted === null) return;
        assert.equal(typeof accepted, "string");
        assert.ok(accepted.startsWith("/"));
        assert.ok(!accepted.startsWith("//"));
        assert.ok(!accepted.includes("\\"));
        assert.ok(
          ![...accepted].some((character) => {
            const code = character.charCodeAt(0);
            return code < 32 || code === 127;
          }),
        );
      },
    ),
    {
      numRuns: 1500,
      examples: [["//example.invalid/path"], ["/safe/path"], ["/\\evil.example/path"], ["/bad\npath"], ["javascript:alert(1)"]],
    },
  );
});

test("managedServiceMap only exposes non-empty string identifiers", () => {
  const service = fc.record({
    id: fc.oneof(fc.string({maxLength: 64}), fc.integer(), fc.constant(null)),
    label: fc.oneof(fc.string({maxLength: 64}), fc.constant(null)),
  });
  fc.assert(
    fc.property(fc.array(service, {maxLength: 100}), (services) => {
      const result = managedServiceMap({managedServices: {services}});
      for (const [key, value] of Object.entries(result)) {
        assert.equal(typeof key, "string");
        assert.notEqual(key, "");
        assert.equal(value.id, key);
      }
    }),
    {numRuns: 800},
  );
});

test("staticLinks never exposes unknown backend link names or unsafe paths", () => {
  fc.assert(
    fc.property(
      fc.dictionary(fc.string({maxLength: 64}), shallowJson, {maxKeys: 60}),
      (links) => {
        const entries = staticLinks({links});
        const seen = new Set();
        for (const entry of entries) {
          assert.ok(Object.hasOwn(links, entry.key));
          assert.ok(!seen.has(entry.key));
          seen.add(entry.key);
          assert.equal(typeof entry.url, "string");
          assert.ok(entry.url.startsWith("/"));
          assert.ok(!entry.url.startsWith("//"));
        }
      },
    ),
    {numRuns: 800},
  );
});

test("inactiveServiceCount is total and bounded by the supplied rows", () => {
  fc.assert(
    fc.property(fc.array(shallowJson, {maxLength: 300}), (rows) => {
      const count = inactiveServiceCount(rows);
      assert.ok(Number.isInteger(count));
      assert.ok(count >= 0);
      assert.ok(count <= rows.length);
    }),
    {numRuns: 1000},
  );
});

test("revisionModel is total for arbitrary shallow backend objects", () => {
  fc.assert(
    fc.property(fc.dictionary(fc.string({maxLength: 48}), shallowJson, {maxKeys: 40}), (update) => {
      const model = revisionModel(update);
      assert.ok(model && typeof model === "object");
      assert.ok(model.kind === "status" || model.kind === "error");
      if (model.kind === "status") {
        assert.ok(["clean", "dirty", "unknown"].includes(model.checkout));
        assert.equal(typeof model.divergence, "string");
      }
    }),
    {numRuns: 800},
  );
});

test("mib never throws and only emits strings for arbitrary numbers", () => {
  fc.assert(
    fc.property(fc.oneof(fc.double({noNaN: false, noDefaultInfinity: false}), fc.integer()), (value) => {
      assert.equal(typeof mib(value), "string");
    }),
    {numRuns: 1000},
  );
});

test("all backend view-model helpers remain total for hostile JSON", () => {
  fc.assert(
    fc.property(
      shallowJson,
      fc.string({maxLength: 64}),
      (value, actionId) => {
        assert.doesNotThrow(() => managedServiceMap(value));
        assert.doesNotThrow(() => setupModel(value));
        assert.doesNotThrow(() => managedServiceUnitState(value));
        assert.doesNotThrow(() => managedServiceRuntimeText(value));
        assert.doesNotThrow(() => operationBusy(value, actionId));
        assert.doesNotThrow(() => managedServiceOperationsBusy(value));
        assert.doesNotThrow(() => visibleOperations(value));
        assert.doesNotThrow(() => staticLinks(value));
        assert.doesNotThrow(() => managedApplicationLinks(value));
        assert.doesNotThrow(() => inactiveServiceCount(value));
        assert.doesNotThrow(() => revisionModel(value));
      },
    ),
    {numRuns: 1200},
  );
});
