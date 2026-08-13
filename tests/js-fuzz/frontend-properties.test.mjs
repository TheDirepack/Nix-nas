import test from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";

import {
  enabledLinkKeys,
  featureMap,
  inactiveServiceCount,
  mib,
  revisionModel,
  safeInternalPath,
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

test("featureMap only exposes non-empty string identifiers", () => {
  const feature = fc.record(
    {
      id: fc.oneof(fc.string({maxLength: 64}), fc.integer(), fc.constant(null)),
      effective: fc.boolean(),
      available: fc.boolean(),
    },
    {requiredKeys: ["id"]},
  );
  fc.assert(
    fc.property(fc.array(feature, {maxLength: 100}), (features) => {
      const result = featureMap({featureControl: {features}});
      for (const [key, value] of Object.entries(result)) {
        assert.equal(typeof key, "string");
        assert.notEqual(key, "");
        assert.equal(value.id, key);
      }
    }),
    {numRuns: 800},
  );
});

test("enabledLinkKeys never enables unknown backend link names", () => {
  fc.assert(
    fc.property(
      fc.dictionary(fc.string({maxLength: 64}), shallowJson, {maxKeys: 60}),
      fc.array(
        fc.record({id: fc.string({minLength: 1, maxLength: 32}), effective: fc.boolean(), available: fc.boolean()}),
        {maxLength: 40},
      ),
      (links, features) => {
        const keys = enabledLinkKeys({links, featureControl: {features}});
        assert.equal(new Set(keys).size, keys.length);
        for (const key of keys) assert.ok(Object.hasOwn(links, key));
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
