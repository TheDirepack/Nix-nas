import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import {
  defaultValue,
  propertyNamePattern,
  resolveSchema,
  schemaType,
  selectedSchema,
  selectVariantIndex,
  variantOptions,
} from "../../cockpit/src/schema-model.js";

const schema = JSON.parse(
  fs.readFileSync(new URL("../../schemas/managed-services-v3.schema.json", import.meta.url)),
);

test("runtime choices are discovered from the canonical schema instead of app UI branches", () => {
  const runtime = schema.$defs.runtime;
  const options = variantOptions(schema, runtime);
  assert.equal(options.length, 7);
  assert.ok(options.some((option) => option.label === "type: systemd"));
  assert.ok(options.some((option) => option.label === "type: compose"));
  assert.ok(options.some((option) => option.label === "type: oci"));

  const ociIndex = selectVariantIndex(schema, runtime, {type: "oci", image: "example:v1"});
  const selected = selectedSchema(
    schema,
    runtime,
    {type: "oci", image: "example:v1"},
    ociIndex,
  );
  assert.equal(resolveSchema(schema, selected.properties.type).const, "oci");
});

test("new service values are built from schema required/default/const data", () => {
  const service = defaultValue(schema, schema.$defs.service);
  assert.equal(service.name, "");
  assert.deepEqual(service.workload, {
    kind: "daemon",
    activation: "persistent",
    schedules: [],
  });
  assert.equal(service.runtime.type, "systemd");
  assert.equal(service.runtime.unit, "");
  assert.equal(service.enabled, true);
  assert.equal(service.managed, true);
});

test("dynamic service and resource IDs use the schema propertyNames constraint", () => {
  const services = resolveSchema(schema, schema.properties.services);
  const resources = resolveSchema(schema, schema.properties.storageResources);
  assert.equal(propertyNamePattern(schema, services), "^[a-z][a-z0-9-]{0,63}$");
  assert.equal(propertyNamePattern(schema, resources), "^[a-z][a-z0-9-]{0,63}$");
  assert.equal(schemaType(schema, services.additionalProperties), "object");
});

test("oneOf without a discriminator keeps the base object properties", () => {
  const schedule = schema.$defs.schedule;
  const calendar = selectedSchema(schema, schedule, {calendar: "daily"});
  assert.ok(calendar.properties.calendar);
  assert.ok(calendar.properties.intervalSeconds);
  assert.deepEqual(calendar.required, ["calendar"]);

  const interval = selectedSchema(schema, schedule, {intervalSeconds: 3600});
  assert.deepEqual(interval.required, ["intervalSeconds"]);
});

test("generic schema model contains no built-in application identifiers", () => {
  const source = fs.readFileSync(
    new URL("../../cockpit/src/schema-model.js", import.meta.url),
    "utf8",
  );
  for (const application of [
    "copyparty",
    "syncthing",
    "grafana",
    "ai-runtime",
    "ai-workspace",
    "ntfy",
  ]) {
    assert.equal(source.includes(application), false, `${application} must not be special-cased`);
  }
});
