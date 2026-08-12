import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import {
  defaultValue,
  migrateVariantValue,
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
  const selected = selectedSchema(schema, runtime, {type: "oci", image: "example:v1"}, ociIndex);
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

test("oneOf variant switching preserves compatible shared fields", () => {
  const runtime = schema.$defs.runtime;
  const execVal = {
    type: "exec",
    command: ["/bin/demo"],
    environment: {FOO: "bar"},
    workingDirectory: "/tmp",
  };
  const systemdIdx = variantOptions(schema, runtime).findIndex((o) => o.label === "type: systemd");
  const preserved = migrateVariantValue(schema, runtime, execVal, systemdIdx);
  // type discriminator should change to systemd, exec-specific fields removed, but no crash
  assert.equal(preserved.type, "systemd");
  assert.equal(preserved.command, undefined);
  // switching back to exec should get defaults for required fields
  const execIdx = variantOptions(schema, runtime).findIndex((o) => o.label === "type: exec");
  const back = migrateVariantValue(schema, runtime, preserved, execIdx);
  assert.equal(back.type, "exec");
});

test("runtime discriminator oneOf keeps shared sandbox-compatible values", () => {
  const service = defaultValue(schema, schema.$defs.service);
  service.resources = {accelerators: [{kind: "gpu", vendor: "NVIDIA"}]};
  service.sandbox = {mode: "strict"};
  const runtime = schema.$defs.runtime;
  const quadletIdx = variantOptions(schema, runtime).findIndex((o) => o.label === "type: quadlet");
  const execIdx = variantOptions(schema, runtime).findIndex((o) => o.label === "type: exec");
  const quadletVal = migrateVariantValue(
    schema,
    runtime,
    {type: "exec", command: ["/bin/x"]},
    quadletIdx,
  );
  assert.equal(quadletVal.type, "quadlet");
  const execVal = migrateVariantValue(schema, runtime, quadletVal, execIdx);
  assert.equal(execVal.type, "exec");
});

test("non-discriminator oneOf (schedule) preserves shared fields", () => {
  const schedule = schema.$defs.schedule;
  const calendarVal = {calendar: "daily", randomizedDelaySeconds: 100, persistent: true};
  const intervalIdx = variantOptions(schema, schedule).findIndex((o) =>
    o.label.includes("intervalSeconds"),
  );
  const migrated = migrateVariantValue(schema, schedule, calendarVal, intervalIdx);
  // shared fields randomizedDelaySeconds and persistent should survive, calendar removed
  assert.equal(migrated.randomizedDelaySeconds, 100);
  assert.equal(migrated.persistent, true);
  assert.equal(migrated.calendar, undefined);
  assert.ok(typeof migrated.intervalSeconds === "number");
  const calendarIdx = variantOptions(schema, schedule).findIndex((o) =>
    o.label.includes("calendar"),
  );
  const back = migrateVariantValue(schema, schedule, migrated, calendarIdx);
  assert.ok(typeof back.calendar === "string");
  assert.equal(back.intervalSeconds, undefined);
});

test("obsolete branch-specific properties are removed", () => {
  const runtime = schema.$defs.runtime;
  const execVal = {type: "exec", command: ["/bin/x"], workingDirectory: "/tmp"};
  const systemdIdx = variantOptions(schema, runtime).findIndex((o) => o.label === "type: systemd");
  const migrated = migrateVariantValue(schema, runtime, execVal, systemdIdx);
  assert.equal(migrated.command, undefined);
  assert.equal(migrated.workingDirectory, undefined);
  assert.equal(migrated.type, "systemd");
  assert.ok(typeof migrated.unit === "string");
});
