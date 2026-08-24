import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {resolve} from "node:path";

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
