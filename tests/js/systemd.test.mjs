import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const source = readFileSync(new URL('../../cockpit/src/systemd.js', import.meta.url), 'utf8');

test('systemd module uses the system bus and bounded native manager methods', () => {
  assert.match(source, /cockpit\.dbus\(SYSTEMD_NAME, \{bus: "system"\}\)/);
  assert.match(source, /"ListUnitsByNames"/);
  assert.match(source, /"ListUnitsByPatterns"/);
  assert.match(source, /PROPERTIES_INTERFACE/);
  assert.match(source, /"MemoryCurrent"/);
  assert.doesNotMatch(source, /cockpit\.spawn/);
  assert.doesNotMatch(source, /shell:/);
});

test('systemd projection closes the DBus client and only merges named units', () => {
  assert.match(source, /finally \{\s*client\.close\(\);\s*\}/s);
  assert.match(source, /new Set\(unitNames\.filter/);
  assert.match(source, /Object\.fromEntries\(hydrated\.map/);
  assert.match(source, /unitState\[unit\?\.unit\]/);
});
