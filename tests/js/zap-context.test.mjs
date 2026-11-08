import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';
const context = vm.createContext({});
vm.runInContext(fs.readFileSync(new URL('../../scripts/lib/zap-context.js', import.meta.url), 'utf8'), context);
const classify = context.classifyObservation;
const origin = 'https://nas-test.local:8443';
const socket = origin + '/console/cockpit/socket';
const sample = '[WebSocket Message] 5:10!9\n[[[625.0605398075708, 1722.4112318978587]]]';
test('fractional metrics are observations; genuine card numbers and unrelated alerts stay fatal', () => {
  assert.ok(classify(110005, socket, '', '4112318978587', sample, origin));
  for (const [rule, url, evidence, frame] of [
    [110005, socket, '4111111111111111', '[WebSocket Message] 5:10!9\n[[4111111111111111]]'],
    [110005, socket, '4111111111111111', '[WebSocket Message] 5:10!9\n{"card":"4111111111111111"}'],
    [110005, socket, '4112318978587', sample + ' secret'],
    [110005, origin + '/public/socket', '4112318978587', sample],
    [110005, 'https://other.test/console/cockpit/socket', '4112318978587', sample],
    [90027, socket, '4112318978587', sample],
    [110006, socket, '10.89.0.0', '[WebSocket Message] 4:4!3 truncated journal'],
  ]) assert.equal(classify(rule, url, '', evidence, frame, origin), null);
});
test('only exact upstream static examples and cryptographic constants are classified', () => {
  const js = origin + '/console/cockpit/@localhost/';
  assert.ok(classify(2, js + 'network/networkmanager.js', '', '10.0.0.1', '', origin));
  assert.equal(classify(2, js + 'network/networkmanager.js', '', '10.0.2.15', '', origin), null);
  assert.ok(classify(10096, js + 'podman/index.js', '', '1732584193', '', origin));
  assert.equal(classify(10096, js + 'podman/index.js', '', '1732584194', '', origin), null);
  assert.equal(classify(10096, origin + '/api/time', '', '1732584193', '', origin), null);
});
test('CSRF cookie exception cannot classify session-cookie failures', () => {
  const url = origin + '/identity/api/v3/flows/executor/default-authentication-flow/?query=x';
  assert.ok(classify(10010, url, 'authentik_csrf', 'Set-Cookie: authentik_csrf', '', origin));
  assert.equal(classify(10010, url, 'authentik_session', 'Set-Cookie: authentik_session', '', origin), null);
  assert.equal(classify(10011, url, 'authentik_csrf', 'Set-Cookie: authentik_csrf', '', origin), null);
});
