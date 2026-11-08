import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
import test from "node:test";
const context = vm.createContext({});
vm.runInContext(
  fs.readFileSync(new URL("../../scripts/lib/zap-context.js", import.meta.url), "utf8"),
  context,
);
const classify = context.classifyObservation;
const origin = "https://nas-test.local:8443";
const socket = origin + "/console/cockpit/socket";
const sample = "[WebSocket Message] 5:10!9\n[[[625.0605398075708, 1722.4112318978587]]]";
test("fractional metrics are observations; genuine card numbers and unrelated alerts stay fatal", () => {
  assert.ok(classify(110005, socket, "", "4112318978587", sample, origin));
  for (const [rule, url, evidence, frame] of [
    [110005, socket, "4111111111111111", "[WebSocket Message] 5:10!9\n[[4111111111111111]]"],
    [110005, socket, "4111111111111111", '[WebSocket Message] 5:10!9\n{"card":"4111111111111111"}'],
    [
      110005,
      socket,
      "4111111111111111",
      "[WebSocket Message] 5:10!9\n[[4111111111111111, 1722.4111111111111111]]",
    ],
    [110005, socket, "4112318978587", sample + " secret"],
    [110005, origin + "/public/socket", "4112318978587", sample],
    [110005, "https://other.test/console/cockpit/socket", "4112318978587", sample],
    [90027, socket, "4112318978587", sample],
    [110006, socket, "10.89.0.0", "[WebSocket Message] 4:4!3 truncated journal"],
  ])
    assert.equal(classify(rule, url, "", evidence, frame, origin), null);
});
test("only exact upstream static examples and cryptographic constants are classified", () => {
  const js = origin + "/console/cockpit/@localhost/";
  assert.ok(classify(2, js + "network/networkmanager.js", "", "10.0.0.1", "", origin));
  assert.equal(classify(2, js + "network/networkmanager.js", "", "10.0.2.15", "", origin), null);
  assert.ok(classify(10096, js + "podman/index.js", "", "1732584193", "", origin));
  assert.equal(classify(10096, js + "podman/index.js", "", "1732584194", "", origin), null);
  assert.equal(classify(10096, origin + "/api/time", "", "1732584193", "", origin), null);
});
test("CSRF cookie exception cannot classify session-cookie failures", () => {
  const url = origin + "/identity/api/v3/flows/executor/default-authentication-flow/?query=x";
  assert.ok(classify(10010, url, "authentik_csrf", "Set-Cookie: authentik_csrf", "", origin));
  assert.equal(
    classify(10010, url, "authentik_session", "Set-Cookie: authentik_session", "", origin),
    null,
  );
  assert.equal(
    classify(10011, url, "authentik_csrf", "Set-Cookie: authentik_csrf", "", origin),
    null,
  );
});

test("plaintext-on-TLS blind-spot proxy reports are classified but real proxy reports are not", () => {
  const report =
    "Using the TRACE, OPTIONS, and TRACK methods, the following proxy servers have been identified between ZAP and the application/web server:\n- Unknown\nThe following web/application server has been identified:\n- Unknown\n";
  const url = origin + "/console/";
  assert.ok(classify(40025, url, "", "", report, origin));
  assert.equal(classify(40025, url, "", "", report, "http://nas-test.local:8443"), null);
  assert.equal(classify(40025, url, "", "proxy", report, origin), null);
  assert.equal(
    classify(
      40025,
      url,
      "",
      "",
      report.replace("server:\n- Unknown", "server:\n- nginx/1.24"),
      origin,
    ),
    null,
  );
  assert.equal(classify(40025, url, "", "", report + "\nTRACE is enabled", origin), null);
  assert.equal(classify(40025, "https://other.test/console/", "", "", report, origin), null);
});

test("admin network observations require authentication and structured NetworkManager properties", () => {
  const packet = {
    notify: {
      "/org/freedesktop/NetworkManager/IP4Config/2": {
        "org.freedesktop.NetworkManager.IP4Config": {Gateway: "10.0.2.2"},
      },
    },
  };
  const frame = "[WebSocket Message] 4:6!6\n" + JSON.stringify(packet);
  assert.ok(classify(110006, socket, "", "10.0.2.2", frame, origin, true));
  assert.equal(classify(110006, socket, "", "10.0.2.2", frame, origin, false), null);
  assert.equal(
    classify(110006, origin + "/public/socket", "", "10.0.2.2", frame, origin, true),
    null,
  );
  packet.notify["/org/freedesktop/NetworkManager/IP4Config/2"][
    "org.freedesktop.NetworkManager.IP4Config"
  ].Note = "10.0.2.2";
  assert.equal(
    classify(
      110006,
      socket,
      "",
      "10.0.2.2",
      "[WebSocket Message] 4:6!6\n" + JSON.stringify(packet),
      origin,
      true,
    ),
    null,
  );
  assert.equal(classify(110006, socket, "", "10.0.2.2", frame.slice(0, -1), origin, true), null);
});

test("journal stream fragments classify only complete firewalld source-query diagnostics", () => {
  const record = {
    _SYSTEMD_UNIT: "firewalld.service",
    SYSLOG_IDENTIFIER: "firewalld",
    MESSAGE: "ERROR: UNKNOWN_SOURCE: '10.89.0.0/24' is not in any zone",
  };
  const frame = "[WebSocket Message] 4:4!3\npartial\n" + JSON.stringify(record) + '\n{"partial":';
  assert.ok(classify(110006, socket, "", "10.89.0.0", frame, origin, true));
  assert.equal(classify(110006, socket, "", "10.89.0.0", frame, origin, false), null);
  assert.equal(classify(110006, socket, "", "10.89.0.0", frame.slice(0, -20), origin, true), null);
  record._SYSTEMD_UNIT = "other.service";
  assert.equal(
    classify(
      110006,
      socket,
      "",
      "10.89.0.0",
      "[WebSocket Message] 4:4!3\n" + JSON.stringify(record),
      origin,
      true,
    ),
    null,
  );
  record._SYSTEMD_UNIT = "firewalld.service";
  record.MESSAGE = "Unexpected data at 10.89.0.0";
  assert.equal(
    classify(
      110006,
      socket,
      "",
      "10.89.0.0",
      "[WebSocket Message] 4:4!3\n" + JSON.stringify(record),
      origin,
      true,
    ),
    null,
  );
});
