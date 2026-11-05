import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {setImmediate} from "node:timers/promises";
import vm from "node:vm";

const source = readFileSync(new URL("../../cockpit/e2e/final-vm.spec.mjs", import.meta.url), "utf8")
  .replace('import {test, expect} from "@playwright/test";\n', "")
  .replace('import AxeBuilder from "@axe-core/playwright";\n', "");

const expectedHostilePayloads = [
  "<script>globalThis.__nas_login_xss=1</script>",
  '<img src=x onerror="globalThis.__nas_login_xss=2">',
  "<svg/onload=globalThis.__nas_login_xss=3>",
  '\"><iframe srcdoc="<script>parent.__nas_login_xss=4<\\/script>"></iframe>',
  "javascript:globalThis.__nas_login_xss=5",
  "' OR 1=1 --",
  "../../../../etc/passwd",
  "\r\nX-Injected: yes",
];

function deferred() {
  let resolve;
  const promise = new Promise((done) => {
    resolve = done;
  });
  return {promise, resolve};
}

function loginCase(name, {deferClose = false} = {}) {
  const cases = new Map();
  const closeComplete = deferred();
  if (!deferClose) closeComplete.resolve();
  const state = {
    stage: "username",
    url: "https://nas.test/identity/if/flow/default-authentication-flow/",
    marker: 0,
    markerReads: 0,
    errorReads: 0,
    frameReads: 0,
    closeCalls: 0,
    closed: false,
    earlyCookieClears: 0,
    cookieClears: 0,
    navigations: 0,
    submissions: [],
    listeners: new Map(),
  };
  const button = {
    filter() {
      return this;
    },
    first() {
      return this;
    },
    async click() {
      if (state.stage === "username") {
        state.stage = "password";
      } else {
        state.submissions.push({
          username: state.username,
          password: state.password,
          visible: deferred(),
          rendered: false,
        });
      }
    },
  };
  const page = {
    on(event, callback) {
      state.listeners.set(event, callback);
    },
    async addInitScript() {},
    context() {
      return {
        async clearCookies() {
          state.cookieClears += 1;
          if (state.submissions.some((item) => !item.rendered)) state.earlyCookieClears += 1;
        },
      };
    },
    url() {
      return state.url;
    },
    async goto() {
      state.navigations += 1;
      state.stage = "username";
      state.marker = 0;
    },
    getByRole(role, options) {
      return {
        role,
        name: options.name,
        async fill(value) {
          state[options.name === "Password" ? "password" : "username"] = value;
        },
        async click() {
          assert.fail("the hostile-login rounds no longer reset through a link click");
        },
      };
    },
    locator() {
      return button;
    },
    frames() {
      state.frameReads += 1;
      return [];
    },
    async evaluate() {
      state.markerReads += 1;
      return state.marker;
    },
    async close() {
      state.closeCalls += 1;
      await closeComplete.promise;
      state.closed = true;
    },
  };
  const expect = (value) => ({
    async toBeVisible() {
      if (value.role === "alert") {
        assert.equal(value.name, "Invalid password");
        const pending = state.submissions.at(-1);
        assert.ok(pending, "rejection must follow a password submission");
        await pending.visible.promise;
      }
    },
    async toHaveURL(pattern) {
      assert.ok(pattern.test(state.url));
    },
    toBe(expected) {
      assert.equal(value, expected);
    },
    toEqual(expected) {
      state.errorReads += 1;
      assert.deepEqual(Array.from(value), Array.from(expected));
    },
  });
  const register = (title, callback) => cases.set(title, callback);
  register.describe = {configure() {}};
  // Only asynchronous page/locator I/O is doubled. These execute the complete
  // installed-suite callbacks, not a separate implementation of the login test.
  new vm.Script(source, {filename: "final-vm.spec.mjs"}).runInNewContext({
    test: register,
    expect,
    URL,
    process: {env: {NAS_VM_TEST_USER: "test-user", NAS_VM_TEST_PASSWORD: "test-password"}},
  });
  assert.ok(cases.has(name), `missing registered callback: ${name}`);
  const result = {settled: false, error: undefined};
  result.done = cases
    .get(name)({page})
    .then(
      () => {
        result.settled = true;
      },
      (error) => {
        result.settled = true;
        result.error = error;
      },
    );
  function render({marker = 0, pageError} = {}) {
    const pending = state.submissions.find((item) => !item.rendered);
    assert.ok(pending);
    pending.rendered = true;
    state.marker = marker;
    if (pageError) state.listeners.get("pageerror")(pageError);
    pending.visible.resolve();
  }
  function finishClose({pageError} = {}) {
    assert.equal(state.closeCalls, 1, "finish only a requested page close");
    if (pageError) state.listeners.get("pageerror")(pageError);
    closeComplete.resolve();
  }
  return {state, result, render, finishClose};
}

test("invalid-credential callback cannot finish before rendered rejection", async () => {
  const fixture = loginCase("invalid credentials cannot expose the NAS component");
  await setImmediate();
  assert.equal(fixture.state.submissions.length, 1);
  assert.equal(fixture.result.settled, false, "the identity URL is not a rejection barrier");
  fixture.render();
  await fixture.result.done;
  assert.equal(fixture.result.error, undefined);
});

test("all hostile-login callbacks wait for rejection and submit distinct expected credentials", async () => {
  const submissions = [];
  for (let index = 0; index < expectedHostilePayloads.length; index += 1) {
    const fixture = loginCase(`hostile anonymous login value ${index + 1} stays inert`);
    await setImmediate();
    assert.equal(fixture.result.settled, false);
    assert.equal(fixture.state.submissions.length, 1);
    assert.equal(fixture.state.markerReads, 0, "inertness must be checked after rejection");
    assert.equal(fixture.state.errorReads, 0, "page errors must be checked after rejection");
    assert.equal(fixture.state.closeCalls, 0, "retain the page until rejection");
    assert.equal(fixture.state.earlyCookieClears, 0);
    fixture.render();
    await fixture.result.done;
    assert.equal(fixture.result.error, undefined);
    assert.equal(fixture.state.markerReads, 1);
    assert.equal(fixture.state.errorReads, 1);
    assert.equal(fixture.state.closeCalls, 1);
    assert.equal(fixture.state.closed, true);
    assert.equal(fixture.state.submissions.length, 1);
    assert.equal(fixture.state.navigations, 1, "initialize the anonymous login flow once");
    assert.equal(fixture.state.cookieClears, 0, "retain native anonymous CSRF/session state");
    submissions.push(fixture.state.submissions[0]);
  }
  for (const field of ["username", "password"]) {
    const values = submissions.map((item) => item[field]);
    assert.deepEqual(values, expectedHostilePayloads, `exact hostile ${field} payloads`);
    assert.equal(new Set(values).size, 8, `eight distinct hostile ${field} payloads`);
  }
});

for (let index = 0; index < expectedHostilePayloads.length; index += 1) {
  const name = `hostile anonymous login value ${index + 1} stays inert`;
  test(`${name} rejects a marker changed while rejection was pending`, async () => {
    const fixture = loginCase(name);
    await setImmediate();
    fixture.render({marker: 1});
    await fixture.result.done;
    assert.equal(fixture.result.error?.name, "AssertionError");
  });

  test(`${name} retains page errors delivered with rejection`, async () => {
    const fixture = loginCase(name);
    await setImmediate();
    fixture.render({pageError: new Error("delayed rejection page error")});
    await fixture.result.done;
    assert.equal(fixture.result.error?.name, "AssertionError");
    assert.match(fixture.result.error.message, /delayed rejection page error/);
  });

  test(`${name} awaits page close and retains errors delivered during close`, async () => {
    const fixture = loginCase(name, {deferClose: true});
    await setImmediate();
    fixture.render();
    await setImmediate();
    assert.equal(fixture.state.markerReads, 1);
    assert.equal(
      fixture.state.frameReads,
      2,
      "check login and final component absence before close",
    );
    assert.equal(fixture.state.closeCalls, 1, "close the page before the final error assertion");
    assert.equal(fixture.state.closed, false);
    assert.equal(fixture.result.settled, false, "the callback must await page closure");
    assert.equal(fixture.state.errorReads, 0, "keep the error assertion after page closure");
    fixture.finishClose({pageError: new Error("page error during close")});
    await fixture.result.done;
    assert.equal(fixture.state.closed, true);
    assert.equal(fixture.state.errorReads, 1);
    assert.equal(fixture.result.error?.name, "AssertionError");
    assert.match(fixture.result.error.message, /page error during close/);
  });
}
