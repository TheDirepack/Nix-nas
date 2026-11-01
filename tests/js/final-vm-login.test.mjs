import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {setImmediate} from "node:timers/promises";
import vm from "node:vm";

const source = readFileSync(new URL("../../cockpit/e2e/final-vm.spec.mjs", import.meta.url), "utf8")
  .replace('import {test, expect} from "@playwright/test";\n', "")
  .replace('import AxeBuilder from "@axe-core/playwright";\n', "");

function deferred() {
  let resolve;
  const promise = new Promise((done) => {
    resolve = done;
  });
  return {promise, resolve};
}

function loginCase(name) {
  const cases = new Map();
  const state = {
    stage: "username",
    url: "https://nas.test/identity/if/flow/default-authentication-flow/",
    marker: 0,
    markerReads: 0,
    earlyCookieClears: 0,
    cookieClears: 0,
    navigations: 0,
    cancellations: 0,
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
        state.submissions.push({password: state.password, visible: deferred(), rendered: false});
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
          assert.equal(role, "link");
          assert.equal(options.name, "Not you?");
          assert.equal(state.stage, "password");
          assert.ok(state.submissions.every((item) => item.rendered));
          state.cancellations += 1;
          state.stage = "username";
        },
      };
    },
    locator() {
      return button;
    },
    frames: () => [],
    async evaluate() {
      state.markerReads += 1;
      return state.marker;
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
  assert.ok(cases.has(name));
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
  return {state, result, render};
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

test("hostile-login callback waits for every rejection before assertions or cookie clearing", async () => {
  const fixture = loginCase("hostile anonymous login values stay inert");
  for (let index = 0; index < 8; index += 1) {
    await setImmediate();
    assert.equal(fixture.result.settled, false);
    assert.equal(fixture.state.submissions.length, index + 1);
    assert.equal(fixture.state.markerReads, index, "inertness must be checked after rejection");
    assert.equal(fixture.state.earlyCookieClears, 0);
    fixture.render();
  }
  await fixture.result.done;
  assert.equal(fixture.result.error, undefined);
  assert.equal(fixture.state.markerReads, 8);
  assert.equal(fixture.state.submissions.length, 8);
  assert.equal(new Set(fixture.state.submissions.map((item) => item.password)).size, 8);
  assert.equal(fixture.state.navigations, 1, "initialize the anonymous login flow once");
  assert.equal(fixture.state.cookieClears, 0, "retain native anonymous CSRF/session state");
  assert.equal(
    fixture.state.cancellations,
    7,
    "reset each rejected flow through native cancellation",
  );
});

test("hostile-login callback rejects a marker changed while rejection was pending", async () => {
  const fixture = loginCase("hostile anonymous login values stay inert");
  await setImmediate();
  fixture.render({marker: 1});
  await fixture.result.done;
  assert.equal(fixture.result.error?.name, "AssertionError");
});

test("hostile-login callback retains page errors delivered with rejection", async () => {
  const fixture = loginCase("hostile anonymous login values stay inert");
  for (let index = 0; index < 8; index += 1) {
    await setImmediate();
    fixture.render({
      pageError: index === 0 ? new Error("delayed rejection page error") : undefined,
    });
  }
  await fixture.result.done;
  assert.equal(fixture.result.error?.name, "AssertionError");
  assert.match(fixture.result.error.message, /delayed rejection page error/);
});
