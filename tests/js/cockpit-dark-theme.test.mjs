import test from "node:test";
import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";

const source = async (name) => readFile(new URL(`../../cockpit/${name}`, import.meta.url), "utf8");

function loadThemeModule({storedStyle = null, prefersDark = false} = {}) {
  const classes = new Set();
  const listeners = {};
  const mediaListeners = [];
  const store = {style: storedStyle};
  const windowStub = {
    localStorage: {
      getItem: (key) => (key === "shell:style" ? store.style : null),
    },
    matchMedia: () => ({
      matches: prefersDark,
      addEventListener: (_event, handler) => mediaListeners.push(handler),
    }),
    addEventListener: (event, handler) => {
      listeners[event] = listeners[event] || [];
      listeners[event].push(handler);
    },
  };
  const documentStub = {
    documentElement: {
      classList: {
        toggle: (name, force) => {
          if (force) classes.add(name);
          else classes.delete(name);
        },
      },
    },
  };
  const CustomEvent = class CustomEventMock {
    constructor(type, options) {
      this.type = type;
      this.detail = options?.detail;
    }
  };
  const run = async () => {
    const body = await source("src/cockpit-dark-theme.js");
    new Function("window", "document", "localStorage", "CustomEvent", body)(
      windowStub,
      documentStub,
      windowStub.localStorage,
      CustomEvent,
    );
  };
  return {
    run,
    classes,
    CustomEvent,
    emitStorage(key, newValue) {
      if (key === "shell:style") store.style = newValue;
      for (const handler of listeners.storage || []) handler({key, newValue});
    },
    emitCockpitStyle(style) {
      for (const handler of listeners["cockpit-style"] || []) {
        handler(new this.CustomEvent("cockpit-style", {detail: {style}}));
      }
    },
    emitPreferenceChange() {
      for (const handler of mediaListeners) handler();
    },
  };
}

test("dark theme module mirrors the Cockpit shell style choice onto pf-v6-theme-dark", async (t) => {
  await t.test("explicit dark style enables the PatternFly dark theme", async () => {
    const theme = loadThemeModule({storedStyle: "dark"});
    await theme.run();
    assert.ok(theme.classes.has("pf-v6-theme-dark"));
  });

  await t.test("explicit light style keeps the dark theme off despite OS preference", async () => {
    const theme = loadThemeModule({storedStyle: "light", prefersDark: true});
    await theme.run();
    assert.ok(!theme.classes.has("pf-v6-theme-dark"));
  });

  await t.test("auto follows the operating system preference", async () => {
    const dark = loadThemeModule({prefersDark: true});
    await dark.run();
    assert.ok(dark.classes.has("pf-v6-theme-dark"));
    const light = loadThemeModule({prefersDark: false});
    await light.run();
    assert.ok(!light.classes.has("pf-v6-theme-dark"));
  });

  await t.test("shell storage updates switch the theme without reload", async () => {
    const theme = loadThemeModule({storedStyle: "light"});
    await theme.run();
    assert.ok(!theme.classes.has("pf-v6-theme-dark"));
    theme.emitStorage("shell:style", "dark");
    assert.ok(theme.classes.has("pf-v6-theme-dark"));
  });

  await t.test("shell style events override the stored preference", async () => {
    const theme = loadThemeModule({storedStyle: "dark"});
    await theme.run();
    assert.ok(theme.classes.has("pf-v6-theme-dark"));
    theme.emitCockpitStyle("light");
    assert.ok(!theme.classes.has("pf-v6-theme-dark"));
  });
});

test("entry point wires the vendored dark theme module into the bundle", async () => {
  const index = await source("src/index.jsx");
  assert.match(index, /import "\.\/cockpit-dark-theme\.js";/);
});
