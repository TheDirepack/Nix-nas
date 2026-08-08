import {test, expect} from "@playwright/test";

const seeds = [
  "<script>alert(1)</script>",
  '<img src=x onerror="alert(1)">',
  '<svg/onload=alert(1)>',
  "javascript:alert(1)",
  "' OR 1=1 --",
  "\r\nX-Injected: yes",
  "../".repeat(32),
];

function mutate(seed, index) {
  const variants = [
    seed,
    seed.toUpperCase(),
    seed.replaceAll("<", "%3C").replaceAll(">", "%3E"),
    seed.replaceAll("<", "&lt;").replaceAll(">", "&gt;"),
    `prefix-${index}-${seed}-suffix`,
    `${"W".repeat((index % 16) * 64)}${seed}`,
  ];
  return variants[index % variants.length];
}

const cases = Array.from({length: 96}, (_, index) => ({
  name: `mutation-${String(index).padStart(3, "0")}`,
  value: mutate(seeds[index % seeds.length], index),
}));

test.describe.configure({mode: "parallel"});

for (const {name, value} of cases) {
  test(`slow hostile-input fuzz ${name}`, async ({page}) => {
    await page.addInitScript(payload => {
      globalThis.__nas_xss = 0;
      const response = {
        host: payload,
        protectedReady: true,
        setup: {firstStart: {status: "complete", message: payload}, setupState: {status: "complete"}},
        identity: {ok: true, users: [{uid: payload}], groups: [], administrators: [], shareAuthority: payload},
        capabilities: {ok: true, users: []},
        featureControl: {features: [], memory: {components: [], system: {availableBytes: 1}}},
        update: {revision: payload, branch: payload, upstream: payload, ahead: 0, behind: 0, dirty: false},
        services: [{unit: payload, active: payload, enabled: payload, sub: payload, load: payload}],
        zpool: {ok: true, text: payload},
        zfs: {ok: true, text: payload},
        failedUnits: [payload],
        timers: [],
        operationState: {busyClasses: [], conflictsByAction: {}, featureConflicts: []},
        links: {identity: "/identity/", documentation: "/docs/", shares: "/shares/", settings: payload, files: payload},
      };
      globalThis.cockpit = {
        spawn() {
          const promise = Promise.resolve(JSON.stringify(response));
          promise.input = () => {};
          promise.stream = () => promise;
          return promise;
        },
      };
    }, value);
    await page.goto("/index.html");
    await expect(page.getByRole("heading", {name: "NAS Overview"})).toBeVisible();
    expect(await page.evaluate(() => globalThis.__nas_xss)).toBe(0);
    expect(await page.locator("script, iframe, svg, img").evaluateAll(nodes => nodes.some(node => node.outerHTML.includes("alert(1)")))).toBe(false);
  });
}
