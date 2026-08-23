import {test, expect} from "@playwright/test";

const payloads = [
  ["script-tag", "<script>globalThis.__nas_xss=1</script>"],
  ["img-onerror", '<img src=x onerror="globalThis.__nas_xss=2">'],
  ["svg-onload", "<svg/onload=globalThis.__nas_xss=3>"],
  ["details-ontoggle", '<details open ontoggle="globalThis.__nas_xss=4">x</details>'],
  ["body-onload", '<body onload="globalThis.__nas_xss=5">'],
  ["iframe-srcdoc", '<iframe srcdoc="<script>parent.__nas_xss=6<\/script>"></iframe>'],
  ["javascript-url", "javascript:globalThis.__nas_xss=7"],
  ["data-html-url", "data:text/html,<script>parent.__nas_xss=8</script>"],
  ["attribute-breakout", '\"><img src=x onerror=globalThis.__nas_xss=9>'],
  ["single-quote-breakout", "'><svg onload=globalThis.__nas_xss=10>"],
  ["encoded-script", "&lt;script&gt;globalThis.__nas_xss=11&lt;/script&gt;"],
  ["mixed-case", "<ScRiPt>globalThis.__nas_xss=12</ScRiPt>"],
  ["nullish-tag", "<img src=x onerror=globalThis.__nas_xss=13\u0000>"],
  ["template-ish", "${globalThis.__nas_xss=14}<img src=x onerror=globalThis.__nas_xss=15>"],
  ["css-url", 'url("javascript:globalThis.__nas_xss=16")'],
  ["event-newline", '<img src=x\nonerror="globalThis.__nas_xss=17">'],
];

test.describe.configure({mode: "parallel"});

async function installPayload(page, payload) {
  await page.addInitScript((value) => {
    globalThis.__nas_xss = 0;
    const response = {
      host: value,
      protectedReady: true,
      setup: {firstStart: {status: "complete", message: value}, setupState: {status: "complete"}},
      identity: {
        ok: true,
        users: [{uid: value}],
        groups: [],
        administrators: [],
        shareAuthority: value,
      },
      capabilities: {ok: true, users: []},
      featureControl: {features: [], memory: {components: [], system: {availableBytes: 1}}},
      update: {revision: value, branch: value, upstream: value, ahead: 0, behind: 0, dirty: false},
      services: [{unit: value, active: value, enabled: value, sub: value, load: value}],
      zpool: {ok: true, text: value},
      zfs: {ok: true, text: value},
      failedUnits: [value],
      timers: [],
      operationState: {busyClasses: [], conflictsByAction: {}, featureConflicts: []},
      links: {
        identity: "/identity/",
        documentation: "/docs/",
        shares: "/shares/",
        settings: value,
        files: value,
      },
    };
    globalThis.cockpit = {
      spawn() {
        const promise = Promise.resolve(JSON.stringify(response));
        promise.input = () => {};
        promise.stream = () => promise;
        return promise;
      },
    };
  }, payload);
}

for (const [name, payload] of payloads) {
  test(`common XSS probe is rendered inert: ${name}`, async ({page}) => {
    const pageErrors = [];
    page.on("pageerror", (error) => pageErrors.push(String(error)));
    await installPayload(page, payload);
    await page.goto("/index.html");
    await expect(page.getByRole("heading", {name: "NixOS NAS"})).toBeVisible();
    expect(await page.evaluate(() => globalThis.__nas_xss)).toBe(0);
    expect(
      await page
        .locator("script, iframe, svg, img")
        .evaluateAll((nodes) => nodes.some((node) => node.outerHTML.includes("__nas_xss"))),
    ).toBe(false);
    expect(pageErrors).toEqual([]);
  });
}
