import {test, expect} from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

const xss = '<img src=x onerror="globalThis.__nas_xss=(globalThis.__nas_xss||0)+1">';
const longToken = `long-${"W".repeat(2048)}`;
const hostileDisplayCorpus = [
  ["img-onerror", xss],
  ["script-tag", "<script>globalThis.__nas_xss=2</script>"],
  ["svg-onload", "<svg/onload=globalThis.__nas_xss=3>"],
  ["javascript-url", "javascript:globalThis.__nas_xss=4"],
  ["attribute-breakout", '"><img src=x onerror=globalThis.__nas_xss=5>'],
  ["details-ontoggle", '<details open ontoggle="globalThis.__nas_xss=6">x</details>'],
  ["body-onload", '<body onload="globalThis.__nas_xss=7">'],
  ["iframe-srcdoc", '<iframe srcdoc="<script>parent.__nas_xss=8<\\/script>"></iframe>'],
  ["data-html-url", "data:text/html,<script>parent.__nas_xss=9</script>"],
  ["single-quote-breakout", "'><svg onload=globalThis.__nas_xss=10>"],
  ["encoded-script", "&lt;script&gt;globalThis.__nas_xss=11&lt;/script&gt;"],
  ["mixed-case-script", "<ScRiPt>globalThis.__nas_xss=12</ScRiPt>"],
  ["nullish-tag", "<img src=x onerror=globalThis.__nas_xss=13\u0000>"],
  ["template-ish", "${globalThis.__nas_xss=14}<img src=x onerror=globalThis.__nas_xss=15>"],
  ["css-url", 'url("javascript:globalThis.__nas_xss=16")'],
  ["event-newline", '<img src=x\nonerror="globalThis.__nas_xss=17">'],
  ["bidi-long-text", "\u202e" + "W".repeat(1024)],
];

function overview() {
  return {
    host: `nas-${xss}`,
    protectedReady: true,
    zfsReplicationInstalled: true,
    authentikTokenWarning: "",
    setup: {
      firstStart: {status: "complete", message: "complete"},
      setupState: {status: "complete"},
    },
    identity: {
      ok: true,
      users: [{uid: "alice"}],
      groups: [],
      administrators: ["operator"],
      shareAuthority: "CopyParty",
    },
    capabilities: {
      ok: true,
      users: [
        {
          id: "alice",
          displayName: xss,
          administrator: false,
          capabilities: {
            files: {allowed: true, source: xss},
            webdav: {allowed: false, source: "default"},
            ai: {allowed: false, source: "default"},
            vault: {allowed: true, source: "group"},
          },
        },
      ],
    },
    featureControl: {
      features: [
        {
          id: "aiWorkspace",
          label: xss,
          description: xss,
          available: true,
          runtimeAvailable: true,
          effective: true,
          requestedMode: "on-demand",
          effectiveMode: "on-demand",
          allowedModes: ["off", "on-demand", "always"],
          running: false,
          idleRemainingSeconds: null,
          units: [],
        },
      ],
      memory: {
        residentEstimateMiB: {min: 100, max: 200, typical: 150},
        activeEstimateMiB: {min: 100, max: 200, typical: 150},
        configuredMaximumMiB: {min: 200, max: 300, typical: 250},
        onDemandSavingsMiB: {typical: 100},
        system: {availableBytes: 1024 * 1024 * 1024},
        components: [
          {
            id: "core",
            label: xss,
            configured: true,
            resident: true,
            mode: "core",
            estimateMiB: {min: 1, max: 2, typical: 1},
            currentBytes: 1024,
            notes: xss,
          },
        ],
      },
    },
    update: {
      revision: "deadbeef",
      branch: "main",
      upstream: "origin/main",
      ahead: 0,
      behind: 0,
      dirty: false,
    },
    services: [
      {
        unit: "cockpit.socket",
        active: "active",
        enabled: "enabled",
        sub: "listening",
        load: "loaded",
      },
    ],
    managedServices: {
      services: [
        {
          id: "policy-probe",
          label: xss,
          description: "hostile label probe",
          managed: true,
          requestedMode: "off",
          effectiveMode: "always",
          healthy: true,
          allowedModes: ["off", "on-demand", "always"],
          units: [],
        },
      ],
    },
    zpool: {ok: true, text: xss},
    zfs: {ok: true, text: `tank/nas 1G 2G ${xss}`},
    failedUnits: [xss, longToken],
    timers: [],
    operationState: {busyClasses: [], conflictsByAction: {}, featureConflicts: ["runtime"]},
    links: {
      identity: "/identity/",
      documentation: "/docs/",
      shares: "/shares/",
      zfs: "/zfs/",
      network: "/network/",
      settings: "javascript:globalThis.__nas_xss=9",
      files: "//evil.invalid/files",
    },
  };
}

function hostileOverview(value) {
  const data = overview();
  data.setup.firstStart.message = value;
  data.setup.firstStart.configPath = value;
  data.setup.firstStart.planDigest = value;
  data.update.revision = value;
  data.update.branch = value;
  data.update.upstream = value;
  data.featureControl.features[0].label = value;
  data.featureControl.features[0].description = value;
  data.featureControl.features[0].parent = value;
  data.featureControl.features[0].availabilityReason = value;
  data.featureControl.features[0].heldBy = [value];
  data.featureControl.memory.components[0].label = value;
  data.featureControl.memory.components[0].mode = value;
  data.featureControl.memory.components[0].notes = value;
  data.capabilities.users[0].displayName = value;
  data.capabilities.users[0].capabilities.files.source = value;
  data.aiConfig = {
    ok: true,
    localModels: [
      {
        id: "local-model",
        path: value,
        context: 32768,
        ttl: 300,
        tools: true,
        extraArgs: [value],
        managed: true,
      },
    ],
    providers: [
      {
        id: "provider",
        url: value,
        models: [value],
        credentialConfigured: false,
        timeouts: {connect: 30, keepalive: 30, responseHeader: 60, tlsHandshake: 10, idleConn: 90},
        filters: {stripParams: value, setParams: {[value]: value}},
      },
    ],
    availableTargets: [value],
    codingRoles: {"coding/default": {targets: [value], strategy: "warm", spillover: 1}},
    advanced: {
      healthCheckTimeout: 300,
      globalTTL: 300,
      unloadTimeout: 10,
      logLevel: value,
      captureBuffer: 0,
      metricsMaxInMemory: 250,
    },
  };
  data.operationState.active = [{action: value, startedAt: 0}];
  data.failedUnits = [value, longToken];
  data.timers = [value];
  data.services = [{unit: value, active: value, enabled: value, sub: value, load: value}];
  data.zpool.text = value;
  data.zfs.text = value;
  for (const key of Object.keys(data.links)) data.links[key] = value;
  return data;
}

async function installCockpitMock(page, behavior = {}) {
  const data = behavior.payload || overview();
  await page.addInitScript(
    ({payload, configuredBehavior}) => {
      globalThis.__nas_xss = 0;
      globalThis.__nas_spawn_calls = [];
      const response = structuredClone(payload);
      const rejected = (message) => {
        const promise = Promise.reject(new Error(message));
        promise.input = () => {};
        promise.stream = () => promise;
        return promise;
      };
      globalThis.cockpit = {
        spawn(args) {
          globalThis.__nas_spawn_calls.push([...args]);
          if (
            args[0] === "nas-cockpit-api" &&
            args[1] === "overview" &&
            configuredBehavior.overviewError
          ) {
            return rejected(configuredBehavior.overviewError);
          }
          if (
            args[0] === "nas-cockpit-api" &&
            args[1] === "feature" &&
            configuredBehavior.featureError
          ) {
            return rejected(configuredBehavior.featureError);
          }
          if (
            args[0] === "nas-cockpit-api" &&
            args[1] === "action" &&
            configuredBehavior.actionError
          ) {
            return rejected(configuredBehavior.actionError);
          }
          let value = {ok: true};
          if (args[0] === "nas-cockpit-api" && args[1] === "overview") value = response;
          if (args[0] === "nas-cockpit-api" && args[1] === "feature")
            value = {ok: true, feature: args[2], mode: args[3]};
          if (args[0] === "nas-cockpit-api" && args[1] === "action")
            value = {ok: true, action: args[2], output: "ok"};
          const promise = Promise.resolve(JSON.stringify(value));
          promise.input = () => {};
          promise.stream = () => promise;
          return promise;
        },
      };
    },
    {payload: data, configuredBehavior: behavior},
  );
}

async function openApp(page, behavior = {}) {
  await installCockpitMock(page, behavior);
  await page.goto("/index.html");
  await expect(page.getByRole("heading", {name: "NixOS NAS"})).toBeVisible();
  await expect(page.getByText("Managed Services V2").first()).toBeVisible();
}

async function openOperationsSection(page) {
  await page.locator(".pf-v6-c-nav").getByText("Operations", {exact: true}).click();
  await expect(page.getByRole("heading", {name: "Operations"})).toBeVisible();
}

test("renders hostile backend text as text, never executable markup", async ({page}) => {
  const pageErrors = [];
  page.on("pageerror", (error) => pageErrors.push(String(error)));
  await openApp(page);
  await expect(page.getByText(xss, {exact: true}).first()).toBeVisible();
  expect(await page.evaluate(() => globalThis.__nas_xss)).toBe(0);
  expect(
    await page
      .locator("script")
      .evaluateAll((nodes) => nodes.some((node) => node.textContent?.includes("__nas_xss"))),
  ).toBe(false);
  expect(await page.locator("img").count()).toBe(0);
  await expect(page.getByRole("link", {name: "My account settings"})).toHaveCount(0);
  await expect(page.getByRole("link", {name: "Host files"})).toHaveCount(0);
  expect(pageErrors).toEqual([]);
});

for (const [name, payload] of hostileDisplayCorpus) {
  test(`every custom UI display surface stays inert: ${name}`, async ({page}) => {
    const pageErrors = [];
    page.on("pageerror", (error) => pageErrors.push(String(error)));
    await openApp(page, {payload: hostileOverview(payload)});
    await expect(page.getByText(payload, {exact: true}).first()).toBeVisible();
    expect(await page.evaluate(() => globalThis.__nas_xss)).toBe(0);
    const unsafeNodes = await page
      .locator("script, iframe, svg, img, object, embed")
      .evaluateAll((nodes) =>
        nodes
          .filter((node) => {
            const tag = node.tagName.toLowerCase();
            const html = node.outerHTML;
            if (tag === "svg") {
              return /onerror\s*=|onload\s*=|javascript:|srcdoc\s*=|__nas_xss/i.test(html);
            }
            return /__nas_xss|javascript:|onerror\s*=|onload\s*=|srcdoc\s*=|<script[^>]*>[^<]/i.test(
              html,
            );
          })
          .map((node) => node.outerHTML),
      );
    expect(unsafeNodes).toEqual([]);
    expect(await page.locator('[href^="javascript:"], [href^="//"]').count()).toBe(0);
    expect(pageErrors).toEqual([]);
  });
}

test("stays within the viewport and keeps controls usable", async ({page}) => {
  await openApp(page);
  const metrics = await page.evaluate(() => ({
    viewport: document.documentElement.clientWidth,
    pageWidth: document.documentElement.scrollWidth,
    bodyWidth: document.body.scrollWidth,
  }));
  expect(metrics.pageWidth).toBeLessThanOrEqual(metrics.viewport + 1);
  expect(metrics.bodyWidth).toBeLessThanOrEqual(metrics.viewport + 1);

  await page.locator(".pf-v6-c-nav").getByText("Managed services", {exact: true}).click();
  const select = page.getByLabel(`${xss} runtime policy`);
  await expect(select).toBeVisible();
  await select.selectOption("always");
  await openOperationsSection(page);
  await page.getByRole("button", {name: "Run system health checks"}).click();
  await expect(page.getByRole("heading", {name: "Confirm maintenance action"})).toBeVisible();
  await page.getByRole("button", {name: "Cancel"}).click();
});

test("has no serious or critical automated accessibility violations", async ({page}) => {
  await openApp(page);
  const result = await new AxeBuilder({page})
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  const blocking = result.violations.filter((item) =>
    ["serious", "critical"].includes(item.impact),
  );
  expect(blocking).toEqual([]);
});

test("handles narrow, wide, and enlarged-text layouts without document overflow", async ({
  page,
}) => {
  await openApp(page);
  for (const viewport of [
    {width: 320, height: 568},
    {width: 375, height: 667},
    {width: 768, height: 900},
    {width: 1366, height: 768},
    {width: 1920, height: 1080},
  ]) {
    await page.setViewportSize(viewport);
    for (const fontScale of [1, 2]) {
      await page.evaluate((scale) => {
        document.documentElement.style.fontSize = `${scale * 100}%`;
      }, fontScale);
      const metrics = await page.evaluate(() => ({
        viewport: document.documentElement.clientWidth,
        pageWidth: document.documentElement.scrollWidth,
        bodyWidth: document.body.scrollWidth,
      }));
      expect(metrics.pageWidth).toBeLessThanOrEqual(metrics.viewport + 1);
      expect(metrics.bodyWidth).toBeLessThanOrEqual(metrics.viewport + 1);
    }
  }
});

test("all visible interactive controls stay inside the viewport and keyboard reachable", async ({
  page,
}) => {
  await page.setViewportSize({width: 360, height: 740});
  await openApp(page);
  const controls = page.locator(
    'button, a[href], select, input, textarea, [tabindex]:not([tabindex="-1"])',
  );
  const count = await controls.count();
  expect(count).toBeGreaterThan(4);
  for (let index = 0; index < Math.min(count, 40); index += 1) {
    const control = controls.nth(index);
    if (!(await control.isVisible())) continue;
    const box = await control.boundingBox();
    if (!box) continue;
    expect(box.width).toBeGreaterThan(0);
    expect(box.height).toBeGreaterThan(0);
    expect(box.x).toBeLessThan(361);
    expect(box.x + box.width).toBeGreaterThan(0);
  }
  await page.keyboard.press("Tab");
  expect(await page.evaluate(() => document.activeElement !== document.body)).toBe(true);
});

test("has unique DOM ids and keeps the confirmation dialog usable at extreme zoom", async ({
  page,
}) => {
  await page.setViewportSize({width: 320, height: 568});
  await openApp(page);
  const ids = await page
    .locator("[id]")
    .evaluateAll((nodes) => nodes.map((node) => node.id).filter(Boolean));
  expect(new Set(ids).size).toBe(ids.length);

  await openOperationsSection(page);
  await page.evaluate(() => {
    document.documentElement.style.fontSize = "200%";
  });
  await page.getByRole("button", {name: "Run system health checks"}).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  const box = await dialog.boundingBox();
  expect(box).not.toBeNull();
  expect(box.x).toBeGreaterThanOrEqual(-1);
  expect(box.x + box.width).toBeLessThanOrEqual(321);
  const cancel = page.getByRole("button", {name: "Cancel"});
  await expect(cancel).toBeVisible();
  await cancel.focus();
  await expect(cancel).toBeFocused();
});

test("hostile status corpus never creates executable elements", async ({page}) => {
  await openApp(page);
  const hostile = [
    "<script>globalThis.__nas_xss=2</script>",
    "<svg/onload=globalThis.__nas_xss=3>",
    "javascript:globalThis.__nas_xss=4",
    "../".repeat(256),
    "' OR 1=1 --",
    "\r\nX-Injected: yes",
    "\u202e" + "W".repeat(1024),
  ];
  await page.evaluate((values) => {
    const root = document.createElement("div");
    root.id = "nas-hostile-corpus";
    for (const value of values) {
      const item = document.createElement("span");
      item.textContent = value;
      root.append(item);
    }
    document.body.append(root);
  }, hostile);
  expect(
    await page
      .locator("#nas-hostile-corpus script, #nas-hostile-corpus svg, #nas-hostile-corpus img")
      .count(),
  ).toBe(0);
  expect(await page.evaluate(() => globalThis.__nas_xss)).toBe(0);
});

test("backend refresh failure becomes a bounded operator-visible error", async ({page}) => {
  const pageErrors = [];
  page.on("pageerror", (error) => pageErrors.push(String(error)));
  await installCockpitMock(page, {overviewError: "simulated backend outage"});
  await page.goto("/index.html");
  await expect(page.getByRole("heading", {name: "NixOS NAS"})).toBeVisible();
  await expect(page.getByRole("heading", {name: /Unable to load appliance status/})).toBeVisible();
  await expect(page.getByText("simulated backend outage", {exact: true})).toBeVisible();
  await expect(page.getByLabel("Loading NAS state")).toHaveCount(0);
  expect(pageErrors).toEqual([]);
});

test("privileged action failure stays recoverable and never becomes an uncaught page error", async ({
  page,
}) => {
  const pageErrors = [];
  page.on("pageerror", (error) => pageErrors.push(String(error)));
  await openApp(page, {actionError: "simulated operation rejection"});
  await openOperationsSection(page);
  await page.getByRole("button", {name: "Run system health checks"}).click();
  await page.getByRole("button", {name: "Confirm"}).click();
  await expect(page.getByRole("heading", {name: /Operation failed/})).toBeVisible();
  await expect(page.getByText("simulated operation rejection", {exact: true})).toBeVisible();
  await expect(page.getByRole("dialog")).toBeVisible();
  await page.getByRole("button", {name: "Cancel"}).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  expect(pageErrors).toEqual([]);
});

test("confirmation dialog supports keyboard cancellation", async ({page}) => {
  await openApp(page);
  await openOperationsSection(page);
  const trigger = page.getByRole("button", {name: "Run system health checks"});
  await trigger.click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  const actionCalls = await page.evaluate(
    () => globalThis.__nas_spawn_calls.filter((args) => args[1] === "action").length,
  );
  expect(actionCalls).toBe(0);
});
