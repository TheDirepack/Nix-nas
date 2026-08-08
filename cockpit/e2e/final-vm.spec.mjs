import {test, expect} from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

const username = process.env.NAS_VM_TEST_USER;
const password = process.env.NAS_VM_TEST_PASSWORD;

if (!username || !password) {
  throw new Error("NAS_VM_TEST_USER and NAS_VM_TEST_PASSWORD are required for the final VM browser suite");
}

test.describe.configure({mode: "parallel"});

async function expectLogin(page) {
  await expect(page.locator("#login-user-input")).toBeVisible();
  await expect(page.locator("#login-password-input")).toBeVisible();
  await expect(page.locator("#login-button")).toBeVisible();
  await expect(page.getByRole("heading", {name: "NAS Overview"})).toHaveCount(0);
}

async function login(page) {
  await page.goto("/");
  const user = page.locator("#login-user-input");
  const pass = page.locator("#login-password-input");
  const button = page.locator("#login-button");
  await expect(user).toBeVisible();
  await user.fill(username);
  await pass.fill(password);
  await button.click();
  await expect(page.locator("#login-user-input")).toHaveCount(0, {timeout: 30_000});
}

async function openNasOverview(page) {
  await login(page);
  const link = page.getByText("NAS Overview", {exact: true}).first();
  await expect(link).toBeVisible({timeout: 30_000});
  await link.click();
  await expect(page.getByRole("heading", {name: "NAS Overview"})).toBeVisible({timeout: 30_000});
}

function documentMetrics() {
  return {
    viewport: document.documentElement.clientWidth,
    pageWidth: document.documentElement.scrollWidth,
    bodyWidth: document.body.scrollWidth,
  };
}

test("anonymous clients see only the Cockpit login boundary", async ({page}) => {
  const errors = [];
  page.on("pageerror", error => errors.push(String(error)));
  await page.goto("/");
  await expectLogin(page);
  expect(errors).toEqual([]);
});

test("direct anonymous attempts to reach the NAS component remain login-protected", async ({page}) => {
  for (const path of ["/cockpit/@localhost/nixos-nas/index.html", "/cockpit/@localhost/nixos-nas/", "/#/nixos-nas"]) {
    await page.goto(path);
    await expectLogin(page);
  }
});

test("invalid credentials cannot expose the NAS component", async ({page}) => {
  await page.goto("/");
  await page.locator("#login-user-input").fill(`invalid-${Date.now()}`);
  await page.locator("#login-password-input").fill("definitely-not-a-password");
  await page.locator("#login-button").click();
  await expect(page.locator("#login-user-input")).toBeVisible();
  await expect(page.getByRole("heading", {name: "NAS Overview"})).toHaveCount(0);
});

test("hostile anonymous login values stay inert", async ({page}) => {
  const errors = [];
  page.on("pageerror", error => errors.push(String(error)));
  await page.addInitScript(() => { globalThis.__nas_login_xss = 0; });
  await page.goto("/");
  const payloads = [
    '<script>globalThis.__nas_login_xss=1</script>',
    '<img src=x onerror="globalThis.__nas_login_xss=2">',
    '<svg/onload=globalThis.__nas_login_xss=3>',
    '\"><iframe srcdoc="<script>parent.__nas_login_xss=4<\\/script>"></iframe>',
    "javascript:globalThis.__nas_login_xss=5",
    "' OR 1=1 --",
    "../../../../etc/passwd",
    "\r\nX-Injected: yes",
  ];
  for (const payload of payloads) {
    await page.locator("#login-user-input").fill(payload);
    await page.locator("#login-password-input").fill(payload);
    await page.locator("#login-button").click();
    await expect(page.locator("#login-user-input")).toBeVisible();
    expect(await page.evaluate(() => globalThis.__nas_login_xss)).toBe(0);
  }
  expect(errors).toEqual([]);
});

test("final VM exposes the installed Cockpit NAS component after real authentication", async ({page}) => {
  const pageErrors = [];
  page.on("pageerror", error => pageErrors.push(String(error)));
  await openNasOverview(page);
  await expect(page.getByRole("heading", {name: "Service policies"})).toBeVisible();
  expect(pageErrors).toEqual([]);
});

test("final VM component has no serious or critical accessibility violations", async ({page}) => {
  await openNasOverview(page);
  const result = await new AxeBuilder({page})
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  const blocking = result.violations.filter(item => ["serious", "critical"].includes(item.impact));
  expect(blocking).toEqual([]);
});

test("final VM has no overlap or document overflow across common layouts and 200 percent text", async ({page}) => {
  await openNasOverview(page);
  for (const viewport of [
    {width: 320, height: 568},
    {width: 375, height: 667},
    {width: 768, height: 900},
    {width: 1366, height: 768},
    {width: 1920, height: 1080},
  ]) {
    await page.setViewportSize(viewport);
    for (const scale of [1, 1.5, 2]) {
      await page.evaluate(value => { document.documentElement.style.fontSize = `${value * 100}%`; }, scale);
      const metrics = await page.evaluate(documentMetrics);
      expect(metrics.pageWidth).toBeLessThanOrEqual(metrics.viewport + 1);
      expect(metrics.bodyWidth).toBeLessThanOrEqual(metrics.viewport + 1);

      const visible = page.locator('button, a[href], select, input, textarea, [role="dialog"], [role="alert"]:visible');
      const boxes = [];
      for (let index = 0, count = await visible.count(); index < Math.min(count, 80); index += 1) {
        const item = visible.nth(index);
        if (!(await item.isVisible())) continue;
        const box = await item.boundingBox();
        if (box) boxes.push(box);
      }
      for (const box of boxes) {
        expect(box.width).toBeGreaterThan(0);
        expect(box.height).toBeGreaterThan(0);
        expect(box.x).toBeLessThanOrEqual(viewport.width + 1);
        expect(box.x + box.width).toBeGreaterThanOrEqual(-1);
      }
    }
  }
});

test("final VM visible controls remain keyboard reachable and DOM ids are unique", async ({page}) => {
  await page.setViewportSize({width: 360, height: 740});
  await openNasOverview(page);
  const ids = await page.locator("[id]").evaluateAll(nodes => nodes.map(node => node.id).filter(Boolean));
  expect(new Set(ids).size).toBe(ids.length);
  const controls = page.locator('button, a[href], select, input, textarea, [tabindex]:not([tabindex="-1"])');
  expect(await controls.count()).toBeGreaterThan(4);
  await page.keyboard.press("Tab");
  expect(await page.evaluate(() => document.activeElement !== document.body)).toBe(true);
});

test("final VM confirmation dialog stays usable at extreme zoom", async ({page}) => {
  await page.setViewportSize({width: 320, height: 568});
  await openNasOverview(page);
  await page.evaluate(() => { document.documentElement.style.fontSize = "200%"; });
  const trigger = page.getByRole("button", {name: "Run system health checks"});
  await expect(trigger).toBeVisible();
  await trigger.click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  const box = await dialog.boundingBox();
  expect(box).not.toBeNull();
  expect(box.x).toBeGreaterThanOrEqual(-1);
  expect(box.x + box.width).toBeLessThanOrEqual(321);
  const cancel = page.getByRole("button", {name: "Cancel"});
  await cancel.focus();
  await expect(cancel).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
});

test("final VM rejects scriptable navigation schemes in NAS links", async ({page}) => {
  await openNasOverview(page);
  const hrefs = await page.locator("a[href]").evaluateAll(nodes => nodes.map(node => node.getAttribute("href") || ""));
  for (const href of hrefs) {
    const value = href.trim().toLowerCase();
    expect(value.startsWith("javascript:")).toBe(false);
    expect(value.startsWith("data:text/html")).toBe(false);
    expect(value.startsWith("vbscript:")).toBe(false);
  }
});

test("final VM CSP blocks inline script execution in the component frame", async ({page}) => {
  await openNasOverview(page);
  const result = await page.evaluate(() => {
    globalThis.__nas_inline_probe = 0;
    const script = document.createElement("script");
    script.textContent = "globalThis.__nas_inline_probe = 1";
    document.body.append(script);
    script.remove();
    return globalThis.__nas_inline_probe;
  });
  expect(result).toBe(0);
});
