import {test, expect} from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

const username = process.env.NAS_VM_TEST_USER;
const password = process.env.NAS_VM_TEST_PASSWORD;

if (!username || !password) {
  throw new Error("NAS_VM_TEST_USER and NAS_VM_TEST_PASSWORD are required for the final VM browser suite");
}

test.describe.configure({mode: "parallel"});

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

test("final VM exposes the installed Cockpit NAS component", async ({page}) => {
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

test("final VM remains usable at narrow and enlarged layouts", async ({page}) => {
  await page.setViewportSize({width: 360, height: 740});
  await openNasOverview(page);
  for (const fontSize of ["100%", "150%", "200%"]) {
    await page.evaluate(size => { document.documentElement.style.fontSize = size; }, fontSize);
    const metrics = await page.evaluate(() => ({
      viewport: document.documentElement.clientWidth,
      pageWidth: document.documentElement.scrollWidth,
      bodyWidth: document.body.scrollWidth,
    }));
    expect(metrics.pageWidth).toBeLessThanOrEqual(metrics.viewport + 1);
    expect(metrics.bodyWidth).toBeLessThanOrEqual(metrics.viewport + 1);
  }
});

test("final VM rejects scriptable navigation schemes in NAS links", async ({page}) => {
  await openNasOverview(page);
  const hrefs = await page.locator("a[href]").evaluateAll(nodes => nodes.map(node => node.getAttribute("href") || ""));
  for (const href of hrefs) {
    expect(href.trim().toLowerCase().startsWith("javascript:")).toBe(false);
    expect(href.trim().toLowerCase().startsWith("data:text/html")).toBe(false);
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
