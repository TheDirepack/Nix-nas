import {test, expect} from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

const username = process.env.NAS_VM_TEST_USER;
const password = process.env.NAS_VM_TEST_PASSWORD;

if (!username || !password) {
  throw new Error("NAS_VM_TEST_USER and NAS_VM_TEST_PASSWORD are required for the final VM browser suite");
}

test.describe.configure({mode: "parallel"});

const VIEWPORTS = [
  {width: 320, height: 568},
  {width: 375, height: 667},
  {width: 768, height: 900},
  {width: 1366, height: 768},
  {width: 1920, height: 1080},
];
const TEXT_SCALES = [1, 1.5, 2];
const INTERACTIVE = 'button, a[href], select, input, textarea, [role="dialog"], [role="alert"]';

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
  await expect(user).toBeVisible();
  await user.fill(username);
  await pass.fill(password);
  await page.locator("#login-button").click();
  await expect(page.locator("#login-user-input")).toHaveCount(0, {timeout: 30_000});
}

async function openNasOverview(page) {
  await login(page);
  const link = page.getByText("NAS Overview", {exact: true}).first();
  await expect(link).toBeVisible({timeout: 30_000});
  await link.click();
  await expect(page.getByRole("heading", {name: "NAS Overview"})).toBeVisible({timeout: 30_000});
}

async function expectNoSeriousAxeViolations(page) {
  const result = await new AxeBuilder({page})
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  const blocking = result.violations.filter(item => ["serious", "critical"].includes(item.impact));
  expect(blocking).toEqual([]);
}

async function expectLayoutHealthy(page, viewport) {
  const metrics = await page.evaluate(() => ({
    viewport: document.documentElement.clientWidth,
    pageWidth: document.documentElement.scrollWidth,
    bodyWidth: document.body.scrollWidth,
  }));
  expect(metrics.pageWidth).toBeLessThanOrEqual(metrics.viewport + 1);
  expect(metrics.bodyWidth).toBeLessThanOrEqual(metrics.viewport + 1);

  const boxes = await page.locator(INTERACTIVE).evaluateAll(nodes => nodes
    .filter(node => {
      const style = getComputedStyle(node);
      const rect = node.getBoundingClientRect();
      return style.visibility !== "hidden" && style.display !== "none" && rect.width > 0 && rect.height > 0;
    })
    .slice(0, 100)
    .map((node, index) => {
      const rect = node.getBoundingClientRect();
      return {
        index,
        tag: node.tagName,
        id: node.id || "",
        text: (node.getAttribute("aria-label") || node.textContent || "").trim().slice(0, 80),
        x: rect.x,
        y: rect.y,
        width: rect.width,
        height: rect.height,
      };
    }));

  for (const box of boxes) {
    expect(box.x).toBeGreaterThanOrEqual(-1);
    expect(box.x + box.width).toBeLessThanOrEqual(viewport.width + 1);
    expect(box.y + box.height).toBeGreaterThanOrEqual(-1);
  }

  const collisions = [];
  for (let left = 0; left < boxes.length; left += 1) {
    for (let right = left + 1; right < boxes.length; right += 1) {
      const a = boxes[left];
      const b = boxes[right];
      const overlapWidth = Math.min(a.x + a.width, b.x + b.width) - Math.max(a.x, b.x);
      const overlapHeight = Math.min(a.y + a.height, b.y + b.height) - Math.max(a.y, b.y);
      if (overlapWidth > 4 && overlapHeight > 4) {
        collisions.push({a, b, overlapWidth, overlapHeight});
      }
    }
  }
  expect(collisions, `unexpected interactive element overlaps: ${JSON.stringify(collisions.slice(0, 8))}`).toEqual([]);
}

async function exerciseLayoutMatrix(page) {
  for (const viewport of VIEWPORTS) {
    await page.setViewportSize(viewport);
    for (const scale of TEXT_SCALES) {
      await page.evaluate(value => {
        document.documentElement.style.fontSize = `${value * 100}%`;
      }, scale);
      await expectLayoutHealthy(page, viewport);
    }
  }
}

test("anonymous clients see only the Cockpit login boundary", async ({page}) => {
  const errors = [];
  page.on("pageerror", error => errors.push(String(error)));
  await page.goto("/");
  await expectLogin(page);
  expect(errors).toEqual([]);
});

test("anonymous login boundary remains accessible and responsive at common sizes and 200 percent text", async ({page}) => {
  await page.goto("/");
  await expectLogin(page);
  await expectNoSeriousAxeViolations(page);
  await exerciseLayoutMatrix(page);
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
  const errors = [];
  page.on("pageerror", error => errors.push(String(error)));
  await openNasOverview(page);
  await expect(page.getByRole("heading", {name: "Service policies"})).toBeVisible();
  expect(errors).toEqual([]);
});

test("final VM component has no serious or critical accessibility violations", async ({page}) => {
  await openNasOverview(page);
  await expectNoSeriousAxeViolations(page);
});

test("final VM has no overlap overflow or clipping across common layouts and 200 percent text", async ({page}) => {
  await openNasOverview(page);
  await exerciseLayoutMatrix(page);
});

test("final VM visible controls remain keyboard reachable and DOM ids are unique", async ({page}) => {
  await page.setViewportSize({width: 360, height: 740});
  await openNasOverview(page);
  const ids = await page.locator("[id]").evaluateAll(nodes => nodes.map(node => node.id).filter(Boolean));
  expect(new Set(ids).size).toBe(ids.length);

  const focusTrail = [];
  for (let index = 0; index < 16; index += 1) {
    await page.keyboard.press("Tab");
    const active = await page.evaluate(() => {
      const node = document.activeElement;
      if (!node || node === document.body) return "";
      const rect = node.getBoundingClientRect();
      if (rect.width <= 0 || rect.height <= 0) return "";
      return `${node.tagName}:${node.id || node.getAttribute("aria-label") || node.textContent || ""}`.slice(0, 120);
    });
    if (active) focusTrail.push(active);
  }
  expect(focusTrail.length).toBeGreaterThan(4);
  expect(new Set(focusTrail).size).toBeGreaterThan(3);
});

test("final VM confirmation dialog stays usable at extreme zoom and restores focus", async ({page}) => {
  await page.setViewportSize({width: 320, height: 568});
  await openNasOverview(page);
  await page.evaluate(() => { document.documentElement.style.fontSize = "200%"; });
  const trigger = page.getByRole("button", {name: "Run system health checks"});
  await expect(trigger).toBeVisible();
  await trigger.focus();
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
  await expect(trigger).toBeFocused();
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
