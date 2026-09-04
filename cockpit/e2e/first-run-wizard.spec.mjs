import {test, expect} from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

const plan = {
  schemaVersion: 2,
  status: "ready",
  planDigest: "a".repeat(64),
  requiresDestructiveConfirmation: true,
  storage: {
    pool: "tank",
    dataset: "tank/nas",
    devices: ["/dev/disk/by-id/disk-one", "/dev/disk/by-id/disk-two"],
  },
};

async function mockSetupApi(page, handler) {
  await page.route("**/setup/api/**", async (route) => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    const result = await handler({request, pathname});
    await route.fulfill({
      status: result?.statusCode || 200,
      contentType: "application/json",
      body: JSON.stringify(result?.body ?? result ?? {}),
    });
  });
}

async function openWizard(page) {
  await page.goto("/setup/");
  await expect(page.getByRole("heading", {name: "First-start setup"})).toBeVisible();
  await expect(page.getByLabel("Username")).toBeVisible();
}

async function fillAdministrator(page, {separateKeePass = false} = {}) {
  await page.getByLabel("Username").fill("nasadmin");
  await page.getByLabel("Full name").fill("NAS Administrator");
  await page.getByLabel("Email").fill("admin@example.test");
  await page.locator("#wizard-admin-password").fill("administrator-password");
  await page.locator("#wizard-admin-password-confirm").fill("administrator-password");
  if (separateKeePass) {
    await page.getByLabel("Use the same password for the KeePassXC database").uncheck();
    await page.locator("#wizard-keepass-password").fill("keepass-password");
    await page.locator("#wizard-keepass-password-confirm").fill("keepass-password");
  }
}

async function goToConfirmation(page) {
  await page.getByRole("button", {name: "Next"}).click();
  await expect(page.getByText("Review the storage plan published by the appliance")).toBeVisible();
  await expect(page.getByRole("link", {name: "Open Storage"})).toHaveAttribute(
    "href",
    "/console/storage",
  );
  await expect(page.getByRole("link", {name: "Open Terminal"})).toHaveAttribute(
    "href",
    "/console/system/terminal",
  );
  await page.getByLabel("I understand the listed devices will be wiped").check();
  await page.getByRole("button", {name: "Next"}).click();
  await expect(page.getByText("Finishing setup applies the reviewed plan")).toBeVisible();
}

test("completes every first-start control through reboot", async ({page}) => {
  const submissions = [];
  let rebooted = false;
  await mockSetupApi(page, async ({request, pathname}) => {
    if (request.method() === "GET" && pathname.endsWith("/first-start")) return plan;
    if (request.method() === "POST" && pathname.endsWith("/first-run")) {
      submissions.push(request.postDataJSON());
      return {schemaVersion: 1, jobId: "b".repeat(24), status: "submitted"};
    }
    if (pathname.endsWith(`/job/${"b".repeat(24)}`)) {
      return {schemaVersion: 1, jobId: "b".repeat(24), status: "complete-unverified"};
    }
    if (request.method() === "POST" && pathname.endsWith("/reboot")) {
      rebooted = true;
      return {rebooting: true};
    }
    return {statusCode: 404, body: {error: "Not found"}};
  });

  await openWizard(page);
  await expect(page.getByRole("button", {name: "Cancel"})).toHaveCount(0);
  await page.getByLabel("Color theme").selectOption("dark");
  await expect(page.locator("html")).toHaveClass(/pf-v6-theme-dark/);
  await fillAdministrator(page, {separateKeePass: true});
  await goToConfirmation(page);
  await expect(page.getByRole("button", {name: "Finish"})).toHaveCount(0);

  await page.getByRole("button", {name: "Run setup"}).click();
  await expect(page.getByRole("button", {name: "Reboot now"})).toBeVisible({timeout: 6_000});
  expect(submissions).toHaveLength(1);
  expect(submissions[0]).toEqual({
    password: "keepass-password",
    administrator: {
      username: "nasadmin",
      name: "NAS Administrator",
      email: "admin@example.test",
      password: "administrator-password",
    },
    planDigest: "a".repeat(64),
    devices: plan.storage.devices,
    allowDestructiveStorage: true,
    confirmPasswordReapply: false,
  });
  await page.getByRole("button", {name: "Reboot now"}).click();
  await expect(
    page.getByText("This page will disconnect while the appliance restarts."),
  ).toBeVisible();
  expect(rebooted).toBe(true);
});

test("validates entries, refreshes the plan, and safely retries a failed job", async ({page}) => {
  const submissions = [];
  let planRequests = 0;
  let jobRequests = 0;
  await mockSetupApi(page, async ({request, pathname}) => {
    if (request.method() === "GET" && pathname.endsWith("/first-start")) {
      planRequests += 1;
      if (planRequests === 1) return {statusCode: 503, body: {error: "Plan is still preparing"}};
      return plan;
    }
    if (request.method() === "POST" && pathname.endsWith("/first-run")) {
      submissions.push(request.postDataJSON());
      if (submissions.length === 1) return {jobId: "c".repeat(24), status: "submitted"};
      return {status: "complete"};
    }
    if (pathname.endsWith(`/job/${"c".repeat(24)}`)) {
      jobRequests += 1;
      return {jobId: "c".repeat(24), status: "failed", message: "Injected setup failure"};
    }
    return {statusCode: 404, body: {error: "Not found"}};
  });

  await openWizard(page);
  await page.getByLabel("Username").fill("Invalid Name");
  await page.getByLabel("Full name").fill("NAS Administrator");
  await page.getByLabel("Email").fill("invalid");
  await page.locator("#wizard-admin-password").fill("short");
  await page.locator("#wizard-admin-password-confirm").fill("short");
  await page.getByRole("button", {name: "Next"}).click();
  await expect(page.getByText("Plan is still preparing")).toBeVisible();
  await page.getByRole("button", {name: "Refresh plan"}).click();
  await expect(page.getByText("/dev/disk/by-id/disk-one")).toBeVisible();
  await page.getByRole("button", {name: "Next"}).click();
  await page.getByRole("button", {name: "Run setup"}).click();
  await expect(page.getByText("Use a valid administrator username.")).toBeVisible();

  await page.getByRole("button", {name: "Back"}).click();
  await page.getByRole("button", {name: "Back"}).click();
  await fillAdministrator(page);
  await goToConfirmation(page);
  await page.getByRole("button", {name: "Run setup"}).click();
  await expect(page.getByText("Injected setup failure")).toBeVisible({timeout: 6_000});
  const retry = page.getByRole("button", {name: "Retry setup"});
  await expect(retry).toBeDisabled();
  await page
    .getByLabel("I understand retrying may reapply administrator and account passwords")
    .check();
  await retry.click();
  await expect(page.getByRole("button", {name: "Reboot now"})).toBeVisible();
  expect(jobRequests).toBeGreaterThan(0);
  expect(submissions).toHaveLength(2);
  expect(submissions[1].confirmPasswordReapply).toBe(true);
});

test("fits the viewport and has no serious accessibility violations", async ({page}) => {
  await mockSetupApi(page, async () => plan);
  await openWizard(page);
  const metrics = await page.evaluate(() => ({
    viewport: document.documentElement.clientWidth,
    pageWidth: document.documentElement.scrollWidth,
    bodyWidth: document.body.scrollWidth,
  }));
  expect(metrics.pageWidth).toBeLessThanOrEqual(metrics.viewport + 1);
  expect(metrics.bodyWidth).toBeLessThanOrEqual(metrics.viewport + 1);
  const result = await new AxeBuilder({page})
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(result.violations.filter((item) => ["serious", "critical"].includes(item.impact))).toEqual(
    [],
  );
});
