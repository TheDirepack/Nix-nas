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

async function fillAdministrator(page) {
  await page.getByLabel("Username").fill("nasadmin");
  await page.getByLabel("Full name").fill("NAS Administrator");
  await page.getByLabel("Email").fill("admin@example.test");
  await page.locator("#wizard-admin-password").fill("administrator-password");
  await page.locator("#wizard-admin-password-confirm").fill("administrator-password");
  await page.locator("#wizard-keepass-password").fill("keepass-password");
  await page.locator("#wizard-keepass-password-confirm").fill("keepass-password");
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

test("sets up a fresh appliance from disk discovery without a prepared JSON file", async ({
  page,
}) => {
  let current = {status: "configuration-missing"};
  const created = [];
  const submissions = [];
  await mockSetupApi(page, async ({request, pathname}) => {
    if (request.method() === "GET" && pathname.endsWith("/first-start")) return current;
    if (pathname.endsWith("/storage-options"))
      return {
        poolPresent: false,
        devices: [
          {path: "/dev/vda", type: "disk", available: false, model: "Boot disk", size: 64000},
          {
            path: "/dev/disk/by-id/data-one",
            type: "disk",
            available: true,
            model: "Data disk",
            size: 32000,
          },
        ],
      };
    if (pathname.endsWith("/first-start/plan")) {
      created.push(request.postDataJSON());
      current = {...plan, storage: {...plan.storage, devices: ["/dev/disk/by-id/data-one"]}};
      return current;
    }
    if (pathname.endsWith("/first-run")) {
      submissions.push(request.postDataJSON());
      return {jobId: "b".repeat(24), status: "complete", capability: "d".repeat(48)};
    }
    return {statusCode: 404, body: {error: "Not found"}};
  });
  await openWizard(page);
  await fillAdministrator(page);
  await page.getByRole("button", {name: "Next"}).click();
  await expect(page.getByRole("heading", {name: "Create the storage plan"})).toBeVisible();
  await expect(page.getByLabel("/dev/vda", {exact: false})).toBeDisabled();
  await expect(page.getByRole("button", {name: "Review storage plan"})).toBeDisabled();
  await page.getByLabel("/dev/disk/by-id/data-one", {exact: false}).check();
  await page.getByRole("button", {name: "Review storage plan"}).click();
  await expect
    .poll(() => created)
    .toEqual([
      {
        storage: {
          createPool: true,
          devices: ["/dev/disk/by-id/data-one"],
          topology: "single",
          wipeDevices: true,
        },
      },
    ]);
  expect(submissions).toHaveLength(0);
  await expect(page.getByText("/dev/disk/by-id/data-one", {exact: true})).toBeVisible();
  await expect(page.getByLabel("I understand the listed devices will be wiped")).not.toBeChecked();
  await page.getByLabel("I understand the listed devices will be wiped").check();
  await page.getByRole("button", {name: "Next"}).click();
  await page.getByRole("button", {name: "Run setup"}).click();
  await expect(
    page.getByRole("heading", {name: "Success alert: Setup completed", exact: true}),
  ).toBeVisible();
  expect(submissions).toHaveLength(1);
  expect(submissions[0].planDigest).toBe(current.planDigest);
  expect(submissions[0].devices).toEqual(current.storage.devices);
});

test("plan creation failures preserve input and cannot enable setup", async ({page}) => {
  let attempts = 0;
  await mockSetupApi(page, async ({pathname}) => {
    if (pathname.endsWith("/first-start")) return {status: "configuration-missing"};
    if (pathname.endsWith("/storage-options"))
      return {poolPresent: false, devices: [{path: "/dev/vdb", type: "disk", available: true}]};
    if (pathname.endsWith("/first-start/plan")) {
      attempts += 1;
      return {statusCode: 400, body: {error: "Configured storage device is in use"}};
    }
    return {statusCode: 404, body: {error: "Not found"}};
  });
  await openWizard(page);
  await fillAdministrator(page);
  await page.getByRole("button", {name: "Next"}).click();
  await page.getByLabel("/dev/vdb", {exact: false}).check();
  await page.getByRole("button", {name: "Review storage plan"}).click();
  await expect(page.getByText("Configured storage device is in use", {exact: false})).toBeVisible();
  await expect(page.getByLabel("/dev/vdb", {exact: false})).toBeChecked();
  await page.getByLabel("/dev/vdb", {exact: false}).uncheck();
  await expect(page.getByText("Configured storage device is in use", {exact: false})).toBeHidden();
  await expect(page.getByRole("button", {name: "Review storage plan"})).toBeDisabled();
  await page.getByLabel("/dev/vdb", {exact: false}).check();
  await page.getByRole("button", {name: "Review storage plan"}).click();
  await expect(page.getByText("Configured storage device is in use", {exact: false})).toBeVisible();
  await page.getByLabel("Pool layout").selectOption("mirror");
  await expect(page.getByText("Configured storage device is in use", {exact: false})).toBeHidden();
  await page.getByRole("button", {name: "Next"}).click();
  await expect(page.getByRole("button", {name: "Run setup"})).toBeDisabled();
  expect(attempts).toBe(2);
});

test("completes every first-start control through reboot", async ({page}) => {
  const submissions = [];
  const capability = "d".repeat(48);
  const requestedPaths = [];
  let rebooted = false;
  await mockSetupApi(page, async ({request, pathname}) => {
    requestedPaths.push(pathname);
    if (request.method() === "GET" && pathname.endsWith("/first-start")) return plan;
    if (request.method() === "POST" && pathname.endsWith("/first-run")) {
      submissions.push(request.postDataJSON());
      return {schemaVersion: 1, jobId: "b".repeat(24), status: "submitted", capability};
    }
    if (request.method() === "GET" && pathname.endsWith("/first-start/job")) {
      expect(request.headers()["x-nas-setup-capability"]).toBe(capability);
      return {schemaVersion: 1, jobId: "b".repeat(24), status: "complete-unverified"};
    }
    if (request.method() === "POST" && pathname.endsWith("/reboot")) {
      expect(request.headers()["x-nas-setup-capability"]).toBe(capability);
      rebooted = true;
      return {rebooting: true};
    }
    return {statusCode: 404, body: {error: "Not found"}};
  });

  await openWizard(page);
  await expect(page.getByRole("button", {name: "Cancel"})).toHaveCount(0);
  await page.getByLabel("Color theme").selectOption("dark");
  await expect(page.locator("html")).toHaveClass(/pf-v6-theme-dark/);
  await fillAdministrator(page);
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
    encryptStorage: true,
    confirmPasswordReapply: false,
  });
  await page.getByRole("button", {name: "Reboot now"}).click();
  await expect(
    page.getByText("This page will disconnect while the appliance restarts."),
  ).toBeVisible();
  expect(rebooted).toBe(true);
  expect(requestedPaths.some((pathname) => /\/job\/[0-9a-f]{24}$/.test(pathname))).toBe(false);
});

test("validates entries, refreshes the plan, and safely retries a failed job", async ({page}) => {
  const submissions = [];
  const failedCapability = "e".repeat(48);
  const completedCapability = "f".repeat(48);
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
      if (submissions.length === 1) {
        return {jobId: "c".repeat(24), status: "submitted", capability: failedCapability};
      }
      return {jobId: "d".repeat(24), status: "complete", capability: completedCapability};
    }
    if (request.method() === "GET" && pathname.endsWith("/first-start/job")) {
      expect(request.headers()["x-nas-setup-capability"]).toBe(failedCapability);
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
  await expect(page.getByText("Use a valid administrator username.")).toBeVisible();
  await expect(page.getByRole("button", {name: "Run setup"})).toBeDisabled();

  await page.getByRole("button", {name: "Back"}).click();
  await page.getByRole("button", {name: "Back"}).click();
  await fillAdministrator(page);
  await goToConfirmation(page);
  await page.getByRole("button", {name: "Run setup"}).click();
  await expect(page.getByText("Injected setup failure", {exact: true})).toBeVisible({
    timeout: 6_000,
  });
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

test("refreshing an already approved destructive plan requires fresh consent", async ({page}) => {
  const secondPlan = {
    ...plan,
    planDigest: "b".repeat(64),
    storage: {...plan.storage, devices: ["/dev/disk/by-id/disk-three"]},
  };
  let requests = 0;
  const submissions = [];
  await mockSetupApi(page, async ({request, pathname}) => {
    if (request.method() === "GET" && pathname.endsWith("/first-start")) {
      requests += 1;
      return requests === 1 ? plan : secondPlan;
    }
    if (request.method() === "POST" && pathname.endsWith("/first-run")) {
      submissions.push(request.postDataJSON());
      return {jobId: "a".repeat(24), status: "submitted", capability: "d".repeat(48)};
    }
    return {statusCode: 404, body: {error: "Not found"}};
  });
  await openWizard(page);
  await fillAdministrator(page);
  await page.getByRole("button", {name: "Next"}).click();

  const consent = page.getByLabel("I understand the listed devices will be wiped");
  await expect(page.getByText("/dev/disk/by-id/disk-one")).toBeVisible();
  await consent.check();
  await expect(consent).toBeChecked();
  await page.getByRole("button", {name: "Refresh plan"}).click();
  await expect(page.getByText("/dev/disk/by-id/disk-three")).toBeVisible();
  await expect(consent).not.toBeChecked();

  await page.getByRole("button", {name: "Next"}).click();
  await expect(page.getByText("No running setup job")).toBeVisible();
  await expect(page.getByRole("button", {name: "Run setup"})).toBeDisabled();
  expect(submissions).toHaveLength(0);
});

test("leaving the job screen aborts a stalled status request", async ({page}) => {
  // Record aborts from the client side: browsers disagree about whether an
  // aborted fetch reaches the requestfailed listener.
  await page.addInitScript(() => {
    const original = window.fetch;
    window.__abortedRequests = 0;
    window.fetch = (input, init) => {
      const pending = original(input, init);
      pending.catch((error) => {
        if (error && error.name === "AbortError") window.__abortedRequests += 1;
      });
      return pending;
    };
  });
  let statusRequests = 0;
  await mockSetupApi(page, async ({request, pathname}) => {
    if (request.method() === "GET" && pathname.endsWith("/first-start")) return plan;
    if (request.method() === "POST" && pathname.endsWith("/first-run")) {
      return {jobId: "a".repeat(24), status: "running", capability: "d".repeat(48)};
    }
    if (request.method() === "GET" && pathname.endsWith("/first-start/job")) {
      statusRequests += 1;
      // Never answer: only an abort can settle this request.
      await new Promise(() => {});
    }
    return {statusCode: 404, body: {error: "Not found"}};
  });
  await openWizard(page);
  await fillAdministrator(page);
  await goToConfirmation(page);
  await page.getByRole("button", {name: "Run setup"}).click();
  await expect.poll(() => statusRequests).toBeGreaterThan(0);
  await page.getByRole("button", {name: "Back"}).click();
  await expect.poll(() => page.evaluate(() => window.__abortedRequests)).toBe(1);
});
