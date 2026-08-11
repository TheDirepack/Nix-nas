import {defineConfig, devices} from "@playwright/test";

const suite = process.env.NAS_BROWSER_SUITE || "deterministic";
const isFinalVm = suite === "vm";

// Playwright remains appropriate for DOM/XSS execution, layout, interaction,
// accessibility, and final-VM browser behavior. Protocol-level HTTP probes use
// curl in the VM harness instead of paying browser startup cost per request.
const testMatch = isFinalVm ? "final-vm.spec.mjs" : ["ui-security.spec.mjs", "common-xss.spec.mjs"];

export default defineConfig({
  testDir: ".",
  testMatch,
  timeout: isFinalVm ? 90_000 : 45_000,
  expect: {timeout: isFinalVm ? 30_000 : 8_000},
  fullyParallel: true,
  workers: process.env.CI ? 4 : undefined,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI
    ? [["line"], ["html", {outputFolder: "../playwright-report", open: "never"}]]
    : "line",
  use: {
    baseURL: isFinalVm ? process.env.NAS_VM_BASE_URL : "http://127.0.0.1:4173",
    ignoreHTTPSErrors: isFinalVm,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  webServer: isFinalVm
    ? undefined
    : {
        command: "python3 -m http.server 4173 --bind 127.0.0.1 --directory dist",
        url: "http://127.0.0.1:4173/index.html",
        cwd: "..",
        reuseExistingServer: !process.env.CI,
        timeout: 20_000,
      },
  projects: isFinalVm
    ? [
        {name: "chromium-final-vm", use: {...devices["Desktop Chrome"]}},
        {name: "firefox-final-vm", use: {...devices["Desktop Firefox"]}},
        {name: "webkit-final-vm", use: {...devices["Desktop Safari"]}},
        {name: "chromium-mobile-final-vm", use: {...devices["Pixel 7"]}},
      ]
    : [
        {name: "chromium-desktop", use: {...devices["Desktop Chrome"]}},
        {name: "firefox-desktop", use: {...devices["Desktop Firefox"]}},
        {name: "webkit-desktop", use: {...devices["Desktop Safari"]}},
        {name: "chromium-mobile", use: {...devices["Pixel 7"]}},
      ],
});
