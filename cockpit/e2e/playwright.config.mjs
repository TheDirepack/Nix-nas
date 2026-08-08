import {defineConfig, devices} from "@playwright/test";

export default defineConfig({
  testDir: ".",
  testMatch: "ui-security.spec.mjs",
  timeout: 45_000,
  expect: {timeout: 8_000},
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [["line"], ["html", {outputFolder: "../playwright-report", open: "never"}]] : "line",
  use: {
    baseURL: "http://127.0.0.1:4173",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  webServer: {
    command: "python3 -m http.server 4173 --bind 127.0.0.1 --directory dist",
    url: "http://127.0.0.1:4173/index.html",
    cwd: "..",
    reuseExistingServer: !process.env.CI,
    timeout: 20_000,
  },
  projects: [
    {name: "chromium-desktop", use: {...devices["Desktop Chrome"]}},
    {name: "firefox-desktop", use: {...devices["Desktop Firefox"]}},
    {name: "webkit-desktop", use: {...devices["Desktop Safari"]}},
    {name: "chromium-mobile", use: {...devices["Pixel 7"]}},
  ],
});
