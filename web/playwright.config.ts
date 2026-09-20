import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  workers: 1,
  timeout: 90_000,
  expect: { timeout: 10_000 },
  use: {
    baseURL: "http://127.0.0.1:18081",
    viewport: { width: 1440, height: 1000 },
    trace: "retain-on-failure",
  },
  webServer: {
    command: "node e2e/server.mjs",
    url: "http://127.0.0.1:18081/healthz",
    reuseExistingServer: false,
    timeout: 120_000,
  },
});
