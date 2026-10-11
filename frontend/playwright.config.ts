import { defineConfig, devices } from '@playwright/test'

const PORT = Number(process.env.TRIAGELENS_E2E_PORT ?? 8799)
const BASE_URL = `http://127.0.0.1:${PORT}`

// Browser E2E against the real API serving the built frontend from one origin
// (spec 09 section 7). `e2e/serve.mjs` boots `python -m app.main` on an isolated
// temporary data directory; the suite drives the actual React UI.
export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  workers: 1,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['github'], ['list']] : [['list']],
  timeout: 180_000,
  expect: { timeout: 30_000 },
  use: {
    baseURL: BASE_URL,
    trace: 'retain-on-failure',
    video: 'retain-on-failure',
    actionTimeout: 20_000,
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'node e2e/serve.mjs',
    url: `${BASE_URL}/api/health`,
    timeout: 180_000,
    reuseExistingServer: false,
  },
})
