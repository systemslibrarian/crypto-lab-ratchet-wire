import { defineConfig, devices } from '@playwright/test';

/**
 * End-to-end tests run against the actual production build served by
 * `vite preview`, in real Chromium/Firefox/WebKit. This is the definitive
 * "does it work in a browser" check that the Vitest + happy-dom suite can only
 * approximate. Build first (`npm run build`); the web server serves `dist/`.
 */
const PORT = 4173;
const BASE_URL = `http://localhost:${PORT}/crypto-lab-ratchet-wire/`;

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: process.env.CI ? 'github' : 'list',
  use: {
    baseURL: BASE_URL,
    trace: 'on-first-retry',
    // Determinism: skip CSS animations so assertions (and axe contrast checks)
    // never race a fade-in. The app honours prefers-reduced-motion.
    reducedMotion: 'reduce',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } },
  ],
  webServer: {
    // Build before serving: `vite preview` only serves whatever is already in
    // dist/, so without this a failing build leaves the previous good bundle in
    // place and the suite passes green against code that no longer compiles.
    command: `npm run build && npm run preview -- --port ${PORT} --strictPort`,
    url: BASE_URL,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
