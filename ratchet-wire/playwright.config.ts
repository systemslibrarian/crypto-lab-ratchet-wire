import { defineConfig, devices } from '@playwright/test';

/**
 * End-to-end tests run against the actual production build served by
 * `vite preview`, in real Chromium/Firefox/WebKit. This is the definitive
 * "does it work in a browser" check that the Vitest + happy-dom suite can only
 * approximate. Build first (`npm run build`); the web server serves `dist/`.
 */
const PORT = 4666;
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
    /*
     * NO `reducedMotion: 'reduce'` HERE, because on this Playwright it does
     * nothing and the comment that used to sit in its place said it did.
     *
     * Measured on @playwright/test 1.61.0 against this very page: with
     * `reducedMotion: 'reduce'` set in this block,
     * `matchMedia('(prefers-reduced-motion: reduce)').matches` evaluates to
     * FALSE inside the page; calling `page.emulateMedia({ reducedMotion:
     * 'reduce' })` on the same page then makes it TRUE. The context-level
     * option is a no-op here, so the "determinism" this claimed to buy — "skip
     * CSS animations so assertions never race a fade-in" — was never bought,
     * and the suite has been racing `fadeIn`/`slideIn` all along while reading
     * as though it could not.
     *
     * The a11y gate establishes reduced motion the way that works: `boot()` in
     * `e2e/gate.ts` calls `page.emulateMedia()` BEFORE navigating and then
     * ASSERTS from inside the page that it took effect, so this can never
     * silently rot back into a claim nothing checks.
     */
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
